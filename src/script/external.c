/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"

static int acquire_script_permit(const host_t *host) {
	if (set.php.script_timeout <= 0) return EINVAL;
	/* Preserve the existing retry budget without signed multiplication overflow. */
	uint64_t attempts = (uint64_t) set.php.script_timeout * 15;
	int error = EAGAIN;
	for (uint64_t retry = 1; retry < attempts; retry++) {
		error = spine_permits_try_acquire(&available_scripts);
		if (error == 0) return 0;
		if (error == EAGAIN || error == EWOULDBLOCK) {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEVDBG, ("Device[%i] DEBUG: Pausing as unable to obtain a script execution lock", host->id));
		} else {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEVDBG, ("Device[%i] DEBUG: Pausing as error %d whilst obtaining a script execution lock", host->id, error));
		}
		spine_sleep_usec(10000);
	}
	return error;
}

typedef struct {
	const host_t *host;
	const char *command;
	int id;
	const char *type;
} script_result_context_t;

typedef struct {
	/* glibc cleanup unwinds with setjmp/longjmp. Preserve state changed after
	 * pthread_cleanup_push even when the compiler keeps ordinary locals in registers. */
	volatile int fd;
	char *volatile result;
	volatile bool permit;
	char *volatile command;
} script_read_owner_t;

static void cancel_script_read(void *argument) {
	script_read_owner_t *owner = argument;
	int pid;
	if (owner->fd >= 0) {
		pid = nft_pchild(owner->fd);
		if (pid > 1) (void) kill(-pid, SIGKILL);
		(void) nft_pclose(owner->fd);
	}
	free(owner->result);
	free(owner->command);
	if (owner->permit) child_cleanup_script(NULL);
}

static bool read_limited_script_result(const script_result_context_t *context, int fd,
	double deadline, char *result) {
	size_t used = 0;
	size_t limit = set.php.script_max_output != 0 ? set.php.script_max_output : RESULTS_BUFFER - 1;
	char extra;
	int ready;
	ssize_t bytes;
	int pid;
	for (;;) {
		ready = spine_wait_readable(fd, deadline);
		if (ready <= 0) {
			SPINE_LOG(("Device[%i] %s[%i] ERROR: Script output deadline/read failure", context->host->id, context->type, context->id));
			break;
		}
		bytes = read(fd, used < limit ? result + used : &extra, used < limit ? limit - used : 1);
		if (bytes < 0 && errno == EINTR) continue;
		if (bytes == 0) {
			if (used == 0) SET_UNDEFINED(result);
			else result[used] = '\0';
			return used != 0;
		}
		if (bytes < 0 || used == limit) {
			SPINE_LOG(("Device[%i] %s[%i] ERROR: Script output limit/read failure", context->host->id, context->type, context->id));
			break;
		}
		used += (size_t) bytes;
	}
	pid = nft_pchild(fd);
	if (pid > 1) (void) kill(-pid, SIGKILL);
	SET_UNDEFINED(result);
	return FALSE;
}

/* Return whether the legacy popen backend may close without blocking on a
 * timed-out command; nft_popen owns and reaps its registered child instead. */
static bool read_script_result(const script_result_context_t *context, int fd, double deadline, char *result) {
	if (set.php.script_max_output != 0 || set.php.script_cpu_seconds != 0 || set.php.script_memory_mb != 0)
		return read_limited_script_result(context, fd, deadline, result);
	int ready = spine_wait_readable(fd, deadline);
	if (ready < 0) {
		switch (errno) {
			case EBADF:
				SPINE_LOG(("Device[%i] ERROR: One or more of the file descriptor sets specified a file descriptor that is not a valid open file descriptor.", context->host->id));
				break;
			case EINVAL:
				SPINE_LOG(("Device[%i] ERROR: Possible invalid timeout specified in select() statement.", context->host->id));
				break;
			default:
				SPINE_LOG(("Device[%i] ERROR: The script/command select() failed", context->host->id));
				break;
		}
		SET_UNDEFINED(result);
		return FALSE;
	}
	if (ready == 0) {
		SPINE_LOG_MEDIUM(("Device[%i] ERROR: The NIFTY POPEN timed out", context->host->id));
		int pid = nft_pchild(fd);
		if (pid > 1) {
			/* nft_popen() made the script a group leader; take its descendants too. */
			kill(-pid, SIGKILL);
		} else {
			SPINE_LOG(("Device[%i] ERROR: Unable to find the timed-out POPEN child", context->host->id));
		}
		SET_UNDEFINED(result);
		return FALSE;
	}
	/* Use the full capacity to detect truncation without waiting for EOF. */
	ssize_t bytes = read(fd, result, RESULTS_BUFFER);
	if (bytes > 0 && bytes < RESULTS_BUFFER && memchr(result, '\0', (size_t) bytes) == NULL) {
		result[bytes] = '\0';
	} else {
		char script[SMALL_BUFSIZE];

		php_command_script(context->command, script, sizeof(script));
		if (STRIMATCH(context->type, "DS")) {
			SPINE_LOG(("Device[%i] DS[%i] ERROR: Empty result [%s]: '%s'", context->host->id, context->id, context->host->hostname, script));
		} else {
			SPINE_LOG(("Device[%i] DQ[%i] ERROR: Empty result [%s]: '%s'", context->host->id, context->id, context->host->hostname, script));
		}
		SET_UNDEFINED(result);
	}
	return TRUE;
}

/*! \fn char *exec_poll(host_t *current_host, char *command, int id, char *type)
 *  \brief polls a host using a script
 *  \param current_host a pointer to the current host structure
 *  \param command the command to be executed
 *  \param id either the local_data_id or the data_query_id
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return a pointer to a character buffer containing the result.
 *
 */
/* WARNING: command is passed to /bin/sh -c (via nft_popen) without shell escaping.
 * The caller MUST ensure command originates from a trusted source
 * (the Cacti database). Do not pass user-controlled input directly. */
char *exec_poll(host_t *current_host, char *command, int id, const char *type) {
	int cmd_fd;
	double deadline;
	char *proc_command;
	char *result_string;

/* compensate for back slashes in arguments */
#if defined(__CYGWIN__)
	proc_command = add_slashes(command);
#else
	proc_command = command;
#endif

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: poller.c exec_poll!");
	}

	/* set zeros */
	memset(result_string, 0, RESULTS_BUFFER);


	/* don't run too many scripts, operating systems do not like that. */
	int sem_err;
	script_read_owner_t execution_owner = {-1, result_string, FALSE, NULL};
#if defined(__CYGWIN__)
	execution_owner.command = proc_command;
#endif

	/* used for checking executable status */
	char executable[BUFSIZE];
	const char *program;
	size_t program_length;
	const char *prefix;

	pthread_cleanup_push(cancel_script_read, &execution_owner);

	sem_err = acquire_script_permit(current_host);

	if (sem_err) {
		SPINE_LOG(("ERROR: Device[%i]: Failed to obtain a script execution lock (error %d)", current_host->id, sem_err));
		SET_UNDEFINED(result_string);
	} else {
		/* Mark for cleanup */
		execution_owner.permit = TRUE;

		/* record start time */
		deadline = spine_monotonic_time() + set.php.script_timeout;

		/* peel the executable from the command; only the first token is a
		 * path, so long arguments cannot overflow the candidate below */
		program = proc_command + strspn(proc_command, " ");
		program_length = strcspn(program, " ");

		/* cheesy little hack to add /usr/bin/ if its not included */
		prefix = memchr(program, '/', program_length) == NULL ? "/usr/bin/" : "";

		executable[0] = '\0';
		if (program_length + strlen(prefix) >= sizeof(executable)) {
			/* One oversized item must not terminate the poller. */
			SPINE_LOG(("Device[%i] %s[%i] ERROR: Script executable path exceeds %d bytes", current_host->id, type, id, BUFSIZE - 1));
		} else {
			spine_snprintf(executable, sizeof(executable), "%s%.*s", prefix, (int) program_length, program);

			/* executable is the first token; the arguments can carry credentials. */
			SPINE_LOG_DEBUG(("The executable is '%s'", executable));
		}

		if (executable[0] == '\0') {
			SET_UNDEFINED(result_string);
		} else if (access(executable, X_OK | F_OK) != -1) {
			cmd_fd = nft_popen(proc_command, "r");
			SPINE_LOG_DEVICE(current_host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: The NIFTY POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));

			if (cmd_fd >= 0) {
				const script_result_context_t context = {current_host, command, id, type};
				script_read_owner_t owner = {cmd_fd, NULL, FALSE, NULL};
				int child_status;
				int cancel_state;
				pthread_cleanup_push(cancel_script_read, &owner);
				(void) read_script_result(&context, cmd_fd, deadline, result_string);

				/* close pipe */
				/* Resolve child ownership before delivering a pending cancellation. */
				pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
				owner.fd = -1;
				child_status = nft_pclose_deadline(cmd_fd, deadline);
				pthread_setcancelstate(cancel_state, NULL);
				if ((set.php.script_max_output != 0 || set.php.script_cpu_seconds != 0 || set.php.script_memory_mb != 0) &&
					(child_status < 0 || !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)) {
					SPINE_LOG(("Device[%i] %s[%i] ERROR: Limited script failed or exceeded its resource policy", current_host->id, type, id));
					SET_UNDEFINED(result_string);
				}
				pthread_cleanup_pop(0);
			} else {
				SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN [%s]: '%s'", current_host->id, current_host->hostname, executable));
				SET_UNDEFINED(result_string);
			}
		} else {
			SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN.  File '%s' does not exist or is not executable.", current_host->id, executable));
			SET_UNDEFINED(result_string);
		}
	}

	/* reduce the active script count */
	execution_owner.result = NULL;
	pthread_cleanup_pop(1);

	return result_string;
}
