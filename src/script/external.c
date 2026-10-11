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
#include <sys/wait.h>

static bool script_limits_enabled(void) {
	const spine_script_limits_t *limits = &set.php.limits;
	return limits->deadline_seconds || limits->output_bytes || limits->cpu_seconds ||
		limits->memory_kib || limits->file_kib || limits->open_files;
}

static bool read_limited_script(const host_t *host, int fd, double deadline, char *result) {
	size_t used = 0;
	size_t maximum = set.php.limits.output_bytes ? set.php.limits.output_bytes : RESULTS_BUFFER - 1;
	char chunk[RESULTS_BUFFER];
	int ready;
	ssize_t bytes;
	if (maximum >= RESULTS_BUFFER) {
		SET_UNDEFINED(result);
		return FALSE;
	}
	while ((ready = spine_wait_readable(fd, deadline)) > 0) {
		bytes = read(fd, chunk, sizeof(chunk));
		if (bytes < 0 && errno == EINTR) continue;
		if (bytes == 0 && used != 0) {
			result[used] = '\0';
			return TRUE;
		}
		if (bytes <= 0) {
			SPINE_LOG(("Device[%i] ERROR: Script policy rejected empty output or a read failure", host->id));
			break;
		}
		if ((size_t) bytes > maximum - used) {
			SPINE_LOG(("Device[%i] ERROR: Script output exceeded its configured byte limit", host->id));
			break;
		}
		memcpy(result + used, chunk, (size_t) bytes);
		used += (size_t) bytes;
	}
	if (ready == 0) SPINE_LOG(("Device[%i] ERROR: Script execution exceeded its configured deadline", host->id));
	if (ready < 0) SPINE_LOG(("Device[%i] ERROR: Script policy could not wait for output", host->id));
	SET_UNDEFINED(result);
	return FALSE;
}

typedef struct {
	char *result;
	char *command;
	int fd;
	int host_id;
	bool permit;
} script_cleanup_t;

static void cleanup_script_poll(void *argument) {
	script_cleanup_t *owned = argument;
	int pid;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if (owned->fd >= 0) {
		pid = nft_pchild(owned->fd);
		if (pid > 1) kill(-pid, SIGKILL);
		nft_pclose(owned->fd);
	}
	if (owned->permit) spine_permits_release(&available_scripts);
	free(owned->command);
	free(owned->result);
	SPINE_LOG(("Device[%i] ERROR: Script execution cancelled and owned resources released", owned->host_id));
}

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

/* Return whether the legacy popen backend may close without blocking on a
 * timed-out command; nft_popen owns and reaps its registered child instead. */
static bool read_script_result(const script_result_context_t *context, int fd, double deadline, char *result) {
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
	/* Preserve the single-read response contract; later output is ignored. */
	ssize_t bytes = read(fd, result, RESULTS_BUFFER - 1);
	if (bytes > 0 && bytes < RESULTS_BUFFER) {
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
	int previous_state;
	int previous_type;
	int status;
	int child_pid;
	int spawn_error;
	bool valid_result;
	unsigned int execution_seconds;
	bool limited = script_limits_enabled();
	script_cleanup_t owned = {NULL, NULL, -1, current_host->id, FALSE};
	/* Deferred cancellation allows ownership to be registered between APIs.
	 * Cancellation remains supported while waiting for a permit or output. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_state);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &previous_type);

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
	owned.result = result_string;
#if defined(__CYGWIN__)
	owned.command = proc_command;
#endif


	/* don't run too many scripts, operating systems do not like that. */
	int sem_err;

	/* used for checking executable status */
	char executable[BUFSIZE];
	char *saveptr = NULL;

	pthread_cleanup_push(cleanup_script_poll, &owned);
	pthread_setcancelstate(previous_state, NULL);

	sem_err = acquire_script_permit(current_host);

	if (sem_err) {
		SPINE_LOG(("ERROR: Device[%i]: Failed to obtain a script execution lock (error %d)", current_host->id, sem_err));
		SET_UNDEFINED(result_string);
#if defined(__CYGWIN__)
		/* The common ownership cleanup releases this allocation. */
#endif
	} else {
		/* Mark for cleanup */
		owned.permit = TRUE;

		/* record start time */
		execution_seconds = (unsigned int) set.php.script_timeout;
		if (set.php.limits.deadline_seconds && set.php.limits.deadline_seconds < execution_seconds)
			execution_seconds = set.php.limits.deadline_seconds;
		deadline = spine_monotonic_time() + execution_seconds;

		/* peel the executable from the command */
		saveptr = proc_command;
		spine_snprintf(executable, sizeof(executable), "%s", proc_command);
		strtok_r(executable, " ", &saveptr);

		/* cheesy little hack to add /usr/bin/ if its not included */
		if (strstr(executable, "/") == NULL) {
			saveptr = proc_command;
			spine_snprintf(executable, sizeof(executable), "/usr/bin/%s", proc_command);
			strtok_r(executable, " ", &saveptr);
		}

		/* executable is the first token; the arguments can carry credentials. */
		SPINE_LOG_DEBUG(("The executable is '%s'", executable));

		if (access(executable, X_OK | F_OK) != -1) {
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
			cmd_fd = nft_popen_limited(proc_command, "r", &set.php.limits);
			spawn_error = errno;
			owned.fd = cmd_fd;
			pthread_setcancelstate(previous_state, NULL);
			SPINE_LOG_DEVICE(current_host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: The NIFTY POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));

			if (cmd_fd >= 0) {
				const script_result_context_t context = {current_host, command, id, type};
				if (limited) {
					valid_result = read_limited_script(current_host, cmd_fd, deadline, result_string);
					if (!valid_result) {
						child_pid = nft_pchild(cmd_fd);
						if (child_pid > 1) kill(-child_pid, SIGKILL);
					}
				} else (void) read_script_result(&context, cmd_fd, deadline, result_string);

				/* close pipe */
				pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
				status = nft_pclose(cmd_fd);
				owned.fd = -1;
				pthread_setcancelstate(previous_state, NULL);
				if (limited && (status < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)) {
					SPINE_LOG(("Device[%i] DS/DQ[%i] ERROR: Script resource policy or child exit failed for '%s'", current_host->id, id, executable));
					SET_UNDEFINED(result_string);
				}
			} else {
				if (spawn_error == ENOTSUP && limited) {
					SPINE_LOG(("Device[%i] DS/DQ[%i] ERROR: Configured child resource limits are unsupported on this platform for '%s'", current_host->id, id, executable));
				} else {
					SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN [%s]: '%s': %s", current_host->id, current_host->hostname, executable, strerror(spawn_error)));
				}
				SET_UNDEFINED(result_string);
			}
		} else {
			SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN.  File '%s' does not exist or is not executable.", current_host->id, executable));
			SET_UNDEFINED(result_string);
		}

#if defined(__CYGWIN__)
		/* The common ownership cleanup releases this allocation. */
#endif
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if (owned.permit) spine_permits_release(&available_scripts);
	owned.permit = FALSE;
	free(owned.command);
	owned.command = NULL;
	pthread_setcanceltype(previous_type, NULL);
	pthread_setcancelstate(previous_state, NULL);
	pthread_testcancel();
	owned.result = NULL;
	pthread_cleanup_pop(0);

	return result_string;
}
