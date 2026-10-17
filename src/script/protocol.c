/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "internal/common.h"
#include "app/spine.h"
#include "script/server_internal.h"
#include <limits.h>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

/*! \fn static int php_addclose_unless_std(posix_spawn_file_actions_t *fa, int fd)
 *  \brief queue a close for a pipe end unless it is stdin or stdout
 *
 *  After the dup2 redirects, descriptors 0 and 1 hold the child's ends. Closing
 *  them here would undo the redirect that was just set up.
 */
static void php_process_lock(int php_process) {
	thread_mutex_lock(LOCK_PHP_PROC_0 + php_process);
}

static void php_process_unlock(int php_process) {
	thread_mutex_unlock(LOCK_PHP_PROC_0 + php_process);
}

static char *php_undefined_result(void) {
	char *result = strdup("U");

	if (result == NULL)
		die("ERROR: Fatal malloc error: php.c php_cmd!");

	return result;
}

/* Script and script server arguments can carry SNMP communities and v3
 * passphrases, so logs name only the first token, the script, never the
 * arguments. */
void php_command_script(const char *command, char *script, size_t capacity) {
	size_t length = strcspn(command, " \t\r\n");

	if (length >= capacity) length = capacity - 1;
	memcpy(script, command, length);
	script[length] = '\0';
}

void php_fail_read(int php_process, int allow_restart) {
	php_processes[php_process].php_state = PHP_BUSY;
	if (allow_restart) {
		php_close(php_process);
		php_init(php_process);
	}
}

void php_processes_initialize(php_t *processes, int count) {
	int i;

	if (processes == NULL || count <= 0)
		return;

	for (i = 0; i < count; i++) {
		processes[i].php_state = PHP_BUSY;
		processes[i].php_pid = -1;
		processes[i].php_read_fd = -1;
		processes[i].php_write_fd = -1;
	}
}



/* Block SIGPIPE in the calling thread around Spine's two pipe writes. The
 * daemon normally catches SIGPIPE with a no-op handler process-wide, but this local guard
 * makes these writes safe even before signal initialization or in unit tests
 * that temporarily restore SIG_DFL. Only the default disposition needs its
 * generated signal drained; a caught signal is safe when the old mask returns. */
ssize_t php_write_no_sigpipe(int fd, const void *buffer, size_t length) {
	sigset_t blocked;
	sigset_t old_mask;
	sigset_t pending;
	struct sigaction sigpipe_action;
	ssize_t result;
	int saved_errno;
	int mask_error;
	int received_signal;
	int should_drain = FALSE;
	int was_pending = FALSE;

	sigemptyset(&blocked);
	sigaddset(&blocked, SIGPIPE);
#ifdef SPINE_PHP_RUNTIME_TESTING
	mask_error = spine_php_test_sigmask(SIG_BLOCK, &blocked, &old_mask);
#else
	mask_error = pthread_sigmask(SIG_BLOCK, &blocked, &old_mask);
#endif
	if (mask_error != 0) {
		errno = mask_error;
		return -1;
	}
	if (sigpending(&pending) == 0) was_pending = sigismember(&pending, SIGPIPE);
	if (sigaction(SIGPIPE, NULL, &sigpipe_action) == 0 &&
		sigpipe_action.sa_handler == SIG_DFL) {
		should_drain = TRUE;
	}

	result = write(fd, buffer, length);
	saved_errno = errno;
	if (result < 0 && saved_errno == EPIPE && !was_pending && should_drain) {
		do {
			mask_error = sigwait(&blocked, &received_signal);
		} while (mask_error == EINTR);
	}
	pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	errno = saved_errno;
	return result;
}

/*! \fn char *php_cmd(const char *php_command, int php_process)
 *  \brief calls the script server and executes a script command
 *  \param php_command the formatted php script server command
 *  \param php_process the php script server process to call
 *
 *  This function is called directly by the spine poller when a script server
 *  request has been initiated for a host.  It will place the PHP Script Server
 *  command on it's output pipe and then wait the pre-defined timeout period for
 *  a response on the PHP Script Servers output pipe.
 *
 *  \return pointer to the string results.  Must be freed by the parent.
 *
 */
char *php_cmd(const char *php_command, int php_process) {
	char *result_string;
	char command[BUFSIZE];
	ssize_t bytes;
	int retries = 0;

	assert(php_command != 0);
	if (php_processes == NULL || php_process < 0 || php_process >= set.php.php_servers ||
		php_process >= MAX_PHP_SERVERS) {
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server slot is unavailable", php_process));
		return php_undefined_result();
	}

	/* pad command with CR-LF */
	snprintf(command, BUFSIZE, "%s\r\n", php_command);

	php_process_lock(php_process);

retry:
	/* Validate every attempt under the same per-slot lock that protects
	 * close/restart. A
	 * check before the lock races a recovery and can use a descriptor after it
	 * has been closed and reused by another thread. A failed restart may also
	 * leave live descriptors in a BUSY slot, which must not receive a command. */
	if (php_processes[php_process].php_state != PHP_READY ||
		php_processes[php_process].php_pid <= 1 ||
		php_processes[php_process].php_read_fd < 0 ||
		php_processes[php_process].php_write_fd < 0) {
		php_process_unlock(php_process);
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server slot is unavailable", php_process));
		return php_undefined_result();
	}

	/* send command to the script server */
	bytes = php_write_no_sigpipe(php_processes[php_process].php_write_fd, command, strlen(command));

	/* if write status is <= 0 then the script server may be hung */
	if (bytes <= 0) {
		char script[SMALL_BUFSIZE];

		php_command_script(command, script, sizeof(script));
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server communications lost sending a command.  Restarting PHP Script Server", php_process));
		SPINE_LOG_DEBUG(("DEBUG: SS[%i] Unsent command for script '%s'", php_process, script));

		php_close(php_process);
		retries++;
		if (retries < 3 && php_init(php_process) == TRUE &&
			php_processes[php_process].php_state == PHP_READY) {
			goto retry;
		}

		/* allocated only once the retry budget is spent: a successful retry
		   reassigns result_string below and would orphan an earlier copy */
		result_string = php_undefined_result();
	} else {
		/* read the result from the php_command */
		result_string = php_readpipe(php_process, command);

		/* check for a null */
		if (!strlen(result_string)) {
			SET_UNDEFINED(result_string);
		}
	}

	php_process_unlock(php_process);

	return result_string;
}

/*!  \fn in php_get_process()
 *  \brief returns the next php script server process to utilize
 *
 *  This very simple function simply returns the next PHP Script Server
 *  process id to poll using a round robin algorithm.
 *
 *  \return the next usable script server, or -1 if none is available
 *
 */
int php_get_process(void) {
	int candidate;
	int checked;
	int contended_candidate = -1;
	int recovery_candidate = -1;
	int start_candidate;
	int server_count;

	if (php_processes == NULL || set.php.php_servers <= 0) return -1;
	server_count = set.php.php_servers > MAX_PHP_SERVERS ? MAX_PHP_SERVERS : set.php.php_servers;

	/* LOCK_PHP protects only the round-robin cursor. A startup handshake can
	 * wait for script_timeout, so it must never run under this process-global
	 * lock. */
	thread_mutex_lock(LOCK_PHP);
	if (set.php.php_current_server >= server_count) set.php.php_current_server = 0;
	start_candidate = set.php.php_current_server++;
	thread_mutex_unlock(LOCK_PHP);

	/* Prefer any ready slot. Each snapshot uses the same per-slot mutex as
	 * php_cmd() and recovery, so descriptors cannot change under the check. */
	for (checked = 0; checked < server_count; checked++) {
		candidate = (start_candidate + checked) % server_count;
		if (thread_mutex_trylock(LOCK_PHP_PROC_0 + candidate) != 0) {
			if (contended_candidate < 0) contended_candidate = candidate;
			continue;
		}
		if (php_processes[candidate].php_state == PHP_READY &&
			php_processes[candidate].php_pid > 1 &&
			php_processes[candidate].php_read_fd >= 0 &&
			php_processes[candidate].php_write_fd >= 0) {
			php_process_unlock(candidate);
			return candidate;
		}
		if (recovery_candidate < 0) recovery_candidate = candidate;
		php_process_unlock(candidate);
	}

	/* A locked slot is normally a healthy server executing another command.
	 * Return it so php_cmd() queues on the slot mutex instead of turning routine
	 * contention into an undefined data point, but first repair any failed slot
	 * observed by this scan so steady contention cannot starve pool recovery.
	 * Validation still happens after the contended lock is acquired. */
	if (contended_candidate >= 0 && recovery_candidate < 0)
		return contended_candidate;

	if (recovery_candidate < 0 ||
		thread_mutex_trylock(LOCK_PHP_PROC_0 + recovery_candidate) != 0) {
		return contended_candidate;
	}

	/* Recover at most one slot per request. The per-slot lock prevents a
	 * simultaneous php_cmd() or another recovery from closing the same fd or
	 * signalling a recycled pid. */
	if (php_processes[recovery_candidate].php_state == PHP_READY &&
		php_processes[recovery_candidate].php_pid > 1 &&
		php_processes[recovery_candidate].php_read_fd >= 0 &&
		php_processes[recovery_candidate].php_write_fd >= 0) {
		php_process_unlock(recovery_candidate);
		return recovery_candidate;
	}
	if (php_processes[recovery_candidate].php_pid > 1 ||
		php_processes[recovery_candidate].php_read_fd >= 0 ||
		php_processes[recovery_candidate].php_write_fd >= 0) {
		php_close(recovery_candidate);
	}
	if (php_init(recovery_candidate) == TRUE &&
		php_processes[recovery_candidate].php_state == PHP_READY) {
		php_process_unlock(recovery_candidate);
		return recovery_candidate;
	}
	php_process_unlock(recovery_candidate);

	return contended_candidate;
}

#ifdef SPINE_PHP_RUNTIME_TESTING
ssize_t php_write_no_sigpipe_for_test(int fd, const void *buffer, size_t length) {
	return php_write_no_sigpipe(fd, buffer, length);
}

char *php_read_result_for_test(int php_process, char *command, int allow_restart) {
	return php_read_result(php_process, command, allow_restart);
}
#endif

/*! \fn char *php_readpipe(int php_process, const char *command)
 *  \brief read a line from a PHP Script Server process
 *  \param php_process the PHP Script Server process to obtain output from
 *
 *  This function will read the output pipe from the PHP Script Server process
 *  and return that string to the Spine thread requesting the output.  If for
 *  some reason the PHP Script Server process does not respond in time, it will
 *  be closed using the php_close function, then restarted.
 *
 *  \return a string pointer to the PHP Script Server response
 */
