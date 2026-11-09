/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
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
#include "script/server_internal.h"
#include <limits.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <spawn.h>
#include <sys/wait.h>

/*! \fn int php_output_pending(int fd)
 *  \brief reports whether the script server has output nobody asked for.
 *
 *  The protocol is one request, one response line. Bytes that are already
 *  readable before a request is written, or right after a response line was
 *  read, belong to no request: a function that echoes, or a multi-line
 *  result. Reading them as the next response shifts every later value onto
 *  the wrong item. End of file is not output; the write or read that follows
 *  reports a server that has gone away.
 *
 *  \return TRUE when unread bytes are waiting on fd
 */
int php_output_pending(int fd) {
	struct pollfd pending = {fd, POLLIN, 0};
	int available = 0;
	int status;

	do {
		status = poll(&pending, 1, 0);
	} while (status < 0 && errno == EINTR);
	if (status <= 0 || (pending.revents & POLLIN) == 0) return FALSE;
	/* Readable may only mean end of file. Pipes report their unread byte
	 * count; a descriptor that cannot is left to the normal read and write
	 * error handling. */
	if (ioctl(fd, FIONREAD, &available) != 0) return FALSE;
	return available > 0;
}

/*! \fn char *php_read_response(int php_process, const char *command, int allow_restart, int response_timeout)
 *  \brief reads one script server response within response_timeout seconds.
 *
 *  allow_restart is FALSE for the startup handshake. php_init() calls this to
 *  confirm the server it just spawned is answering, and a restart from inside
 *  that read would call php_init() again, which reads again: a server that
 *  starts but never answers put a poller thread into unbounded mutual
 *  recursion, spawning a fresh server at every level. Refusing the restart on
 *  the handshake bounds the depth at one by construction.
 */
char *php_read_response(int php_process, const char *command, int allow_restart, int response_timeout) {
	fd_set fds;
	struct timeval timeout;
	double begin_time = 0;
	double end_time = 0;
	double remaining = 0;
	char *result_string;
	double read_deadline;
	char script[SMALL_BUFSIZE];

	ssize_t i;
	char *cp;
	char *bptr;

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: php.c php_readpipe!");
	}
	result_string[0] = '\0';

	/* Public readers may be called without php_cmd()'s slot validation. */
	if (php_processes == NULL || php_process < 0 ||
		php_process >= set.php.php_servers || php_process >= MAX_PHP_SERVERS) {
		SET_UNDEFINED(result_string);
		return result_string;
	}

	/* record start time */
	begin_time = get_time_as_double();

	/* establish timeout value for the PHP script server to respond */
	timeout.tv_sec = response_timeout;
	timeout.tv_usec = 0;

	/* select() only says the first bytes arrived. A server that writes part of
	 * a line and stalls must not hold this thread past the same deadline. */
	read_deadline = spine_monotonic_time() + response_timeout;

/* check to see which pipe talked and take action
	 * should only be the READ pipe */
retry:

	/* FD_SET on a descriptor at or past FD_SETSIZE writes outside fds, which is
	   a stack object here. ping_icmp() guards its socket the same way. */
	if (php_processes[php_process].php_read_fd < 0 || php_processes[php_process].php_read_fd >= FD_SETSIZE) {
		SPINE_LOG(("ERROR: SS[%i] Script server descriptor %d exceeds FD_SETSIZE %d", php_process, php_processes[php_process].php_read_fd, FD_SETSIZE));

		SET_UNDEFINED(result_string);
		/* A descriptor that select() cannot represent makes this slot unusable.
		 * Mark it unhealthy even during the startup handshake, where restarting
		 * recursively is deliberately disabled, so the scheduler cannot keep
		 * handing out a permanently poisoned READY slot. */
		php_fail_read(php_process, allow_restart);

		return result_string;
	}

	/* initialize file descriptors to review for input/output */
	FD_ZERO(&fds);
	FD_SET(php_processes[php_process].php_read_fd, &fds);

	switch (select(php_processes[php_process].php_read_fd + 1, &fds, NULL, NULL, &timeout)) {
		case -1:
			switch (errno) {
				case EBADF:
					SPINE_LOG(("ERROR: SS[%i] An invalid file descriptor was given in one of the sets.", php_process));
					break;
				case EINTR:
#ifndef SOLAR_THREAD
					/* take a moment */
					usleep(2000);
#endif

					/* record end time */
					end_time = get_time_as_double();

					/* re-establish new timeout value. A spent timeout is a
					 * timeout: a negative tv_sec makes select() fail with EINVAL. */
					remaining = response_timeout - (end_time - begin_time);

					if (remaining > 0) {
						timeout.tv_sec = (time_t) remaining;
						timeout.tv_usec = (suseconds_t) ((remaining - (double) timeout.tv_sec) * 1000000);
						goto retry;
					} else {
						SPINE_LOG(("WARNING: SS[%i] The Script Server script timed out while processing EINTR's.", php_process));
					}

					break;
				case EINVAL:
					SPINE_LOG(("ERROR: SS[%i] N is negative or the value contained within timeout is invalid.", php_process));
					break;
				case ENOMEM:
					SPINE_LOG(("ERROR: SS[%i] Select was unable to allocate memory for internal tables.", php_process));
					break;
				default:
					SPINE_LOG(("ERROR: SS[%i] Unknown fatal select() error", php_process));
					break;
			}

			SET_UNDEFINED(result_string);
			php_fail_read(php_process, allow_restart);
			break;
		case 0:
			/* record end time */
			end_time = get_time_as_double();
			SPINE_LOG(("WARNING: SS[%i] The PHP Script Server did not respond in time for Timeout[%0.2f] and will therefore be restarted", php_process, end_time - begin_time));
			php_command_script(command, script, sizeof(script));
			SPINE_LOG_DEBUG(("DEBUG: SS[%i] Unanswered command for script '%s'", php_process, script));
			SET_UNDEFINED(result_string);
			php_fail_read(php_process, allow_restart);
			break;
		default: {
			int read_ok = TRUE;

			if (FD_ISSET(php_processes[php_process].php_read_fd, &fds)) {
				bptr = result_string;

				while (1) {
					/* reserve one byte for the trailing '\0' written below */
					size_t used = (size_t) (bptr - result_string);

					/* The check after each read stops the loop once the buffer is
					 * full, so space below cannot underflow. */
					assert(used < RESULTS_BUFFER - 1);

					size_t space = (size_t) RESULTS_BUFFER - 1 - used;

					if (used > 0) {
						int ready = spine_wait_readable(php_processes[php_process].php_read_fd, read_deadline);

						if (ready <= 0) {
							SPINE_LOG(("WARNING: SS[%i] The PHP Script Server sent a partial response and %s", php_process, ready == 0 ? "timed out" : "failed"));
							php_command_script(command, script, sizeof(script));
							SPINE_LOG_DEBUG(("DEBUG: SS[%i] Unanswered command for script '%s'", php_process, script));
							SET_UNDEFINED(result_string);
							read_ok = FALSE;
							break;
						}
					}

					i = read(php_processes[php_process].php_read_fd, bptr, space);

					if (i < 0 && errno == EINTR) {
						continue;
					}

					if (i <= 0) {
						SET_UNDEFINED(result_string);
						read_ok = FALSE;
						break;
					}

					bptr += i;
					*bptr = '\0'; /* make what we've got into a string */

					if ((cp = strstr(result_string, "\n")) != 0) {
						/* Anything past the first line, in this read or already
						 * waiting, is not this request's answer. */
						if (cp + 1 < bptr || php_output_pending(php_processes[php_process].php_read_fd)) {
							SPINE_LOG(("WARNING: SS[%i] The PHP Script Server sent more than one response line and will be restarted", php_process));
							php_command_script(command, script, sizeof(script));
							SPINE_LOG_DEBUG(("DEBUG: SS[%i] Desynchronized command for script '%s'", php_process, script));
							SET_UNDEFINED(result_string);
							read_ok = FALSE;
						}
						break;
					}

					if (bptr >= result_string + RESULTS_BUFFER - 1) {
						SPINE_LOG(("ERROR: SS[%i] The Script Server result was longer than the acceptable range", php_process));
						SET_UNDEFINED(result_string);
						read_ok = FALSE;
						break;
					}
				}
			} else {
				SPINE_LOG(("ERROR: SS[%i] The FD was not set as expected", php_process));
				SET_UNDEFINED(result_string);
				read_ok = FALSE;
			}

			if (read_ok) {
				php_processes[php_process].php_state = PHP_READY;
			} else {
				php_fail_read(php_process, allow_restart);
			}
		} break;
	}

	return result_string;
}

/*! \fn char *php_read_banner(int php_process, int response_timeout)
 *  \brief reads the startup banner of a script server just spawned.
 *
 *  PHP can print notices or warnings from the script server's includes
 *  ahead of the banner. As in 1.2.x, up to PHP_STARTUP_LINES lines are read
 *  within response_timeout and the first that announces the server is taken;
 *  the others are skipped. A request/response read would treat the extra
 *  lines as a desynchronized server and leave the slot BUSY.
 *
 *  \return the banner line, or the last line read (U when none) on failure
 */
char *php_read_banner(int php_process, int response_timeout) {
	char pending[RESULTS_BUFFER];
	size_t used = 0;
	int lines = 0;
	int fd;
	double deadline;
	char *line;

	if (!(line = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: php.c php_read_banner!");
	}
	SET_UNDEFINED(line);

	if (php_processes == NULL || php_process < 0 ||
		php_process >= set.php.php_servers || php_process >= MAX_PHP_SERVERS) {
		return line;
	}

	fd = php_processes[php_process].php_read_fd;
	if (fd < 0 || fd >= FD_SETSIZE) {
		SPINE_LOG(("ERROR: SS[%i] Script server descriptor %d exceeds FD_SETSIZE %d", php_process, fd, FD_SETSIZE));
		php_fail_read(php_process, FALSE);
		return line;
	}

	deadline = spine_monotonic_time() + response_timeout;

	while (lines < PHP_STARTUP_LINES) {
		char *newline = memchr(pending, '\n', used);
		size_t consumed;

		if (newline == NULL) {
			ssize_t received;
			int ready;

			if (used == sizeof(pending) - 1) {
				SPINE_LOG(("ERROR: SS[%i] The Script Server startup line was longer than the acceptable range", php_process));
				break;
			}

			ready = spine_wait_readable(fd, deadline);
			if (ready <= 0) {
				SPINE_LOG(("WARNING: SS[%i] The PHP Script Server did not start within Timeout[%i]", php_process, response_timeout));
				break;
			}

			received = read(fd, pending + used, sizeof(pending) - 1 - used);
			if (received < 0 && errno == EINTR) continue;
			if (received <= 0) break;
			used += (size_t) received;
			continue;
		}

		*newline = '\0';
		consumed = (size_t) (newline - pending) + 1;
		lines++;
		snprintf(line, RESULTS_BUFFER, "%s", pending);
		if (strstr(line, "Started") != NULL) return line;

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] Skipped script server startup output: '%s'", php_process, line));
		used -= consumed;
		memmove(pending, pending + consumed, used);
	}

	return line;
}

/* Selection-path recovery runs the restart handshake while holding the slot
 * lock. Bound it independently so a bad PHP configuration cannot pin every
 * selector for the full per-command timeout. */
char *php_read_result(int php_process, const char *command, int allow_restart) {
	return php_read_response(php_process, command, allow_restart,
		allow_restart || set.php.script_timeout < 2 ? set.php.script_timeout : 2);
}

/*! \fn char *php_readpipe(int php_process, const char *command)
 *  \brief reads a script server response, restarting a server that stops
 *         answering.
 *
 *  \return a string pointer to the PHP Script Server response
 */
char *php_readpipe(int php_process, const char *command) {
	return php_read_result(php_process, command, TRUE);
}
