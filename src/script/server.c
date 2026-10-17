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

/*! \fn static void php_close_fd(int *fd)
 *  \brief close a descriptor once and mark it gone
 *
 *  php_init() has one cleanup path for six descriptors, some of which are
 *  handed to php_processes[] on the way out. Clearing as it closes is what
 *  keeps the shared teardown from closing a descriptor the parent still owns,
 *  or one that another thread has since been given.
 */
static void php_close_fd(int *fd) {
	if (*fd >= 0) {
		(void) close(*fd);
		*fd = -1;
	}
}

static int php_addclose_unless_std(posix_spawn_file_actions_t *fa, int fd) {
	if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
		return 0;
	}

	return posix_spawn_file_actions_addclose(fa, fd);
}

/*! \fn int php_init(int php_process)
 *  \brief initialize either a specific PHP Script Server or all of them.
 *  \param php_process the process number to start or PHP_INIT
 *
 *  This function will either start an individual PHP Script Server process
 *  or all of them if the input parameter is the PHP_INIT constant.  The function
 *  will check the status of the process to verify that it is ready to process
 *  scripts as well.
 *
 *  \return TRUE if the PHP Script Server is know running or FALSE otherwise
 */
int php_init(int php_process) {
	int cacti2php_pdes[2] = {-1, -1};
	int php2cacti_pdes[2] = {-1, -1};
	pid_t pid;
	char poller_id[SMALL_BUFSIZE];
	char *argv[7] = {NULL};
	char arg_q[] = "-q";
	char arg_spine[] = "spine";
	char arg_environ_spine[] = "--environ=spine";
	char arg_mode_online[] = "--mode=online";
	char arg_mode_offline[] = "--mode=offline";
	posix_spawn_file_actions_t fa;
	posix_spawnattr_t attr;
	int fa_valid = FALSE;
	int attr_valid = FALSE;
	int cancel_state = 0;
	int cancel_held = FALSE;
	int child_stdin;
	int child_stdout;
	int dup_stdin = -1;
	int dup_stdout = -1;
	char *result_string = NULL;
	int num_processes;
	int slot = -1;
	int i;
	int rc = FALSE;
	char *command = strdup("INIT");

	if (command == NULL) {
		SPINE_LOG(("ERROR: Fatal malloc error: php.c php_init!"));
		return FALSE;
	}

	/* An out-of-range slot would index past php_processes. */
	if (php_processes == NULL || set.php.php_servers < 0 || set.php.php_servers > MAX_PHP_SERVERS ||
		(php_process != PHP_INIT && (php_process < 0 || php_process >= set.php.php_servers))) {
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server slot is unavailable", php_process));
		goto cleanup;
	}

	/* special code to start all PHP Servers */
	if (php_process == PHP_INIT) {
		num_processes = set.php.php_servers;
	} else {
		num_processes = 1;
	}

	for (i = 0; i < num_processes; i++) {
		/* the spawn retry budget is per server. Sharing one counter across the
		   loop meant that once the first server spent it on EAGAIN, every
		   server after it got none, under exactly the resource pressure the
		   retry exists to ride out. */
		int retry_count = 0;

		slot = (php_process == PHP_INIT) ? i : php_process;

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Routine Starting", i));

		/* create the output pipes from Spine to php*/
		if (!spine_open_pipe_cloexec(cacti2php_pdes)) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", i));
			goto cleanup;
		}

		/* create the input pipes from php to Spine */
		if (!spine_open_pipe_cloexec(php2cacti_pdes)) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", i));
			goto cleanup;
		}

		/* disable thread cancellation from this point forward. */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
		cancel_held = TRUE;

		/* establish arguments for script server execution */
		if (set.cacti_version <= 1222) {
			argv[0] = set.php.path_php;
			argv[1] = arg_q;
			argv[2] = set.php.path_php_server;
			argv[3] = arg_spine;
			snprintf(poller_id, sizeof(poller_id), "%d", set.poller.poller_id);
			argv[4] = poller_id;
			argv[5] = NULL;
		} else if (set.poller.poller_id > 1) {
			argv[0] = set.php.path_php;
			argv[1] = arg_q;
			argv[2] = set.php.path_php_server;
			argv[3] = arg_environ_spine;

			snprintf(poller_id, sizeof(poller_id), "--poller=%d", set.poller.poller_id);
			argv[4] = poller_id;

			if (set.poller.mode == REMOTE_ONLINE) {
				argv[5] = arg_mode_online;
			} else {
				argv[5] = arg_mode_offline;
			}

			argv[6] = NULL;
		} else {
			argv[0] = set.php.path_php;
			argv[1] = arg_q;
			argv[2] = set.php.path_php_server;
			argv[3] = arg_environ_spine;
			snprintf(poller_id, sizeof(poller_id), "--poller=%d", set.poller.poller_id);
			argv[4] = poller_id;

			argv[5] = NULL;
		}

		/* spawn a child process */
		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server About to spawn Child Process", i));

		{
			int spawn_err;

			if (posix_spawn_file_actions_init(&fa) != 0) {
				SPINE_LOG(("ERROR: SS[%i] posix_spawn_file_actions_init failed", i));
				goto cleanup;
			}

			fa_valid = TRUE;
			if (spine_spawnattr_sigpipe_default(&attr) != 0) {
				SPINE_LOG(("ERROR: SS[%i] posix_spawnattr setup failed: %s", i, strerror(errno)));
				goto cleanup;
			}
			attr_valid = TRUE;

			/* wire cacti->php read end to child stdin, php->cacti write end to child stdout */
			/* The pipe ends are close-on-exec, and dup2 clears that on its target, so
			 * the usual case is fine. When an end already sits on the descriptor it is
			 * destined for, dup2(fd, fd) is a no-op that clears nothing and the
			 * unconditional close below would then shut the child's stdin or stdout.
			 * The script server would exec with it closed, never answer, and every
			 * script-server data source would record U with no diagnostic. Reaching it
			 * needs spine to start with fd 0 or 1 closed, which a daemon can do.
			 * Same treatment as nft_popen(): dup() to a fresh descriptor, mark the
			 * temporary copy close-on-exec, then use a child file action to dup2 it. */
			child_stdin = cacti2php_pdes[0];
			child_stdout = php2cacti_pdes[1];

			if (child_stdin == STDIN_FILENO) {
				dup_stdin = dup(child_stdin);
				if (dup_stdin >= 0 && spine_set_cloexec(dup_stdin) != 0) {
					php_close_fd(&dup_stdin);
				}
				child_stdin = dup_stdin;
			}

			if (child_stdout == STDOUT_FILENO) {
				dup_stdout = dup(child_stdout);
				if (dup_stdout >= 0 && spine_set_cloexec(dup_stdout) != 0) {
					php_close_fd(&dup_stdout);
				}
				child_stdout = dup_stdout;
			}

			if (child_stdin < 0 || child_stdout < 0 ||
				posix_spawn_file_actions_adddup2(&fa, child_stdin, STDIN_FILENO) != 0 ||
				posix_spawn_file_actions_adddup2(&fa, child_stdout, STDOUT_FILENO) != 0 ||
				/* close the pipe ends the child does not need. Skip fd 0 and 1: after
			       the redirects above they hold the copies the child polls on. */
				php_addclose_unless_std(&fa, cacti2php_pdes[0]) != 0 ||
				php_addclose_unless_std(&fa, cacti2php_pdes[1]) != 0 ||
				php_addclose_unless_std(&fa, php2cacti_pdes[0]) != 0 ||
				php_addclose_unless_std(&fa, php2cacti_pdes[1]) != 0 ||
				(dup_stdin != -1 && posix_spawn_file_actions_addclose(&fa, dup_stdin) != 0) ||
				(dup_stdout != -1 && posix_spawn_file_actions_addclose(&fa, dup_stdout) != 0)) {
				SPINE_LOG(("ERROR: SS[%i] posix_spawn_file_actions setup failed", i));
				goto cleanup;
			}

			do {
				spawn_err = posix_spawn(&pid, argv[0], &fa, &attr, argv, environ);
				if ((spawn_err == EAGAIN || spawn_err == ENOMEM) && retry_count < 3) {
					retry_count++;
#ifndef SOLAR_THREAD
					usleep(50000);
#endif
					continue;
				}
				break;
			} while (1);

			posix_spawn_file_actions_destroy(&fa);
			fa_valid = FALSE;
			posix_spawnattr_destroy(&attr);
			attr_valid = FALSE;

			/* the child holds its own copies now */
			php_close_fd(&dup_stdin);
			php_close_fd(&dup_stdout);

			if (spawn_err != 0) {
				if (spawn_err == EAGAIN) {
					SPINE_LOG(("ERROR: SS[%i] Could not spawn PHP Script Server Out of Resources", i));
				} else if (spawn_err == ENOMEM) {
					SPINE_LOG(("ERROR: SS[%i] Could not spawn PHP Script Server Out of Memory", i));
				} else {
					SPINE_LOG(("ERROR: SS[%i] Could not spawn PHP Script Server Unknown Reason", i));
				}

				SPINE_LOG(("ERROR: SS[%i] Could not spawn PHP Script Server", i));
				goto cleanup;
			}

			SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Child spawn Success", i));
		}

		/* Parent */
		/* close unneeded pipes */
		php_close_fd(&cacti2php_pdes[0]);
		php_close_fd(&php2cacti_pdes[1]);

		php_processes[slot].php_pid = pid;
		php_processes[slot].php_write_fd = cacti2php_pdes[1];
		php_processes[slot].php_read_fd = php2cacti_pdes[0];

		/* php_processes[] owns these now; the cleanup below must not close them */
		cacti2php_pdes[1] = -1;
		php2cacti_pdes[0] = -1;

		/* restore caller's cancellation state. */
		pthread_setcancelstate(cancel_state, NULL);
		cancel_held = FALSE;

		/* check pipe to insure startup took place */
		result_string = php_read_result(slot, command, FALSE);

		if (strstr(result_string, "Started")) {
			SPINE_LOG_DEBUG(("DEBUG: SS[%i] Confirmed PHP Script Server running using readfd[%i], writefd[%i]", slot, php_processes[slot].php_read_fd, php_processes[slot].php_write_fd));

			php_processes[slot].php_state = PHP_READY;
		} else {
			SPINE_LOG(("ERROR: SS[%i] Script Server did not start properly return message was: '%s'", slot, result_string));

			php_processes[slot].php_state = PHP_BUSY;
		}

		SPINE_FREE(result_string);
	}

	rc = TRUE;

cleanup:
	/* One owner for everything this function allocates. The five exits used to
	 * spell their own teardown out and they had already drifted: every one of
	 * them leaked `command`, and each carried a slightly different subset of
	 * the closes. See ping_icmp() and #593 for the same shape. */
	if (fa_valid) {
		posix_spawn_file_actions_destroy(&fa);
	}
	if (attr_valid) {
		posix_spawnattr_destroy(&attr);
	}

	php_close_fd(&dup_stdin);
	php_close_fd(&dup_stdout);
	php_close_fd(&cacti2php_pdes[0]);
	php_close_fd(&cacti2php_pdes[1]);
	php_close_fd(&php2cacti_pdes[0]);
	php_close_fd(&php2cacti_pdes[1]);

	if (cancel_held) {
		pthread_setcancelstate(cancel_state, NULL);
	}
	if (!rc && php_processes != NULL && slot >= 0 && slot < MAX_PHP_SERVERS) {
		php_processes[slot].php_pid = -1;
		php_processes[slot].php_read_fd = -1;
		php_processes[slot].php_write_fd = -1;
		php_processes[slot].php_state = PHP_BUSY;
	}

	SPINE_FREE(result_string);
	free(command);

	return rc;
}
static int php_terminate_and_reap(pid_t pid) {
	int status;
	pid_t waited;

	do {
		waited = waitpid(pid, &status, WNOHANG);
	} while (waited < 0 && errno == EINTR);

	if (waited == pid || (waited < 0 && errno == ECHILD)) {
		return TRUE;
	}

	if (waited < 0) {
		SPINE_LOG(("WARNING: Unable to reap PHP Script Server PID[%ld]: %s", (long) pid, strerror(errno)));
		return FALSE;
	}

	/* Still running after its grace period: kill outright rather than
	 * waiting to see whether a gentler signal works. */
	if (kill(pid, SIGKILL) < 0 && errno != ESRCH) {
		SPINE_LOG(("WARNING: Unable to signal PHP Script Server PID[%ld]: %s", (long) pid, strerror(errno)));
	}

	return FALSE;
}

/*! \fn void php_close(int php_process)
 *  \brief close the php script server process
 *  \param php_process the process to close or PHP_INIT
 *
 *  This function will take an input parameter of either a specially coded
 *  PHP_INIT parameter or an integer stating the process number.  With that
 *  information is will close and/or terminate the child PHP Script Server
 *  process and then return to the calling function.
 *
	 *  Shutdown gives the server one grace period (the "quit" write plus a
	 *  fixed delay below) to exit on its own, then checks once with a
	 *  non-blocking waitpid(). A child still running at that point is killed
	 *  outright and handed to the abandoned-pid sweep instead of waiting for
	 *  it here.
 */
void php_close(int php_process) {
	int i;
	int num_processes;
	int len;

	/* An out-of-range slot would index past php_processes. */
	if (php_processes == NULL || set.php.php_servers < 0 || set.php.php_servers > MAX_PHP_SERVERS ||
		(php_process != PHP_INIT && (php_process < 0 || php_process >= set.php.php_servers))) {
		return;
	}

	if (php_process == PHP_INIT) {
		num_processes = set.php.php_servers;
	} else {
		num_processes = 1;
	}

	for (i = 0; i < num_processes; i++) {
		php_t *phpp;

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] Script Server Shutdown Started", i));

		/* tell the script server to close */
		if (php_process == PHP_INIT) {
			phpp = &php_processes[i];
		} else {
			phpp = &php_processes[php_process];
		}

		/* If we still have a valid write pipe, tell PHP to close down
		 * by sending a "quit" message, then closing the input channel
		 * so it gets an EOF.
		 *
		 * Then we wait a moment before actually killing it to allow for
		 * a clean shutdown.
		 */
		if (phpp->php_write_fd >= 0) {
			static const char quit[] = "quit\r\n";
			/* A hung server can leave the request pipe full; the quit message
			 * is best effort and must not block shutdown. */
			int flags = fcntl(phpp->php_write_fd, F_GETFL);

			if (flags >= 0) {
				(void) fcntl(phpp->php_write_fd, F_SETFL, flags | O_NONBLOCK);
			}

			len = php_write_no_sigpipe(phpp->php_write_fd, quit, strlen(quit));

			if (len < 0) {
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] Script Server quit write failed, closing anyway", i));
			}

			/* Close regardless of the write result.  A dead child makes the
			 * write fail with EPIPE, and skipping the close leaked one
			 * descriptor per script server restart. */
			close(phpp->php_write_fd);
			phpp->php_write_fd = -1;

			/* wait before killing php */
			usleep(50000); /* 50 msec */
		}

		/* only try to kill the process if the PID looks valid.
		 * Trying to kill a negative number is bad news (it's
		 * a process group leader), and PID 1 is "init".
		 */
		if (phpp->php_pid > 1) {
			if (!php_terminate_and_reap(phpp->php_pid)) {
				nft_abandon_child(phpp->php_pid, "PHP child survived shutdown budget");
			}

			phpp->php_pid = -1;
		}

		/* close file descriptors */
		close(phpp->php_read_fd);
		phpp->php_read_fd = -1;
	}
}
