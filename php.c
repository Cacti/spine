/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2024 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#define _GNU_SOURCE
#include "common.h"
#include "spine.h"
#include <fcntl.h>

static pid_t php_orphan_pids[MAX_PHP_SERVERS];
static time_t php_retry_after[MAX_PHP_SERVERS];
static void php_drain_orphans(void);
static void php_close_internal(int php_process, int send_quit);
static pid_t php_get_pid(int server);
static char *php_readpipe_until(int php_process, char *command, double deadline);

static ssize_t php_write_no_sigpipe(int fd, const void *buffer, size_t length) {
	const char *cursor = buffer;
	int saved_errno = errno;
	int sigpipe_was_pending;
	sigset_t blocked;
	sigset_t old_mask;
	sigset_t pending;
	ssize_t total = 0;
	ssize_t written = 0;

	sigemptyset(&blocked);
	sigaddset(&blocked, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &blocked, &old_mask);
	sigpending(&pending);
	sigpipe_was_pending = sigismember(&pending, SIGPIPE);

	while ((size_t)total < length) {
		written = write(fd, cursor + total, length - (size_t)total);
		if (written > 0) {
			total += written;
			continue;
		}
		if (written < 0 && errno == EINTR) {
			continue;
		}

		saved_errno = written == 0 ? EIO : errno;
		total = -1;
		break;
	}

	if (total < 0 && saved_errno == EPIPE && !sigpipe_was_pending) {
		int received_signal;

		/* Some platforms discard an ignored SIGPIPE instead of queuing it.
		 * Consume the signal only when the failed write actually made it
		 * pending, so this cleanup can never block. */
		sigpending(&pending);
		if (sigismember(&pending, SIGPIPE)) {
			sigwait(&blocked, &received_signal);
		}
	}

	pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
	errno = saved_errno;

	return total;
}

static int php_set_cloexec(int fd) {
	int flags = fcntl(fd, F_GETFD);

	return flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static int php_pipe_cloexec(int pipe_fds[2]) {
	#ifdef HAVE_PIPE2
	return pipe2(pipe_fds, O_CLOEXEC);
	#else
	thread_mutex_lock(LOCK_FORK);
	if (pipe(pipe_fds) < 0) {
		thread_mutex_unlock(LOCK_FORK);
		return -1;
	}
	if (!php_set_cloexec(pipe_fds[0]) || !php_set_cloexec(pipe_fds[1])) {
		int saved_errno = errno;
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		thread_mutex_unlock(LOCK_FORK);
		errno = saved_errno;
		return -1;
	}
	thread_mutex_unlock(LOCK_FORK);
	return 0;
	#endif
}

static void php_set_state(int php_process, int state) {
	thread_mutex_lock(LOCK_PHP);
	php_processes[php_process].php_state = state;
	if (state == PHP_READY) {
		php_retry_after[php_process] = 0;
	} else {
		php_retry_after[php_process] = time(NULL) + 30;
	}
	thread_mutex_unlock(LOCK_PHP);
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
	int write_fd;
	int retries = 0;

	assert(php_command != 0);

	/* pad command with CR-LF */
	snprintf(command, BUFSIZE, "%s\r\n", php_command);

	/* place lock around mutex */
	switch (php_process) {
	case 0:  thread_mutex_lock(LOCK_PHP_PROC_0);  break;
	case 1:  thread_mutex_lock(LOCK_PHP_PROC_1);  break;
	case 2:  thread_mutex_lock(LOCK_PHP_PROC_2);  break;
	case 3:  thread_mutex_lock(LOCK_PHP_PROC_3);  break;
	case 4:  thread_mutex_lock(LOCK_PHP_PROC_4);  break;
	case 5:  thread_mutex_lock(LOCK_PHP_PROC_5);  break;
	case 6:  thread_mutex_lock(LOCK_PHP_PROC_6);  break;
	case 7:  thread_mutex_lock(LOCK_PHP_PROC_7);  break;
	case 8:  thread_mutex_lock(LOCK_PHP_PROC_8);  break;
	case 9:  thread_mutex_lock(LOCK_PHP_PROC_9);  break;
	case 10: thread_mutex_lock(LOCK_PHP_PROC_10); break;
	case 11: thread_mutex_lock(LOCK_PHP_PROC_11); break;
	case 12: thread_mutex_lock(LOCK_PHP_PROC_12); break;
	case 13: thread_mutex_lock(LOCK_PHP_PROC_13); break;
	case 14: thread_mutex_lock(LOCK_PHP_PROC_14); break;
	}

	/* send command to the script server */
	retry:
	thread_mutex_lock(LOCK_PHP);
	write_fd = php_processes[php_process].php_write_fd;
	thread_mutex_unlock(LOCK_PHP);
	bytes = php_write_no_sigpipe(write_fd, command, strlen(command));

	/* if write status is <= 0 then the script server may be hung */
	if (bytes <= 0) {
		STRDUP_OR_DIE(result_string, "U", "php_cmd result");
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server communications lost sending Command[%s].  Restarting PHP Script Server", php_process, command));

		php_close(php_process);
		if (!php_init(php_process)) {
			retries = 3;
		}
		/* increment and retry a few times on the next item */
		retries++;
		if (retries < 3) {
			SPINE_FREE(result_string);
			goto retry;
		}
	} else {
		/* read the result from the php_command */
		result_string = php_readpipe(php_process, command);

		/* check for a null */
		if (!strlen(result_string)) {
			SET_UNDEFINED(result_string);
		}
	}

	/* unlock around php process */
	switch (php_process) {
	case 0:  thread_mutex_unlock(LOCK_PHP_PROC_0);  break;
	case 1:  thread_mutex_unlock(LOCK_PHP_PROC_1);  break;
	case 2:  thread_mutex_unlock(LOCK_PHP_PROC_2);  break;
	case 3:  thread_mutex_unlock(LOCK_PHP_PROC_3);  break;
	case 4:  thread_mutex_unlock(LOCK_PHP_PROC_4);  break;
	case 5:  thread_mutex_unlock(LOCK_PHP_PROC_5);  break;
	case 6:  thread_mutex_unlock(LOCK_PHP_PROC_6);  break;
	case 7:  thread_mutex_unlock(LOCK_PHP_PROC_7);  break;
	case 8:  thread_mutex_unlock(LOCK_PHP_PROC_8);  break;
	case 9:  thread_mutex_unlock(LOCK_PHP_PROC_9);  break;
	case 10: thread_mutex_unlock(LOCK_PHP_PROC_10); break;
	case 11: thread_mutex_unlock(LOCK_PHP_PROC_11); break;
	case 12: thread_mutex_unlock(LOCK_PHP_PROC_12); break;
	case 13: thread_mutex_unlock(LOCK_PHP_PROC_13); break;
	case 14: thread_mutex_unlock(LOCK_PHP_PROC_14); break;
	}

	return result_string;
}

/*!  \fn in php_get_process()
 *  \brief returns the next php script server process to utilize
 *
 *  Returns the next ready PHP Script Server using round robin. Busy slots are
 *  skipped while another ready server is available.
 *
 *  \return the next ready script server, or -1 when the pool is unavailable
 *
 */
int php_get_process(void) {
	int attempts;
	int i = -1;
	time_t now = time(NULL);

	thread_mutex_lock(LOCK_PHP);
	for (attempts = 0; attempts < set.php_servers; attempts++) {
		if (set.php_current_server >= set.php_servers) {
			set.php_current_server = 0;
		}

		i = set.php_current_server++;
		if (php_processes[i].php_state == PHP_READY) {
			break;
		}
		i = -1;
	}

	/* Give unavailable slots a bounded route back without attempting a
	 * fork/exec for every script-server item in the cycle.  php_cmd() will
	 * exercise the established close/restart path for the selected slot. */
	if (i < 0 && set.php_initialized) {
		for (attempts = 0; attempts < set.php_servers; attempts++) {
			if (set.php_current_server >= set.php_servers) {
				set.php_current_server = 0;
			}

			i = set.php_current_server++;
			if (php_retry_after[i] <= now) {
				php_retry_after[i] = now + 30;
				break;
			}
			i = -1;
		}
	}
	thread_mutex_unlock(LOCK_PHP);

	return i;
}

/*! \fn char *php_readpipe(int php_process, char *command)
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
char *php_readpipe(int php_process, char *command) {
	return php_readpipe_until(php_process, command, get_time_as_double() + set.script_timeout);
}

static char *php_readpipe_until(int php_process, char *command, double deadline) {
	fd_set fds;
	struct timeval timeout;
	double begin_time = 0;
	double end_time = 0;
	double remaining_usec = 0;
	char *result_string;

	int  i;
	int  read_fd;
	int  reset_server = FALSE;
	int  send_quit = TRUE;
	char *cp;
	char *bptr;

	if (!(result_string = (char *)malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: php.c php_readpipe!");
	}
	result_string[0] = '\0';

	thread_mutex_lock(LOCK_PHP);
	read_fd = php_processes[php_process].php_read_fd;
	thread_mutex_unlock(LOCK_PHP);
	if (read_fd < 0) {
		SET_UNDEFINED(result_string);
		php_close_internal(php_process, FALSE);
		if (strcmp(command, "INIT") != 0) {
			php_init(php_process);
		}
		return result_string;
	}

	/* record start time */
	begin_time = get_time_as_double();

	/* establish timeout value for the PHP script server to respond */
	remaining_usec = deadline - begin_time;
	if (remaining_usec < 0) {
		remaining_usec = 0;
	}
	timeout.tv_sec = (int)remaining_usec;
	timeout.tv_usec = (int)((remaining_usec - timeout.tv_sec) * 1000000);

	/* check to see which pipe talked and take action
	 * should only be the READ pipe */
	retry:

	/* initialize file descriptors to review for input/output */
	FD_ZERO(&fds);
	FD_SET(read_fd,&fds);

	switch (select(read_fd+1, &fds, NULL, NULL, &timeout)) {
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

				/* re-establish new timeout value */
				remaining_usec = deadline - end_time;
				if (remaining_usec < 0) {
					remaining_usec = 0;
				}
				timeout.tv_sec = (int)remaining_usec;
				timeout.tv_usec = (int)((remaining_usec - timeout.tv_sec) * 1000000);

				if (timeout.tv_sec + timeout.tv_usec > 0) {
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

		/* kill script server because it is misbehaving */
		php_close(php_process);
		if (strcmp(command, "INIT") != 0) {
			php_init(php_process);
		}
		break;
	case 0:
		/* record end time */
		end_time = get_time_as_double();
		SPINE_LOG(("WARNING: SS[%i] The PHP Script Server did not respond in time for Timeout[%0.2f], Command[%s] and will therefore be restarted", php_process, end_time - begin_time, command));
		SET_UNDEFINED(result_string);

		/* kill script server because it is misbehaving */
		php_close(php_process);
		if (strcmp(command, "INIT") != 0) {
			php_init(php_process);
		}
		break;
	default:
		if (FD_ISSET(read_fd, &fds)) {
			bptr = result_string;

			while (1) {
				size_t avail;
				size_t used;

				/* reserve one byte for the trailing '\0' written below */
				used = (size_t)(bptr - result_string);

				if (used >= RESULTS_BUFFER - 1) {
					SPINE_LOG(("ERROR: SS[%i] The Script Server result was longer than the acceptable range", php_process));
					SET_UNDEFINED(result_string);
					reset_server = TRUE;
					break;
				}

				/* A newline may require multiple reads.  Re-check readability
				 * against the original command deadline before every one so a
				 * partial line cannot hold this worker indefinitely. */
				end_time = get_time_as_double();
				remaining_usec = deadline - end_time;
				if (remaining_usec <= 0) {
					SPINE_LOG(("WARNING: SS[%i] The PHP Script Server stalled during a partial response", php_process));
					SET_UNDEFINED(result_string);
					reset_server = TRUE;
					break;
				}

				timeout.tv_sec = (int)remaining_usec;
				timeout.tv_usec = (int)((remaining_usec - timeout.tv_sec) * 1000000);
				FD_ZERO(&fds);
				FD_SET(read_fd, &fds);
				i = select(read_fd + 1, &fds, NULL, NULL, &timeout);
				if (i < 0 && errno == EINTR) {
					continue;
				}
				if (i <= 0 || !FD_ISSET(read_fd, &fds)) {
					SPINE_LOG(("WARNING: SS[%i] The PHP Script Server did not complete its response", php_process));
					SET_UNDEFINED(result_string);
					reset_server = TRUE;
					break;
				}

				avail = (size_t)RESULTS_BUFFER - 1 - used;
				i = read(read_fd, bptr, avail);

				if (i < 0 && errno == EINTR) {
					continue;
				}

				if (i <= 0) {
					SET_UNDEFINED(result_string);
					reset_server = TRUE;
					if (i == 0) {
						send_quit = FALSE;
					}
					break;
				}

				bptr += i;
				*bptr = '\0';	/* make what we've got into a string */

				if ((cp = strstr(result_string,"\n")) != 0) {
					break;
				}
			}
		} else {
			SPINE_LOG(("ERROR: SS[%i] The FD was not set as expected", php_process));
			SET_UNDEFINED(result_string);
			reset_server = TRUE;
		}

		if (reset_server) {
			/* The unread tail belongs to this response.  Reusing the pipe would
			 * return it as the next command's result, so discard the process and
			 * start with a fresh protocol stream. */
			php_close_internal(php_process, send_quit);
			if (strcmp(command, "INIT") != 0) {
				php_init(php_process);
			}
		} else if (strcmp(command, "INIT") != 0) {
			php_set_state(php_process, PHP_READY);
		}
	}

	return result_string;
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
	int  cacti2php_pdes[2];
	int  php2cacti_pdes[2];
	pid_t  pid;
	char poller_id[BUFSIZE];
	char mode[BUFSIZE];
	char *argv[7];
	int  cancel_state;
	char *result_string = 0;
	int num_processes;
	int i;
	int ready_count = 0;
	int retry_count = 0;
	char *command;

	/* php_init(PHP_INIT) runs before the main initialization block.  The
	 * pthread_once-backed initializer is idempotent and makes the orphan-list
	 * lock available both here and in later per-server restarts. */
	init_mutexes();
	command = strdup("INIT");
	if (command == NULL) {
		die("ERROR: Fatal malloc error: php.c php_init command!");
	}
	php_drain_orphans();

	/* special code to start all PHP Servers */
	if (php_process == PHP_INIT) {
		num_processes = set.php_servers;
	} else {
		num_processes = 1;
	}

	for (i=0; i < num_processes; i++) {
		double handshake_deadline;
		int handshake_lines;
		int server = (php_process == PHP_INIT) ? i : php_process;
		retry_count = 0;
		if (php_get_pid(server) > 1) {
			SPINE_LOG(("WARNING: SS[%i] Refusing to replace an unreaped PHP Script Server", server));
			php_set_state(server, PHP_BUSY);
			if (php_process == PHP_INIT) {
				continue;
			}
			SPINE_FREE(command);
			return FALSE;
		}

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Routine Starting", server));

		/* create the output pipes from Spine to php*/
		if (php_pipe_cloexec(cacti2php_pdes) < 0) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", server));
			if (php_process == PHP_INIT) {
				continue;
			}
			SPINE_FREE(command);
			return FALSE;
		}

		/* create the input pipes from php to Spine */
		if (php_pipe_cloexec(php2cacti_pdes) < 0) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", server));
			close(cacti2php_pdes[0]);
			close(cacti2php_pdes[1]);
			if (php_process == PHP_INIT) {
				continue;
			}
			SPINE_FREE(command);
			return FALSE;
		}

		/* disable thread cancellation from this point forward. */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

		/* establish arguments for script server execution */
		if (set.cacti_version <= 1222) {
			argv[0] = set.path_php;
			argv[1] = "-q";
			argv[2] = set.path_php_server;
			argv[3] = "spine";
			snprintf(poller_id, BUFSIZE, "%d", set.poller_id);
			argv[4] = poller_id;
			argv[5] = NULL;
		} else if (set.poller_id > 1) {
			argv[0] = set.path_php;
			argv[1] = "-q";
			argv[2] = set.path_php_server;
			argv[3] = "--environ=spine";

			snprintf(poller_id, BUFSIZE, "--poller=%d", set.poller_id);
			argv[4] = poller_id;

			if (set.mode == REMOTE_ONLINE) {
				snprintf(mode, BUFSIZE, "--mode=online");
			} else {
				snprintf(mode, BUFSIZE, "--mode=offline");
			}
			argv[5] = mode;

			argv[6] = NULL;
		} else {
			argv[0] = set.path_php;
			argv[1] = "-q";
			argv[2] = set.path_php_server;
			argv[3] = "--environ=spine";
			snprintf(poller_id, BUFSIZE, "--poller=%d", set.poller_id);
			argv[4] = poller_id;

			argv[5] = NULL;
		}

		/* fork a child process */
		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server About to FORK Child Process", server));

		retry:

		thread_mutex_lock(LOCK_FORK);
		pid = vfork();
		if (pid != 0) {
			thread_mutex_unlock(LOCK_FORK);
		}

		/* check the pid status and process as required */
		switch (pid) {
			case -1: /* ERROR: Could not fork() */
				switch (errno) {
				case EAGAIN:
					if (retry_count < 3) {
						retry_count++;
						#ifndef SOLAR_THREAD
						/* take a moment */
						usleep(50000);
						#endif
						goto retry;
					} else {
						SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Out of Resources", server));
					}
					break;
				case ENOMEM:
					if (retry_count < 3) {
						retry_count++;
						#ifndef SOLAR_THREAD
						/* take a moment */
						usleep(50000);
						#endif
						goto retry;
					} else {
						SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Out of Memory", server));
					}
					break;
				default:
					SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Unknown Reason", server));
				}

				close(php2cacti_pdes[0]);
				close(php2cacti_pdes[1]);
				close(cacti2php_pdes[0]);
				close(cacti2php_pdes[1]);

				SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server", server));
				pthread_setcancelstate(cancel_state, NULL);
				if (php_process == PHP_INIT) {
					continue;
				}
				SPINE_FREE(command);

				return FALSE;
				/* NOTREACHED */
			case 0:	/* SUCCESS: I am now the child */
				/* set the standard input/output channels of the new process.  */
				dup2(cacti2php_pdes[0], STDIN_FILENO);
				dup2(php2cacti_pdes[1], STDOUT_FILENO);
				fcntl(STDIN_FILENO, F_SETFD, 0);
				fcntl(STDOUT_FILENO, F_SETFD, 0);

				/* close unneeded Pipes */
				(void)close(php2cacti_pdes[0]);
				(void)close(php2cacti_pdes[1]);
				(void)close(cacti2php_pdes[0]);
				(void)close(cacti2php_pdes[1]);

				/* start the php script server process */
				execv(argv[0], argv);
				_exit(127);
				/* NOTREACHED */
			default: /* I am the parent process */
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Child FORK Success", server));
		}

		/* Parent */
		/* close unneeded pipes */
		close(cacti2php_pdes[0]);
		close(php2cacti_pdes[1]);

		thread_mutex_lock(LOCK_PHP);
		php_processes[server].php_pid      = pid;
		php_processes[server].php_write_fd = cacti2php_pdes[1];
		php_processes[server].php_read_fd  = php2cacti_pdes[0];
		thread_mutex_unlock(LOCK_PHP);

		/* restore caller's cancellation state. */
		pthread_setcancelstate(cancel_state, NULL);

		/* check pipe to insure startup took place */
		/* PHP can emit a bounded number of startup notices before the banner.
		 * Consume complete lines until the handshake arrives, but share one
		 * script_timeout budget across the entire handshake. */
		handshake_deadline = get_time_as_double() + set.script_timeout;
		for (handshake_lines = 0; handshake_lines < 10; handshake_lines++) {
			result_string = php_readpipe_until(server, command, handshake_deadline);

			if (strstr(result_string, "Started")) {
				break;
			}

			if (strcmp(result_string, "U") == 0) {
				break;
			}

			SPINE_FREE(result_string);
		}

		if (result_string != NULL && strstr(result_string, "Started")) {
			SPINE_LOG_DEBUG(("DEBUG: SS[%i] Confirmed PHP Script Server running using readfd[%i], writefd[%i]", server, php2cacti_pdes[0], cacti2php_pdes[1]));
			php_set_state(server, PHP_READY);
			ready_count++;
		} else {
			SPINE_LOG(("ERROR: SS[%i] Script Server did not start properly return message was: '%s'", server, result_string != NULL ? result_string : "U"));
			php_close_internal(server, TRUE);
			php_set_state(server, PHP_BUSY);
		}

		SPINE_FREE(result_string);
	}

	SPINE_FREE(command);

	return ready_count > 0;
}

static void php_reap_delay(void) {
	struct timeval delay;

	do {
		delay.tv_sec  = 0;
		delay.tv_usec = 10000;
	} while (select(0, NULL, NULL, NULL, &delay) < 0 && errno == EINTR);
}

static pid_t php_get_pid(int server) {
	pid_t pid;

	thread_mutex_lock(LOCK_PHP);
	pid = php_processes[server].php_pid;
	thread_mutex_unlock(LOCK_PHP);

	return pid;
}

static int php_try_reap(int server) {
	int reap_error = 0;
	int status;
	pid_t pid;
	pid_t waited;

	thread_mutex_lock(LOCK_PHP);
	pid = php_processes[server].php_pid;
	if (pid <= 1) {
		thread_mutex_unlock(LOCK_PHP);
		return TRUE;
	}

	do {
		waited = waitpid(pid, &status, WNOHANG);
	} while (waited < 0 && errno == EINTR);

	if (waited == pid || (waited < 0 && errno == ECHILD)) {
		php_processes[server].php_pid = -1;
		thread_mutex_unlock(LOCK_PHP);
		return TRUE;
	}

	if (waited < 0) {
		reap_error = errno;
	}
	thread_mutex_unlock(LOCK_PHP);

	if (reap_error != 0) {
		SPINE_LOG(("WARNING: Unable to reap PHP Script Server PID[%ld]: %s", (long)pid, strerror(reap_error)));
	}

	return FALSE;
}

static void php_signal_servers(int first_process, int num_processes, int signal_number) {
	int i;

	for (i = 0; i < num_processes; i++) {
		int signal_error = 0;
		int server = first_process + i;
		pid_t pid;

		thread_mutex_lock(LOCK_PHP);
		pid = php_processes[server].php_pid;
		if (pid > 1 && kill(pid, signal_number) < 0 && errno != ESRCH) {
			signal_error = errno;
		}
		thread_mutex_unlock(LOCK_PHP);

		if (signal_error != 0) {
			SPINE_LOG(("WARNING: Unable to signal PHP Script Server PID[%ld]: %s", (long)pid, strerror(signal_error)));
		}
	}
}

static void php_reap_servers(int first_process, int num_processes) {
	int attempts;
	int i;

	/* Poll every child once per round.  All children receive their signal
	 * before this runs, so the grace period is shared rather than multiplied
	 * by the number of configured script servers. */
	for (attempts = 0; attempts < 10; attempts++) {
		int remaining = 0;

		for (i = 0; i < num_processes; i++) {
			if (!php_try_reap(first_process + i)) {
				remaining++;
			}
		}

		if (remaining == 0) {
			return;
		}

		php_reap_delay();
	}
}

static int php_park_orphan(int server, pid_t expected_pid) {
	int i;
	int parked = FALSE;

	thread_mutex_lock(LOCK_PHP);
	if (php_processes[server].php_pid == expected_pid) {
		for (i = 0; i < MAX_PHP_SERVERS; i++) {
			if (php_orphan_pids[i] <= 1) {
				php_orphan_pids[i] = expected_pid;
				php_processes[server].php_pid = -1;
				parked = TRUE;
				break;
			}
		}
	}
	thread_mutex_unlock(LOCK_PHP);

	return parked;
}

static void php_drain_orphans(void) {
	int i;
	int reap_error = 0;
	int signal_error = 0;
	pid_t reap_error_pid = -1;
	pid_t signal_error_pid = -1;

	thread_mutex_lock(LOCK_PHP);
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		int status;
		pid_t waited;

		if (php_orphan_pids[i] <= 1) {
			continue;
		}

		do {
			waited = waitpid(php_orphan_pids[i], &status, WNOHANG);
		} while (waited < 0 && errno == EINTR);

		if (waited == php_orphan_pids[i] || (waited < 0 && errno == ECHILD)) {
			php_orphan_pids[i] = -1;
		} else if (waited < 0) {
			reap_error_pid = php_orphan_pids[i];
			reap_error = errno;
		} else if (kill(php_orphan_pids[i], SIGKILL) < 0 && errno != ESRCH) {
			/* A zero wait result proves this PID is still our live child.  With
			 * SIGCHLD normalized to SIG_DFL it cannot be recycled until reaped. */
			signal_error_pid = php_orphan_pids[i];
			signal_error = errno;
		}
	}
	thread_mutex_unlock(LOCK_PHP);

	if (signal_error_pid > 1) {
		SPINE_LOG(("WARNING: Unable to re-signal unreaped PHP Script Server PID[%ld]: %s", (long)signal_error_pid, strerror(signal_error)));
	}
	if (reap_error_pid > 1) {
		SPINE_LOG(("WARNING: Unable to retry reap of PHP Script Server PID[%ld]: %s", (long)reap_error_pid, strerror(reap_error)));
	}
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
 *  TODO: Make ending of the child process not be reliant on SIG_TERM in cases
 *  where the child process is hung for one reason or another.
 *
 */
static void php_close_internal(int php_process, int send_quit) {
	int first_process;
	int had_write_pipe = FALSE;
	int i;
	int num_processes;
	int len;

	php_drain_orphans();

	if (php_process == PHP_INIT) {
		first_process = 0;
		num_processes = set.php_servers;
	} else {
		first_process = php_process;
		num_processes = 1;
	}

	for (i = 0; i < num_processes; i++) {
		int server = first_process + i;
		php_t *phpp = &php_processes[server];
		int write_fd;

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] Script Server Shutdown Started", server));

		thread_mutex_lock(LOCK_PHP);
		phpp->php_state = PHP_BUSY;
		php_retry_after[server] = time(NULL) + 30;
		write_fd = phpp->php_write_fd;
		phpp->php_write_fd = -1;
		thread_mutex_unlock(LOCK_PHP);

		/* tell the script server to close */
		/* If we still have a valid write pipe, tell PHP to close down
		 * by sending a "quit" message, then closing the input channel
		 * so it gets an EOF.  Every server receives the request before
		 * the shared grace period starts.
		 */
		if (write_fd >= 0) {
			static const char quit[] = "quit\r\n";

			len = send_quit ? php_write_no_sigpipe(write_fd, quit, strlen(quit)) : 0;

			if (len < 0) {
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] Script Server quit write failed, closing anyway", server));
			}

			close(write_fd);
			had_write_pipe = TRUE;
		}
	}

	if (had_write_pipe) {
		#ifndef SOLAR_THREAD
		usleep(50000);			/* 50 msec */
		#endif
	}

	/* Signal all children before waiting so shutdown latency is bounded by a
	 * shared grace period instead of one grace period per server. */
	php_signal_servers(first_process, num_processes, SIGTERM);
	php_reap_servers(first_process, num_processes);
	php_signal_servers(first_process, num_processes, SIGKILL);
	php_reap_servers(first_process, num_processes);

	for (i = 0; i < num_processes; i++) {
		int server = first_process + i;
		int read_fd;
		pid_t pid = php_get_pid(server);

		if (pid > 1) {
			/* Move the handle out of the active slot so a replacement can
			 * start while later closes keep retrying this reap. */
			SPINE_LOG(("WARNING: PHP Script Server PID[%ld] did not exit after SIGKILL", (long)pid));
			if (!php_park_orphan(server, pid)) {
				php_drain_orphans();
				if (!php_park_orphan(server, pid)) {
					/* Leave the unreaped PID in its active slot.  php_init() will
					 * refuse to overwrite it and the cooldown bounds retry churn. */
					php_set_state(server, PHP_BUSY);
					SPINE_LOG(("WARNING: Unable to retain PHP Script Server PID[%ld] for a later reap; slot remains unavailable", (long)pid));
				}
			}
		}

		/* close file descriptors */
		thread_mutex_lock(LOCK_PHP);
		read_fd = php_processes[server].php_read_fd;
		php_processes[server].php_read_fd = -1;
		thread_mutex_unlock(LOCK_PHP);

		if (read_fd >= 0) {
			close(read_fd);
		}
	}
}

void php_close(int php_process) {
	php_close_internal(php_process, TRUE);
}
