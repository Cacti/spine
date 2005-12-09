/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 | cactid: a backend data gatherer for cacti                               |
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

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "php.h"
#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "util.h"

extern char **environ;

/******************************************************************************/
/*  php_cmd() - send a command to the script server                           */
/******************************************************************************/
char *php_cmd(char *php_command, int php_process) {
	char *result_string;
	char command[BUFSIZE];
	char logmessage[LOGSIZE];
	int write_status;

	/* pad command with CR-LF */
	snprintf(command, sizeof(command)-1, "%s\r\n", php_command);

	/* place lock around mutex */
	switch (php_process) {
	case 0:
		thread_mutex_lock(LOCK_PHP_PROC_0);
		break;
	case 1:
		thread_mutex_lock(LOCK_PHP_PROC_1);
		break;
	case 2:
		thread_mutex_lock(LOCK_PHP_PROC_2);
		break;
	case 3:
		thread_mutex_lock(LOCK_PHP_PROC_3);
		break;
	case 4:
		thread_mutex_lock(LOCK_PHP_PROC_4);
		break;
	case 5:
		thread_mutex_lock(LOCK_PHP_PROC_5);
		break;
	case 6:
		thread_mutex_lock(LOCK_PHP_PROC_6);
		break;
	case 7:
		thread_mutex_lock(LOCK_PHP_PROC_7);
		break;
	case 8:
		thread_mutex_lock(LOCK_PHP_PROC_8);
		break;
	case 9:
		thread_mutex_lock(LOCK_PHP_PROC_9);
		break;
	}

	/* send command to the script server */
	write_status = write(php_processes[php_process].php_write_fd, command, strlen(command));

	/* if write status is <= 0 then the script server may be hung */
	if (write_status <= 0) {
		result_string = strdup("U");
		snprintf(logmessage, sizeof(logmessage)-1, "ERROR: SS[%i] PHP Script Server communications lost.\n", php_process);
		cacti_log(logmessage);
		php_close(php_process);
	}else{
		/* read the result from the php_command */
		result_string = php_readpipe(php_process);
	}

	/* unlock around php process */
	switch (php_process) {
	case 0:
		thread_mutex_unlock(LOCK_PHP_PROC_0);
		break;
	case 1:
		thread_mutex_unlock(LOCK_PHP_PROC_1);
		break;
	case 2:
		thread_mutex_unlock(LOCK_PHP_PROC_2);
		break;
	case 3:
		thread_mutex_unlock(LOCK_PHP_PROC_3);
		break;
	case 4:
		thread_mutex_unlock(LOCK_PHP_PROC_4);
		break;
	case 5:
		thread_mutex_unlock(LOCK_PHP_PROC_5);
		break;
	case 6:
		thread_mutex_unlock(LOCK_PHP_PROC_6);
		break;
	case 7:
		thread_mutex_unlock(LOCK_PHP_PROC_7);
		break;
	case 8:
		thread_mutex_unlock(LOCK_PHP_PROC_8);
		break;
	case 9:
		thread_mutex_unlock(LOCK_PHP_PROC_9);
		break;
	}

	return result_string;
}

/******************************************************************************/
/*  php_get_process() - get an available php script server process from queue */
/******************************************************************************/
int php_get_process() {
	int i;
		
	thread_mutex_lock(LOCK_PHP);
	if (set.php_current_server >= set.php_servers) {
		set.php_current_server = 0;
	}
	i = set.php_current_server;
	set.php_current_server++;
	thread_mutex_unlock(LOCK_PHP);
	
	return i;
}

/******************************************************************************/
/*  php_readpipe - read a line from the PHP script server                     */
/******************************************************************************/
char *php_readpipe(int php_process) {
	extern errno;
	fd_set fds;
	int rescode, numfds;
	struct timeval timeout;
	struct timeval now;
	double begin_time = 0;
	double end_time = 0;
	char logmessage[LOGSIZE];
	char *result_string;

	if (!(result_string = (char *)malloc(BUFSIZE))) {
		cacti_log("ERROR: Fatal malloc error: php.c php_readpipe!\n");
		exit_cactid();
	}
	memset(result_string, 0, BUFSIZE);	

	/* record start time */
	if (gettimeofday(&now, NULL) == -1) {
		cacti_log("ERROR: Function gettimeofday failed.  Exiting cactid\n");
		exit_cactid();
	}

	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	/* initialize file descriptors to review for input/output */
	FD_ZERO(&fds);
	FD_SET(php_processes[php_process].php_read_fd,&fds);
	numfds = php_processes[php_process].php_read_fd + 1;

	/* establish timeout value for the PHP script server to respond */
	timeout.tv_sec = set.script_timeout;
	timeout.tv_usec = 0;

	/* check to see which pipe talked and take action
	 * should only be the READ pipe */
	retry:
	switch (select(numfds, &fds, NULL, NULL, &timeout)) {
	case -1:
		switch (errno) {
			case EBADF:
				snprintf(logmessage, LOGSIZE-1, "ERROR: SS[%i] An invalid file descriptor was given in one of the sets.\n", php_process);
				break;
			case EINTR:
				/* take a moment */
				usleep(20000);
				
				/* record end time */
				if (gettimeofday(&now, NULL) == -1) {
					cacti_log("ERROR: Function gettimeofday failed.  Exiting cactid\n");
					exit_cactid();
				}

				end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

				/* re-establish new timeout value */
				timeout.tv_sec = rint(floor(set.script_timeout-(end_time-begin_time)));
				timeout.tv_usec = rint((set.script_timeout-(end_time-begin_time)-timeout.tv_sec)*1000000);
				
				if ((end_time - begin_time) < set.script_timeout) {
					goto retry;
				}else{
					snprintf(logmessage, LOGSIZE-1, "WARNING: SS[%i] The Script Server script timed out while processing EINTR's.\n", php_process);
				}
				break;
			case EINVAL:
				snprintf(logmessage, LOGSIZE-1, "ERROR: SS[%i] N is negative or the value contained within timeout is invalid.\n", php_process);
				break;
			case ENOMEM:
				snprintf(logmessage, LOGSIZE-1, "ERROR: SS[%i] Select was unable to allocate memory for internal tables.\n", php_process );
				break;
			default:
				snprintf(logmessage, LOGSIZE-1, "ERROR: SS[%i] Unknown fatal select() error\n", php_process);
				break;
		}

		cacti_log(logmessage);
		snprintf(result_string, BUFSIZE-1, "U");

		/* kill script server because it is misbehaving */
		php_close(php_process);
		php_init(php_process);
		break;
	case 0:
		snprintf(logmessage, LOGSIZE-1, "WARNING: SS[%i] The PHP Script Server did not respond in time and will therefore be restarted\n", php_process);
		cacti_log(logmessage);
		snprintf(result_string, BUFSIZE-1, "U");

		/* kill script server because it is misbehaving */
		php_close(php_process);
		php_init(php_process);
		break;
	default:
		rescode = read(php_processes[php_process].php_read_fd, result_string, BUFSIZE);
		if (rescode == 0) {
			snprintf(result_string, BUFSIZE-1, "U");
		}

		php_processes[php_process].php_state = PHP_READY;
	}

	return result_string;
}

/******************************************************************************/
/*  php_init() - initialize the PHP script server process or processes        */
/******************************************************************************/
int php_init(int php_process) {
	int  cacti2php_pdes[2];
	int  php2cacti_pdes[2];
	pid_t  pid;
	char logmessage[LOGSIZE];
	char poller_id[11];
	char *argv[5];
	int  cancel_state;
	char *result_string;
	int num_processes;
	int i;

	/* special code to start all PHP Servers */
	if (php_process == PHP_INIT) {
		num_processes = set.php_servers;
	}else{
		num_processes = 1;
	}
	
	for (i=0; i < num_processes; i++) {
		if (set.verbose == POLLER_VERBOSITY_DEBUG) {
			snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] PHP Script Server Routine Starting\n", i);
			cacti_log(logmessage);
		}

		/* create the output pipes from cactid to php*/
		if (pipe(cacti2php_pdes) < 0) {
			snprintf(logmessage, sizeof(logmessage)-1, "ERROR: SS[%i] Could not allocate php server pipes\n", i);
			cacti_log(logmessage);
			return FALSE;
		}

		/* create the input pipes from php to cactid */
		if (pipe(php2cacti_pdes) < 0) {
			snprintf(logmessage, sizeof(logmessage)-1, "ERROR: SS[%i] Could not allocate php server pipes\n", i);
			cacti_log(logmessage);
			return FALSE;
		}

		/* disable thread cancellation from this point forward. */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

		/* establish arguments for script server execution */
		argv[0] = set.path_php;
		argv[1] = set.path_php_server;
		argv[2] = "cactid";
		snprintf(poller_id, sizeof(poller_id)-1, "%d", set.poller_id);
		argv[3] = poller_id;
		argv[4] = NULL;

		/* fork a child process */
		if (set.verbose == POLLER_VERBOSITY_DEBUG) {
			snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] PHP Script Server About to FORK Child Process\n", i);
			cacti_log(logmessage);
		}

		pid = fork();

		/* check the pid status and process as required */
		switch (pid) {
			case -1: /* ERROR: Could not fork() */
				close(php2cacti_pdes[0]);
				close(php2cacti_pdes[1]);
				close(cacti2php_pdes[0]);
				close(cacti2php_pdes[1]);

				snprintf(logmessage, sizeof(logmessage)-1, "ERROR: SS[%i] Cound not fork PHP Script Server\n", i);
				cacti_log(logmessage);
				pthread_setcancelstate(cancel_state, NULL);

				return FALSE;
				/* NOTREACHED */
			case 0:	/* SUCCESS: I am now the child */
				/* set the standard input/output channels of the new process.  */
				dup2(cacti2php_pdes[0], STDIN_FILENO);
				dup2(php2cacti_pdes[1], STDOUT_FILENO);

				/* close unneeded Pipes */
				(void)close(php2cacti_pdes[0]);
				(void)close(php2cacti_pdes[1]);
				(void)close(cacti2php_pdes[0]);
				(void)close(cacti2php_pdes[1]);

				/* start the php script server process */
				execve(argv[0], argv, environ);
				_exit(127);
				/* NOTREACHED */
			default: /* I am the parent process */
				if (set.verbose >= POLLER_VERBOSITY_DEBUG) {
					snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] PHP Script Server Child FORK Success\n", i);
					cacti_log(logmessage);
				}
		}

		/* Parent */
		/* close unneeded pipes */
		close(cacti2php_pdes[0]);
		close(php2cacti_pdes[1]);

		if (php_process == PHP_INIT) {
			php_processes[i].php_pid = pid;
			php_processes[i].php_write_fd = cacti2php_pdes[1];
			php_processes[i].php_read_fd = php2cacti_pdes[0];
		}else{
			php_processes[php_process].php_pid = pid;
			php_processes[php_process].php_write_fd = cacti2php_pdes[1];
			php_processes[php_process].php_read_fd = php2cacti_pdes[0];
		}

		/* restore caller's cancellation state. */
		pthread_setcancelstate(cancel_state, NULL);

		/* check pipe to insure startup took place */
		if (php_process == PHP_INIT) {
			result_string = php_readpipe(i);
		}else{
			result_string = php_readpipe(php_process);
		}

		if (strstr(result_string, "Started")) {
			if (php_process == PHP_INIT) {
				if (set.verbose >= POLLER_VERBOSITY_DEBUG) {
					snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] Confirmed PHP Script Server running\n", i);
					cacti_log(logmessage);
				}

				php_processes[i].php_state = PHP_READY;
			}else{
				if (set.verbose >= POLLER_VERBOSITY_DEBUG) {
					snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] Confirmed PHP Script Server running\n", php_process);
					cacti_log(logmessage);
				}

				php_processes[php_process].php_state = PHP_READY;
			}
		}else{
			snprintf(logmessage, sizeof(logmessage)-1, "ERROR: SS[%i] Script Server did not start properly return message was: '%s'\n", php_process, result_string);
			cacti_log(logmessage);

			if (php_process == PHP_INIT) {
				php_processes[i].php_state = PHP_BUSY;
			}else{
				php_processes[php_process].php_state = PHP_BUSY;
			}
		}
	}

	free(result_string);
}

/******************************************************************************/
/*  php_close - close the pipes and wait for the status of the child.         */
/******************************************************************************/
void php_close(int php_process) {
	char logmessage[LOGSIZE];
	int i;
	int num_processes;

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, sizeof(logmessage)-1, "DEBUG: SS[%i] Script Server Shutdown Started\n", php_process);
		cacti_log(logmessage);
	}

	if (php_process == PHP_INIT) {
		num_processes = set.php_servers;
	}else{
		num_processes = 1;
	}
	
	for(i = 0; i < num_processes; i++) {
		/* tell the script server to close */
		if (php_process == PHP_INIT) {
			write(php_processes[i].php_write_fd, "quit\r\n", sizeof("quit\r\n"));

			/* wait before killing php */
			usleep(200000);

			/* end the php script server process */
			kill(php_processes[i].php_pid, SIGTERM);

			/* close file descriptors */
			close(php_processes[i].php_write_fd);
			close(php_processes[i].php_read_fd);
		}else{
			write(php_processes[php_process].php_write_fd, "quit\r\n", sizeof("quit\r\n"));

			/* wait before killing php */
			usleep(200000);

			/* end the php script server process */
			kill(php_processes[php_process].php_pid, SIGTERM);

			/* close file descriptors */
			close(php_processes[php_process].php_write_fd);
			close(php_processes[php_process].php_read_fd);
		}			
	}
}
