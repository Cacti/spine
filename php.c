/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Larry Adams & Ian Berry                              |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
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
#include "php.h"
#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "util.h"

extern char **environ;

/******************************************************************************/
/*  php_cmd() - send a command to the script server                           */
/******************************************************************************/
char *php_cmd(char *php_command) {
	char *result_string;
	char *spaceloc;
	char command[BUFSIZE+5];

	/* pad command with CR-LF */
	snprintf(command, sizeof(command), php_command, strlen(php_command));
	strncat(command, "\r\n", 5);

	thread_mutex_lock(LOCK_PHP);
	/* send command to the script server */
	write(php_pipes.php_write_fd, command, strlen(command));

	/* read the result from the php_command */
	result_string = php_readpipe();

	/* clean garbage from string.  don't know why it's there... */
	spaceloc = strchr(result_string, ' ');
	if (spaceloc != 0) {
		*spaceloc = '\0';
		spaceloc = strchr(result_string, ' ');
		if (spaceloc != 0)
			*spaceloc = '\0';
	}
	thread_mutex_unlock(LOCK_PHP);

	return result_string;
}

/******************************************************************************/
/*  php_readpipe - read a line from the PHP script server                     */
/******************************************************************************/
char *php_readpipe() {
	char *pipe_read = (char *) malloc(BUFSIZE);
	char *result_string = (char *) malloc(BUFSIZE);
	fd_set fds;
	int rescode, numfds;
	struct timeval timeout;
	char logmessage[LOGSIZE];

	/* initialize file descriptors to review for input/output */
	FD_ZERO(&fds);
	FD_SET(php_pipes.php_read_fd,&fds);
	FD_SET(php_pipes.php_write_fd,&fds);

	if (php_pipes.php_read_fd > php_pipes.php_write_fd)
		numfds = php_pipes.php_read_fd + 1;
	else
		numfds = php_pipes.php_write_fd + 1;

	/* establish timeout of 5 seconds to have PHP script server respond */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;

	/* check to see which pipe talked and take action
	 * should only be the READ pipe */
	switch (select(numfds, &fds, NULL, NULL, &timeout)) {
	case -1:
		snprintf(logmessage, LOGSIZE, "ERROR: Fatal select() error\n");
		cacti_log(logmessage);
		snprintf(result_string, 2, "%s", "U");
		break;
	case 0:
		snprintf(logmessage, LOGSIZE, "ERROR: The PHP Script Server Did not Respond in Time\n");
		cacti_log(logmessage);
		snprintf(result_string, 2, "%s", "U");
		break;
	default:
		rescode = read(php_pipes.php_read_fd, pipe_read, BUFSIZE);
		if (rescode > 0)
			snprintf(result_string, rescode, "%s", pipe_read);
		else
			snprintf(result_string, 2, "%s", "U");
		break;
	}

	free(pipe_read);

	return result_string;
}

/******************************************************************************/
/*  php_init() - initialize the PHP script server                             */
/******************************************************************************/
int php_init() {
	int  cacti2php_pdes[2];
	int  php2cacti_pdes[2];
	int  pid;
	char logmessage[LOGSIZE];
	char poller_id[11];
	char *argv[5];
	int  cancel_state;
	char *result_string;

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: PHP Script Server Routine Started\n");
		cacti_log(logmessage);
	}

	/* create the output pipes from cactid to php*/
	if (pipe(cacti2php_pdes) < 0) {
		snprintf(logmessage, LOGSIZE, "ERROR: Could not allocate php server pipes\n");
		cacti_log(logmessage);
		return -1;
	}

	/* create the input pipes from php to cactid */
	if (pipe(php2cacti_pdes) < 0) {
		snprintf(logmessage, LOGSIZE, "ERROR: Could not allocate php server pipes\n");
		cacti_log(logmessage);
		return -1;
	}

	/* disable thread cancellation from this point forward. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	/* establish arguments for script server execution */
	argv[0] = set.path_php;
	argv[1] = set.path_php_server;
	argv[2] = "cactid";
	snprintf(poller_id, sizeof(int), "%d", set.poller_id);
	argv[3] = poller_id;
	argv[4] = NULL;

	/* fork a child process */
	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: PHP Script Server About to FORK Child Process\n");
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

			snprintf(logmessage, LOGSIZE, "ERROR: Could not fork php script server\n");
			cacti_log(logmessage);
			pthread_setcancelstate(cancel_state, NULL);

			return -1;
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
				snprintf(logmessage, LOGSIZE, "DEBUG: PHP Script Server Child FORK Success\n");
				cacti_log(logmessage);
			}
	}

	/* Parent */
	/* close unneeded pipes */
	close(cacti2php_pdes[0]);
	close(php2cacti_pdes[1]);

	php_pipes.php_write_fd = cacti2php_pdes[1];
	php_pipes.php_read_fd = php2cacti_pdes[0];

	/* restore caller's cancellation state. */
	pthread_setcancelstate(cancel_state, NULL);

	/* check pipe to insure startup took place */
	result_string = php_readpipe();

	if ((set.verbose >= POLLER_VERBOSITY_DEBUG) && (strstr(result_string, "Started"))) {
		snprintf(logmessage, LOGSIZE, "DEBUG: Confirmed PHP Script Server Running\n");
		cacti_log(logmessage);
	}

	free(result_string);

	return 1;
}

/******************************************************************************/
/*  php_close - close the pipes and wait for the status of the child.         */
/******************************************************************************/
void php_close() {
	char logmessage[LOGSIZE];

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: PHP Script Server Shutdown Started\n");
		cacti_log(logmessage);
	}

	/* tell the script server to close */
	write(php_pipes.php_write_fd, "quit\r\n", sizeof("quit\r\n"));

	/* close file descriptors */
	close(php_pipes.php_write_fd);
	close(php_pipes.php_read_fd);
}
