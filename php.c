/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
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
/*  php_cmd() - Send a command to the Script Server                           */
/******************************************************************************/
char *php_cmd(char *php_command) {
	char *result_string;
	char *spaceloc;
	char command[BUFSIZE+5];

	/* pad command with CR-LF */
	sprintf(command,php_command,strlen(php_command));
	strcat(command,"\r\n");

	thread_mutex_lock(LOCK_PHP);
	/* send command to the script server */
 	write(php_pipes.php_write_fd, command, strlen(command));

	/* read the result from the php_command */
	result_string = php_readpipe();

	/* Clean garbage from string.  Don't know why it's there... */
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
/*  php_readpipe - Read a line from the PHP Script Server                     */
/******************************************************************************/
char *php_readpipe() {
	char *result_string = (char *) malloc(BUFSIZE);
	char result[BUFSIZE] = "";
	fd_set fds;
	int rescode, numfds;
	struct timeval timeout;

	/* Initialize File Descriptors to Review for Input/Output */
	FD_ZERO(&fds);
	FD_SET(php_pipes.php_read_fd,&fds);
	FD_SET(php_pipes.php_write_fd,&fds);

	if (php_pipes.php_read_fd > php_pipes.php_write_fd)
		numfds = php_pipes.php_read_fd + 1;
	else
		numfds = php_pipes.php_write_fd + 1;

	/* Establish Timeout of 1 Second to Have PHP Script Server Respond */
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;

	/* Wait for A Response on The Pipes */
	select(numfds, &fds, NULL, NULL, &timeout);

	/* Check to See Which Pipe Talked and Take Action */
	/* Should only be the READ Pipe */
	if (FD_ISSET(php_pipes.php_read_fd, &fds)) {
		rescode = read(php_pipes.php_read_fd, result_string, BUFSIZE);
  		if (rescode > 0)
	    	snprintf(result_string, rescode, "%s", result_string);
		else
			snprintf(result_string, 2, "%s", "U");
	} else {
		cacti_log("ERROR: The PHP Script Server Did not Respond in Time\n","e");
		snprintf(result_string, 2, "%s", "U");
	}

	return result_string;
}

/******************************************************************************/
/*  php_init() - Initialize the PHP Script Server                             */
/******************************************************************************/
int php_init() {
	int  cacti2php_pdes[2];
	int  php2cacti_pdes[2];
	char logmessage[255];
	int  i = 0;
    int  pid;
	char *argv[4];
	int  check;
    int  cancel_state;
	char *result_string;

	if (set.verbose >= DEBUG) {
		printf("CACTID: PHP Script Server Routine Started.\n");
	}

	/* create the output pipes from cactid to php*/
    if (pipe(cacti2php_pdes) < 0) {
		cacti_log("ERROR: Could not allocate php server pipes\n", "e");
		return -1;
	}

	/* create the input pipes from php to cactid */
    if (pipe(php2cacti_pdes) < 0) {
		cacti_log("ERROR: Could not allocate php server pipes\n", "e");
		return -1;
	}

    /* Disable thread cancellation from this point forward. */
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

	/* establish arguments for script server execution */
	argv[0] = set.phppath;
	argv[1] = set.path_php_server;
	argv[2] = "cactid";
	argv[3] = NULL;

    /* fork a child process */
	if (set.verbose >= DEBUG) {
		printf("CACTID: PHP Script Server About to FORK Child Process.\n");
	}

	pid = fork();

	/* check the pid status and process as required */
    switch (pid) {
	    case -1: /* ERROR: Could not fork() */
			if (set.verbose >= DEBUG) {
				printf("CACTID: PHP Script Server Child FORK Failed.\n");
			}
			close(php2cacti_pdes[0]);
			close(php2cacti_pdes[1]);
			close(cacti2php_pdes[0]);
			close(cacti2php_pdes[1]);

			cacti_log("ERROR: Could not fork php script server\n","e");
			pthread_setcancelstate(cancel_state, NULL);

			return -1;
			/* NOTREACHED */
	    case 0:	/* SUCCESS: I am now the child */
			/* Set the standard input/output channels of the new process.  */
			dup2(cacti2php_pdes[0], STDIN_FILENO);
			dup2(php2cacti_pdes[1], STDOUT_FILENO);

			/* Close Unneeded Pipes */
			(void)close(php2cacti_pdes[0]);
			(void)close(php2cacti_pdes[1]);
			(void)close(cacti2php_pdes[0]);
			(void)close(cacti2php_pdes[1]);

			/* start the php script server process */
			execve(argv[0], argv, environ);
			_exit(127);
			/* NOTREACHED */
		default: /* I am the parent process */
			if (set.verbose >= DEBUG) {
				printf("CACTID: PHP Script Server Child FORK Success.\n");
			}
	}

    /* Parent */
	/* Close Unneeded Pipes */
	close(cacti2php_pdes[0]);
	close(php2cacti_pdes[1]);

	php_pipes.php_write_fd = cacti2php_pdes[1];
	php_pipes.php_read_fd = php2cacti_pdes[0];

    /* Restore caller's cancellation state. */
	pthread_setcancelstate(cancel_state, NULL);

	/* Check pipe to insure startup took place */
	result_string = php_readpipe();
	free(result_string);

	if ((set.verbose == DEBUG) && (strstr(result_string, "Started")))
		cacti_log("CACTID: Confirmed PHP Script Server Running\n","e");

    return 1;
}

/******************************************************************************/
/*  php_close - Close the pipes and wait for the status of the child.         */
/******************************************************************************/
int php_close() {
	int i;
	char command[255];
	char logmessage[255];
	fd_set fds;
	int numfds;

	if (set.verbose >= DEBUG) {
		cacti_log("CACTID: PHP Script Server Shutdown Started.\n","e");
	}

	/* tell the script server to close */
	write(php_pipes.php_write_fd, "quit\r\n", sizeof("quit\r\n"));

	/* close file descriptors */
    close(php_pipes.php_write_fd);
    close(php_pipes.php_read_fd);
}
