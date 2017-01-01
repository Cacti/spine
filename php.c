/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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

#include "common.h"
#include "spine.h"

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

	/* pad command with CR-LF */
	snprintf(command, BUFSIZE, "%s\r\n", php_command);

	/* place lock around mutex */
	switch (php_process) {
	case 0: thread_mutex_lock(LOCK_PHP_PROC_0);	break;
	case 1: thread_mutex_lock(LOCK_PHP_PROC_1);	break;
	case 2: thread_mutex_lock(LOCK_PHP_PROC_2);	break;
	case 3: thread_mutex_lock(LOCK_PHP_PROC_3);	break;
	case 4: thread_mutex_lock(LOCK_PHP_PROC_4);	break;
	case 5: thread_mutex_lock(LOCK_PHP_PROC_5);	break;
	case 6: thread_mutex_lock(LOCK_PHP_PROC_6);	break;
	case 7: thread_mutex_lock(LOCK_PHP_PROC_7);	break;
	case 8: thread_mutex_lock(LOCK_PHP_PROC_8);	break;
	case 9: thread_mutex_lock(LOCK_PHP_PROC_9);	break;
	}

	/* send command to the script server */
	retry:
	bytes = write(php_processes[php_process].php_write_fd, command, strlen(command));

	/* if write status is <= 0 then the script server may be hung */
	if (bytes <= 0) {
		result_string = strdup("U");
		SPINE_LOG(("ERROR: SS[%i] PHP Script Server communications lost.  Restarting PHP Script Server", php_process));

		php_close(php_process);
		php_init(php_process);
		/* increment and retry a few times on the next item */
		retries++;
		if (retries < 3) {
			goto retry;
		}
	}else{
		/* read the result from the php_command */
		result_string = php_readpipe(php_process);

		/* check for a null */
		if (!strlen(result_string)) {
			SET_UNDEFINED(result_string);
		}
	}

	/* unlock around php process */
	switch (php_process) {
	case 0: thread_mutex_unlock(LOCK_PHP_PROC_0); break;
	case 1: thread_mutex_unlock(LOCK_PHP_PROC_1); break;
	case 2: thread_mutex_unlock(LOCK_PHP_PROC_2); break;
	case 3: thread_mutex_unlock(LOCK_PHP_PROC_3); break;
	case 4: thread_mutex_unlock(LOCK_PHP_PROC_4); break;
	case 5: thread_mutex_unlock(LOCK_PHP_PROC_5); break;
	case 6: thread_mutex_unlock(LOCK_PHP_PROC_6); break;
	case 7: thread_mutex_unlock(LOCK_PHP_PROC_7); break;
	case 8: thread_mutex_unlock(LOCK_PHP_PROC_8); break;
	case 9: thread_mutex_unlock(LOCK_PHP_PROC_9); break;
	}

	return result_string;
}

/*!  \fn in php_get_process()
 *  \brief returns the next php script server process to utilize
 *
 *  This very simple function simply returns the next PHP Script Server
 *  process id to poll using a round robin algorithm.
 *
 *  \return the integer number of the next script server to use
 *
 */
int php_get_process(void) {
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

/*! \fn char *php_readpipe(int php_process)
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
char *php_readpipe(int php_process) {
	fd_set fds;
	struct timeval timeout;
	double begin_time = 0;
	double end_time = 0;
	char *result_string;

	int  i;
	char *cp;
	char *bptr;

	if (!(result_string = (char *)malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: php.c php_readpipe!");
	}
	result_string[0] = '\0';

	/* record start time */
	begin_time = get_time_as_double();

	/* establish timeout value for the PHP script server to respond */
	timeout.tv_sec = set.script_timeout;
	timeout.tv_usec = 0;

	/* check to see which pipe talked and take action
	 * should only be the READ pipe */
	retry:

	/* initialize file descriptors to review for input/output */
	FD_ZERO(&fds);
	FD_SET(php_processes[php_process].php_read_fd,&fds);

	switch (select(php_processes[php_process].php_read_fd+1, &fds, NULL, NULL, &timeout)) {
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
				timeout.tv_sec = rint(floor(set.script_timeout-(end_time-begin_time)));
				timeout.tv_usec = rint((set.script_timeout-(end_time-begin_time)-timeout.tv_sec)*1000000);

				if ((end_time - begin_time) < set.script_timeout) {
					goto retry;
				}else{
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
		php_init(php_process);
		break;
	case 0:
		SPINE_LOG(("WARNING: SS[%i] The PHP Script Server did not respond in time and will therefore be restarted", php_process));
		SET_UNDEFINED(result_string);

		/* kill script server because it is misbehaving */
		php_close(php_process);
		php_init(php_process);
		break;
	default:
		if (FD_ISSET(php_processes[php_process].php_read_fd, &fds)) {
			bptr = result_string;
	
			while (1) {
				i = read(php_processes[php_process].php_read_fd, bptr, RESULTS_BUFFER-(bptr-result_string));
	
				if (i <= 0) {
					SET_UNDEFINED(result_string);
					break;
				}
	
				bptr += i;
				*bptr = '\0';	/* make what we've got into a string */
	
				if ((cp = strstr(result_string,"\n")) != 0) {
					break;
				}
	
				if (bptr >= result_string+BUFSIZE) {
					SPINE_LOG(("ERROR: SS[%i] The Script Server result was longer than the acceptable range", php_process));
					SET_UNDEFINED(result_string);
				}
			}
		}else{
			SPINE_LOG(("ERROR: SS[%i] The FD was not set as expected", php_process));
			SET_UNDEFINED(result_string);
		}

		php_processes[php_process].php_state = PHP_READY;
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
	char poller_id[TINY_BUFSIZE];
	char *argv[6];
	int  cancel_state;
	char *result_string = 0;
	int num_processes;
	int i;
	int retry_count = 0;

	/* special code to start all PHP Servers */
	if (php_process == PHP_INIT) {
		num_processes = set.php_servers;
	}else{
		num_processes = 1;
	}

	for (i=0; i < num_processes; i++) {
		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Routine Starting", i));

		/* create the output pipes from Spine to php*/
		if (pipe(cacti2php_pdes) < 0) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", i));
			return FALSE;
		}

		/* create the input pipes from php to Spine */
		if (pipe(php2cacti_pdes) < 0) {
			SPINE_LOG(("ERROR: SS[%i] Could not allocate php server pipes", i));
			return FALSE;
		}

		/* disable thread cancellation from this point forward. */
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);

		/* establish arguments for script server execution */
		argv[0] = set.path_php;
		argv[1] = "-q";
		argv[2] = set.path_php_server;
		argv[3] = "spine";
		snprintf(poller_id, TINY_BUFSIZE, "%d", set.poller_id);
		argv[4] = poller_id;
		argv[5] = NULL;

		/* fork a child process */
		SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server About to FORK Child Process", i));

		retry:

		pid = vfork();

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
					}else{
						SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Out of Resources", i));
					}
				case ENOMEM:
					if (retry_count < 3) {
						retry_count++;
						#ifndef SOLAR_THREAD
						/* take a moment */
						usleep(50000);
						#endif
						goto retry;
					}else{
						SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Out of Memory", i));
					}
				default:
					SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server Unknown Reason", i));
				}

				close(php2cacti_pdes[0]);
				close(php2cacti_pdes[1]);
				close(cacti2php_pdes[0]);
				close(cacti2php_pdes[1]);

				SPINE_LOG(("ERROR: SS[%i] Could not fork PHP Script Server", i));
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
				execv(argv[0], argv);
				_exit(127);
				/* NOTREACHED */
			default: /* I am the parent process */
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] PHP Script Server Child FORK Success", i));
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
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] Confirmed PHP Script Server running using readfd[%i], writefd[%i]", i, php2cacti_pdes[0], cacti2php_pdes[1]));

				php_processes[i].php_state = PHP_READY;
			}else{
				SPINE_LOG_DEBUG(("DEBUG: SS[%i] Confirmed PHP Script Server running using readfd[%i], writefd[%i]", php_process, php2cacti_pdes[0], cacti2php_pdes[1]));

				php_processes[php_process].php_state = PHP_READY;
			}
		}else{

			if (php_process == PHP_INIT) {
				SPINE_LOG(("ERROR: SS[%i] Script Server did not start properly return message was: '%s'", i, result_string));

				php_processes[i].php_state = PHP_BUSY;
			}else{
				SPINE_LOG(("ERROR: SS[%i] Script Server did not start properly return message was: '%s'", php_process, result_string));

				php_processes[php_process].php_state = PHP_BUSY;
			}
		}
	}

	free(result_string);

	return TRUE;
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
void php_close(int php_process) {
	int i;
	int num_processes;
	ssize_t bytes;

	if (php_process == PHP_INIT) {
		num_processes = set.php_servers;
	}else{
		num_processes = 1;
	}

	for(i = 0; i < num_processes; i++) {
		php_t *phpp;

		SPINE_LOG_DEBUG(("DEBUG: SS[%i] Script Server Shutdown Started", i));

		/* tell the script server to close */
		if (php_process == PHP_INIT) {
			phpp = &php_processes[i];
		}else{
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

			bytes = write(phpp->php_write_fd, quit, strlen(quit));

			close(phpp->php_write_fd);
			phpp->php_write_fd = -1;

			/* wait before killing php */
			#ifndef SOLAR_THREAD
			usleep(50000);			/* 50 msec */
			#endif
		}

		/* only try to kill the process if the PID looks valid.
		 * Trying to kill a negative number is bad news (it's
	 	 * a process group leader), and PID 1 is "init".
	  	 */
		if (phpp->php_pid > 1) {
			/* end the php script server process */
			kill(phpp->php_pid, SIGTERM);

			/* reset this PID variable? */
		}

		/* close file descriptors */
		close(phpp->php_read_fd);
		phpp->php_read_fd  = -1;
	}
}
