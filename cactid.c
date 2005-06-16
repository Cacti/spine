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

#include "common.h"
#include "cactid.h"
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include "poller.h"
#include "locks.h"
#include "snmp.h"
#include "php.h"
#include "sql.h"
#include "util.h"
#include "nft_popen.h"

/* Global Variables */
int entries = 0;
int num_hosts = 0;
int active_threads = 0;

int main(int argc, char *argv[]) {
	struct timeval now;
	char *conf_file = NULL;
	double begin_time, end_time, current_time;
	int poller_interval;
	int num_rows;
	int device_counter = 0;
	int last_active_threads = 0;
	long int EXTERNAL_THREAD_SLEEP = 100000;
	long int internal_thread_sleep;
	time_t nowbin;
	const struct tm *nowstruct;

	pthread_t* threads = NULL;
	pthread_attr_t attr;

	int* ids = NULL;
	MYSQL mysql;
	MYSQL_RES *result = NULL;
	MYSQL_ROW mysql_row;
	int canexit = 0;
	int host_id;
	int i;
	int mutex_status = 0;
	int thread_status = 0;
	pid_t ppid;
	char result_string[BUFSIZE];
	char logmessage[LOGSIZE];

	/* tell cactid that it is parent, set/initialize the process ids, initialize php script server status and set poller id */
	set.parent_fork = CACTID_PARENT;
	set.cactid_pid = getpid();
	set.php_sspid = 0;
	set.poller_id = 0;

	/* set start time for cacti */
	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	/* get time for poller_output table */
	if (time(&nowbin) == (time_t) - 1) {
		printf("ERROR: Could not get time of day from time()\n");
		exit_cactid();
	}

	nowstruct = localtime(&nowbin);

	if (strftime(start_datetime, sizeof(start_datetime), "%Y-%m-%d %H:%M:%S", nowstruct) == (size_t) 0) {
		printf("ERROR: Could not get string from strftime()\n");
		exit_cactid();
	}

	/* set default verbosity */
	set.verbose = POLLER_VERBOSITY_HIGH;

	/* get static defaults for system */
	config_defaults(&set);

	/* scan arguments for errors */
	if ((argc != 1) && (argc != 3)) {
		if (argc == 2) { 
			/* return version */ 
			if ((strcmp(argv[1], "--version") == 0) || 
               (strcmp(argv[1], "--help") == 0) ||
               (strcmp(argv[1], "-h") == 0) ||
               (strcmp(argv[1], "-v") == 0)){ 
				printf("CACTID %s  Copyright 2002-2005 by The Cacti Group\n\n", VERSION); 
				printf("Usage: cactid [start_host_id end_host_id]\n\n");
				printf("If you do not specify [start_host_id end_host_id], Cactid will poll all hosts.\n\n");
				printf("Cactid relies on the cactid.conf file that can exist in multiple locations.\n");
				printf("The first location checked is the current directory.  Optionally, it can be\n");
				printf("placed in the '/etc' directory.\n\n");
				printf("Cactid is distributed under the Terms of the GNU General\n");
				printf("Public License Version 2. (www.gnu.org/copyleft/gpl.html)\n\n");
				printf("For more information, see http://www.cacti.net\n");
				exit_cactid(); 
			} 
		} 

		printf("ERROR: Cactid requires either 0 or 2 input parameters\n");
		printf("USAGE: <cactidpath>/cactid [start_host_id end_host_id]\n");
		exit_cactid();
	}

	/* return error if the first arg is greater than the second */
	if (argc == 3) {
		if (atol(argv[1]) > atol(argv[2])) {
			printf("ERROR: Invalid row specifications.  First row must be less than the second row\n");
			exit_cactid();
		}
	}

	/* read configuration file to establish local environment */
	if (conf_file) {
		if ((read_cactid_config(conf_file, &set)) < 0) {
			printf("ERROR: Could not read config file: %s\n", conf_file);
			exit_cactid();
		}
	}else{
		conf_file = malloc(BUFSIZE);

		if (!conf_file) {
			printf("ERROR: Fatal malloc error!\n");
			exit_cactid();
		}

		for(i=0;i<CONFIG_PATHS;i++) {
			snprintf(conf_file, BUFSIZE-1, "%s%s", config_paths[i], DEFAULT_CONF_FILE);

			if (read_cactid_config(conf_file, &set) >= 0) {
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, BUFSIZE-1, "%s%s", config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	/* get the host_id bounds for polling */
	switch (argc) {
		case 3:
			set.start_host_id = atoi(argv[1]);
			set.end_host_id = atoi(argv[2]);

			break;
		default:
			set.start_host_id = 0;
			set.end_host_id = 0;

			break;
	}

	/* read settings table from the database to further establish environment */
	read_config_options(&set);

	/* find out how many loops we can perform before terminating */
	if (set.poller_interval == 0) {
		poller_interval = 300;
	}else {
		poller_interval = set.poller_interval;
	}

	/* calculate the external_tread_sleep value */
	internal_thread_sleep = EXTERNAL_THREAD_SLEEP * set.num_parent_processes / 2;

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "CACTID: Version %s starting\n", VERSION);
		cacti_log(logmessage);
	} else {
		printf("CACTID: Version %s starting\n", VERSION);
	}

	/* connect to database */
	db_connect(set.dbdb, &mysql);

	/* initialize SNMP */
	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "CACTID: Initializing Net-SNMP API\n", VERSION);
		cacti_log(logmessage);
	}
	snmp_cactid_init();

	/* initialize PHP if required */
	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "CACTID: Initializing PHP Script Server\n", VERSION);
		cacti_log(logmessage);
	}

	/* initialize the script server */
	if (set.php_required) {
		php_init();
	}

	/* log the parent and php script server process id's */
	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "DEBUG: Parent pid=%i, Script Server pid=%i\n", set.cactid_pid, set.php_sspid);
		cacti_log(logmessage);
	}

	/* get the id's to poll */
	switch (argc) {
		case 1:
			result = db_query(&mysql, "SELECT id FROM host WHERE disabled='' ORDER BY id");

			break;
		case 3:
			snprintf(result_string, sizeof(result_string)-1, "SELECT id FROM host WHERE (disabled='' and (id >= %s and id <= %s)) ORDER BY id", argv[1], argv[2]);
			result = db_query(&mysql, result_string);

			break;
		default:
			break;
	}

	num_rows = mysql_num_rows(result) + 1; /* add 1 for host = 0 */
	threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t));
	ids = (int *)malloc(num_rows * sizeof(int));

	/* initialize threads and mutexes */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "DEBUG: Initial Value of Active Threads is %i\n", active_threads);
		cacti_log(logmessage);
	}

	/* tell fork processes that they are now active */
	set.parent_fork = CACTID_FORK;
	
	/* loop through devices until done */
	while ((device_counter < num_rows) && (canexit == 0)) {
		mutex_status = thread_mutex_trylock(LOCK_THREAD);

		switch (mutex_status) {
		case 0:
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			while ((active_threads < set.threads) && (device_counter < num_rows)) {
				if (device_counter > 0) {
					mysql_row = mysql_fetch_row(result);
					host_id = atoi(mysql_row[0]);
					ids[device_counter] = host_id;
				} else {
					ids[device_counter] = 0;
				}

				/* create child process */
				thread_status = pthread_create(&threads[device_counter], &attr, child, &ids[device_counter]);

				switch (thread_status) {
					case 0:
						if (set.verbose == POLLER_VERBOSITY_DEBUG) {
							snprintf(logmessage, LOGSIZE-1, "DEBUG: Valid Thread to be Created\n");
							cacti_log(logmessage);
						}

						device_counter++;
						active_threads++;

						if (set.verbose == POLLER_VERBOSITY_DEBUG) {
							snprintf(logmessage, LOGSIZE-1, "DEBUG: The Value of Active Threads is %i\n", active_threads);
							cacti_log(logmessage);
						}

						break;
					case EAGAIN:
						snprintf(logmessage, LOGSIZE-1, "ERROR: The System Lacked the Resources to Create a Thread\n");
						cacti_log(logmessage);
						break;
					case EFAULT:
						snprintf(logmessage, LOGSIZE-1, "ERROR: The Thread or Attribute Was Invalid\n");
						cacti_log(logmessage);
						break;
					case EINVAL:
						snprintf(logmessage, LOGSIZE-1, "ERROR: The Thread Attribute is Not Initialized\n");
						cacti_log(logmessage);
						break;
					default:
						snprintf(logmessage, LOGSIZE-1, "ERROR: Unknown Thread Creation Error\n");
						cacti_log(logmessage);
						break;
				}
				usleep(internal_thread_sleep);

				/* get current time and exit program if time limit exceeded */
				gettimeofday(&now, NULL);
				current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

				if ((current_time - begin_time) > poller_interval) {
					cacti_log("ERROR: Cactid Timed Out While Processing Hosts Internal\n");
					canexit = 1;
					break;
				}
			}

			thread_mutex_unlock(LOCK_THREAD);

			break;
		case EDEADLK:
			snprintf(logmessage, LOGSIZE-1, "ERROR: Deadlock Occured\n");
			cacti_log(logmessage);
			break;
		case EBUSY:
			break;
		case EINVAL:
			snprintf(logmessage, LOGSIZE-1, "ERROR: Attempt to Unlock an Uninitialized Mutex\n");
			cacti_log(logmessage);
			break;
		case EFAULT:
			snprintf(logmessage, LOGSIZE-1, "ERROR: Attempt to Unlock an Invalid Mutex\n");
			cacti_log(logmessage);
			break;
		default:
			snprintf(logmessage, LOGSIZE-1, "ERROR: Unknown Mutex Lock Error Code Returned\n");
			cacti_log(logmessage);
			break;
		}

		usleep(internal_thread_sleep);

		/* get current time and exit program if time limit exceeded */
		gettimeofday(&now, NULL);
		current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

		if ((current_time - begin_time) > poller_interval) {
			cacti_log("ERROR: Cactid Timed Out While Processing Hosts External\n");
			canexit = 1;
			break;
		}
	}

	/* wait for all threads to complete */
	while (canexit == 0) {
		if (thread_mutex_trylock(LOCK_THREAD) == 0) {
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			if (active_threads == 0) {
				canexit = 1;
			}

			thread_mutex_unlock(LOCK_THREAD);
		}

		usleep(EXTERNAL_THREAD_SLEEP);

		/* get current time and exit program if time limit exceeded */
		gettimeofday(&now, NULL);
		current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

		if ((current_time - begin_time) > poller_interval) {
			cacti_log("ERROR: Cactid Timed Out While Processing Host Shutdown\n");
			canexit = 1;
			break;
		}
	}

	/* tell cactid that it is now parent */
	set.parent_fork = CACTID_PARENT;
	
	/* print out stats */
	gettimeofday(&now, NULL);

	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");
	db_insert(&mysql, "insert into poller_time (poller_id, start_time, end_time) values (0, NOW(), NOW())");

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Thread Cleanup Complete\n");
	}

	/* close the php script server */
	if (set.php_required) {
		php_close();
	}

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: PHP Script Server Pipes Closed\n");
	}

	/* free malloc'd variables */
	free(threads);
	free(ids);
	free(conf_file);

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Allocated Variable Memory Freed\n");
	}

	/* shutdown SNMP */
	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE-1, "CACTID: Shutting down Net-SNMP API\n", VERSION);
		cacti_log(logmessage);
	}
	snmp_cactid_close();

	/* close mysql */
	mysql_free_result(result);
	mysql_close(&mysql);

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: MYSQL Free & Close Completed\n");
	}

	/* finally add some statistics to the log and exit */
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if ((set.verbose >= POLLER_VERBOSITY_MEDIUM) && (argc != 1)) {
		snprintf(logmessage, LOGSIZE-1, "Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
		cacti_log(logmessage);
	} else {
		printf("CACTID: Execution Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
	}

	exit(0);
}

