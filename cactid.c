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
	double begin_time, end_time;
	char *conf_file = NULL;

	int num_rows;
	int device_counter = 0;
	int last_active_threads = 0;
	long int THREAD_SLEEP = 100000;

	pthread_t* threads = NULL;
	pthread_attr_t attr;
	pthread_mutexattr_t mutexattr;

	int* ids = NULL;
	MYSQL mysql;
	MYSQL_RES *result = NULL;
	MYSQL_ROW mysql_row;
	int canexit = 0;
	int host_id;
	int i;
	int mutex_status = 0;
	int thread_status = 0;
	char result_string[BUFSIZE] = "";
	char logmessage[LOGSIZE];

	/* set start time for cacti */
	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	set.verbose = POLLER_VERBOSITY_HIGH;

	/* get static defaults for system */
	config_defaults(&set);

	/* scan arguments for errors */
	if ((argc != 1) && (argc != 3)) {
		printf("ERROR: Cactid requires either 0 or 2 input parameters\n");
		printf("USAGE: <cactidpath>/cactid [start_id end_id]\n");
		exit(-1);
	}

	/* return error if the first arg is greater than the second */
	if (argc == 3) {
		if (atol(argv[1]) > atol(argv[2])) {
			printf("ERROR: Invalid row specifications.  First row must be less than the second row\n");
			exit(-2);
		}
	}

	/* read configuration file to establish local environment */
	if (conf_file) {
		if ((read_cactid_config(conf_file, &set)) < 0) {
			printf("ERROR: Could not read config file: %s\n", conf_file);
			exit(-3);
		}
	}else{
		conf_file = malloc(BUFSIZE);

		if (!conf_file) {
			printf("ERROR: Fatal malloc error!\n");
			exit(-1);
		}

		for(i=0;i<CONFIG_PATHS;i++) {
			snprintf(conf_file, BUFSIZE, "%s%s", config_paths[i], DEFAULT_CONF_FILE);

			if (read_cactid_config(conf_file, &set) >= 0) {
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, BUFSIZE, "%s%s", config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	/* read settings table from the database to further establish environment */
	read_config_options(&set);

	/* set the poller ID, stub for next version */
	set.poller_id = 0;

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log(logmessage);
	} else {
		printf("CACTID: Version %s starting\n", VERSION);
	}

	/* connect to database */
	db_connect(set.dbdb, &mysql);

	/* initialize PHP */
	php_init();

	/* get the id's to poll */
	switch (argc) {
		case 1:
			result = db_query(&mysql, "SELECT id FROM host WHERE disabled='' ORDER BY id");

			break;
		case 3:
			snprintf(result_string, sizeof(result_string), "SELECT id FROM host WHERE (disabled='' and (id >= %s and id <= %s)) ORDER BY id\0", argv[1], argv[2]);
			result = db_query(&mysql, result_string);

			break;
		default:
			break;
	}

	num_rows = mysql_num_rows(result);
	threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t));
	ids = (int *)malloc(num_rows * sizeof(int));

	/* initialize threads and mutexes */
	pthread_attr_init(&attr);

	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	init_mutexes();

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: Initial Value of Active Threads is %i\n", active_threads);
		cacti_log(logmessage);
	}

	/* loop through devices until done */
	while (device_counter < num_rows) {
		mutex_status = thread_mutex_trylock(LOCK_THREAD);

		switch (mutex_status) {
		case 0:
			if (set.verbose == POLLER_VERBOSITY_DEBUG) {
				snprintf(logmessage, LOGSIZE, "DEBUG: Valid Thread to be Created\n");
				cacti_log(logmessage);
			}
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			while ((active_threads < set.threads) && (device_counter < num_rows)) {
				mysql_row = mysql_fetch_row(result);
				host_id = atoi(mysql_row[0]);
				ids[device_counter] = host_id;

				/* create child process */
				thread_status = pthread_create(&threads[device_counter], &attr, child, &ids[device_counter]);

				switch (thread_status) {
					case 0:
						if (set.verbose == POLLER_VERBOSITY_DEBUG) {
							snprintf(logmessage, LOGSIZE, "DEBUG: Valid Thread to be Created\n");
							cacti_log(logmessage);
						}

						device_counter++;
						active_threads++;

						if (set.verbose == POLLER_VERBOSITY_DEBUG) {
							snprintf(logmessage, LOGSIZE, "DEBUG: The Value of Active Threads is %i\n", active_threads);
							cacti_log(logmessage);
						}

						break;
					case EAGAIN:
						snprintf(logmessage, LOGSIZE, "ERROR: The System Lacked the Resources to Create a Thread\n");
						cacti_log(logmessage);
						break;
					case EFAULT:
						snprintf(logmessage, LOGSIZE, "ERROR: The Thread or Attribute Was Invalid\n");
						cacti_log(logmessage);
						break;
					case EINVAL:
						snprintf(logmessage, LOGSIZE, "ERROR: The Thread Attribute is Not Initialized\n");
						cacti_log(logmessage);
						break;
					default:
						snprintf(logmessage, LOGSIZE, "ERROR: Unknown Thread Creation Error\n");
						cacti_log(logmessage);
						break;
				}
				usleep(500);
			}

			thread_mutex_unlock(LOCK_THREAD);

			break;
		case EBUSY:
			snprintf(logmessage, LOGSIZE, "ERROR: Deadlock Occured\n");
			cacti_log(logmessage);
			break;
		case EINVAL:
			snprintf(logmessage, LOGSIZE, "ERROR: Attempt to Unlock an Uninitialized Mutex\n");
			cacti_log(logmessage);
			break;
		case EFAULT:
			snprintf(logmessage, LOGSIZE, "ERROR: Attempt to Unlock an Invalid Mutex\n");
			cacti_log(logmessage);
			break;
		default:
			snprintf(logmessage, LOGSIZE, "ERROR: Unknown Mutex Lock Error Code Returned\n");
			cacti_log(logmessage);
			break;
		}

		usleep(THREAD_SLEEP);
	}

	/* wait for all threads to complete */
	while (canexit == 0) {
		if (thread_mutex_trylock(LOCK_THREAD) != EBUSY) {
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			if (active_threads == 0) {
				canexit = 1;
			}

			thread_mutex_unlock(LOCK_THREAD);
		}

		usleep(THREAD_SLEEP);
	}

	/* print out stats */
	gettimeofday(&now, NULL);

	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");
	db_insert(&mysql, "insert into poller_time (poller_id, start_time, end_time) values (0, NOW(), NOW())");

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);
	pthread_mutexattr_destroy(&mutexattr);

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Thread Cleanup Complete\n");
	}

	/* close the php script server */
	php_close();

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

	/* close mysql */
	mysql_free_result(result);
	mysql_close(&mysql);

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: MYSQL Free & Close Completed\n");
	}

	/* finally add some statistics to the log and exit */
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if ((set.verbose >= POLLER_VERBOSITY_MEDIUM) || (argc == 1)) {
		snprintf(logmessage, LOGSIZE, "Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
		cacti_log(logmessage);
	} else {
		printf("CACTID: Execution Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
	}

	exit(0);
}

