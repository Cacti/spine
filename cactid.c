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
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int canexit = 0;
	int host_id;
	int i;
	int mutex_status = 0;
	int thread_status = 0;
	char result_string[256] = "";
	char logmessage[256];

	set.verbose = HIGH;

	if (set.verbose >= HIGH) {
		printf("CACTID: Version %s starting.\n", VERSION);
	}

	config_defaults(&set);

	/* Initial Argument Error Checking */
	if ((argc != 1) && (argc != 3)) {
		printf("ERROR: Cactid requires either 0 or 2 input parameters.\n");
		printf("USAGE: <cactidpath>/cactid [start_id end_id]\n");
		exit(1);
	}

	/* Return error if the first arg is greater than the second */
	if (argc == 3) {
		if (atol(argv[1]) > atol(argv[2])) {
			printf("ERROR: Invalid row specifications.  First row must be less than the second row.\n");
			exit(2);
		}
	}

	/* read configuration file to establish local environment */
	if (conf_file) {
		if ((read_cactid_config(conf_file, &set)) < 0) {
			printf("ERROR: Could not read config file: %s\n", conf_file);
			exit(-1);
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

	db_connect(set.dbdb, &mysql);

	/* determine log file, syslog or both, default is 1 or log file only */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_destination'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set.log_destination = atoi(mysql_row[0]);
	}else{
		set.log_destination = 1;
	}

	/* determine web_root for script_server operation */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_php_server'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

  		strcpy(set.path_php_server,mysql_row[0]);
	}

	/* set logging option for errors */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_perror'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (!strcmp(mysql_row[0],"on")) {
			set.log_perror = 1;
		}
	}

	/* set logging option for statistics */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_pstats'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (!strcmp(mysql_row[0],"on")) {
			set.log_pstats = 1;
		}
	}

	/* get logging level from database - overrides cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_verbosity'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (atoi(mysql_row[0])) {
			set.verbose = atoi(mysql_row[0]);
		}
	}

	/* get Cacti defined max threads override cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='max_threads'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set.threads = atoi(mysql_row[0]);
	}

	/* get PHP Path Information for Scripting */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_php_binary'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		strcpy(set.path_php,mysql_row[0]);
	}

	/* Set the Poller ID */
	set.poller_id = 0;

	if (set.verbose >= HIGH) {
		sprintf(logmessage,"Ready.\n");
		cacti_log(logmessage);
	}

	/* Initialize SNMP */
	snmp_init();

	/* Initialize PHP */
	php_init();

	/* get the id's to poll */
	switch (argc) {
		case 1:
			result = db_query(&mysql, "SELECT id FROM host WHERE disabled='' ORDER BY id");

			break;
		case 3:
			sprintf(result_string, "SELECT id FROM host WHERE (disabled='' and (id >= %s and id <= %s)) ORDER BY id\0", argv[1], argv[2]);
			result = db_query(&mysql, result_string);

			break;
		default:
			break;
	}

	num_rows = mysql_num_rows(result);
	threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t));
	ids = (int *)malloc(num_rows * sizeof(int));

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if (set.verbose >= DEBUG) {
  		sprintf(logmessage,"DEBUG: Initial Value of Active Threads is ->%i\n",set.poller_id,active_threads);
		cacti_log(logmessage);
	}

	while (device_counter < num_rows) {
		mutex_status = thread_mutex_trylock(LOCK_THREAD);
		switch (mutex_status) {
		case 0:
			if (set.verbose >= DEBUG) {
				sprintf(logmessage,"DEBUG: Valid Thread to be Created.\n");
				cacti_log(logmessage);
			}
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			while ((active_threads < set.threads) && (device_counter < num_rows)) {
				mysql_row = mysql_fetch_row(result);
				host_id = atoi(mysql_row[0]);
				ids[device_counter] = host_id;

				/* create chile process */
				thread_status = pthread_create(&threads[device_counter], &attr, child, &ids[device_counter]);

				switch (thread_status) {
					case 0:
						if (set.verbose >= DEBUG) {
							sprintf(logmessage,"DEBUG: Valid Thread to be Created.\n");
							cacti_log(logmessage);
						}

						device_counter++;
						active_threads++;

						if (set.verbose >= DEBUG) {
							sprintf(logmessage,"DEBUG: The Value of Active Threads is ->%i\n",active_threads);
							cacti_log(logmessage);
						}

						break;
					case EAGAIN:
						sprintf(logmessage,"ERROR: The System Lacked the Resources to Create a Thread.\n");
						cacti_log(logmessage);
						break;
					case EFAULT:
						sprintf(logmessage, "ERROR: The Thread or Attribute Was Invalid.\n");
						cacti_log(logmessage);
						break;
					case EINVAL:
						sprintf(logmessage, "ERROR: The Thread Attribute is Not Initialized.\n");
						cacti_log(logmessage);
						break;
					default:
						sprintf(logmessage, "ERROR: Unknown Thread Creation Error.\n");
						cacti_log(logmessage);
						break;
				}
				usleep(500);
			}

			thread_mutex_unlock(LOCK_THREAD);

			break;
		case EBUSY:
			sprintf(logmessage,"ERROR: Deadlock Occured.\n");
			cacti_log(logmessage);
			break;
		case EINVAL:
			sprintf(logmessage,"ERROR: Attempt to Unlock an Uninitialized Mutex.\n");
			cacti_log(logmessage);
			break;
		case EFAULT:
			sprintf(logmessage,"ERROR: Attempt to Unlock an Invalid Mutex.\n");
			cacti_log(logmessage);
			break;
		default:
			sprintf(logmessage,"ERROR: Unknown Mutex Lock Error Code Returned.\n");
			cacti_log(logmessage);
			break;
		}

		usleep(THREAD_SLEEP);
	}

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

	/* print out stats and sleep */
	gettimeofday(&now, NULL);

	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");
	db_insert(&mysql, "insert into poller_time (poller_id, start_time, end_time) values (0, NOW(), NOW())");

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);
	pthread_mutexattr_destroy(&mutexattr);

	/* cleanup the snmp process*/
	snmp_free();

	/* close the php script server */
	php_close();

	free(threads);
	free(ids);
	free(conf_file);

	mysql_free_result(result);
	mysql_close(&mysql);

	/* finally add some statistics to the log and exit */
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	if (set.verbose == MEDIUM) {
		sprintf(logmessage, "CACTID: Execution Time: %.4f s, Max Threads/Process: %i, Polled Hosts: %i\n",(end_time - begin_time),set.threads,num_rows);
		cacti_log(logmessage);
	}

	exit(0);
}

