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
#include "poller.h"
#include "locks.h"
#include "sql.h"
#include "util.h"
#include "nft_popen.h"

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
	pthread_attr_t attr = NULL;
	pthread_mutexattr_t mutexattr = NULL;

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
		if ((read_config(conf_file, &set)) < 0) {
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
		strcpy(set.phppath,mysql_row[0]);
	}

	if (set.verbose >= HIGH) {
		printf("CACTID: Ready.\n");
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
	pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if (set.verbose >= HIGH) {
		printf("Initial Value of Active Threads is ->%i\n",active_threads);
	}

	while (device_counter < num_rows) {
		mutex_status = thread_mutex_trylock(LOCK_THREAD);

		switch (mutex_status) {
		case 0:
			if (set.verbose >= HIGH) {
				printf("THREAD: Valid Thread to be Created.\n");
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

				/* throttle down the parent to give the thread a change to start */
				/* if not, deadlocks have been known to occur */
				/*usleep(200000);*/
				switch (thread_status) {
				case 0:
					if (set.verbose >= HIGH) {
						printf("THREAD: Valid Thread to be Created.\n");
					}

					device_counter++;
					active_threads++;

					if (set.verbose >= HIGH) {
						printf("The Value of Active Threads is ->%i\n",active_threads);
					}

					break;
				case EAGAIN:
					cacti_log("ERROR: The System Lacked the Resources to Create a Thread.\n","e");
					break;
				case EFAULT:
					cacti_log("ERROR: The Thread or Attribute Was Invalid.\n","e");
					break;
				case EINVAL:
					cacti_log("ERROR: The Thread Attribute is Not Initialized.\n","e");
					break;
				default:
					cacti_log("ERROR: Unknown Thread Creation Error.\n","e");
					break;
				}
			}

			thread_mutex_unlock(LOCK_THREAD);

			break;
		case EBUSY:
			cacti_log("ERROR: Deadlock Occured.\n","e");
			break;
		case EINVAL:
			cacti_log("ERROR: Attempt to Unlock an Uninitialized Mutex.\n","e");
			break;
		case EFAULT:
			cacti_log("ERROR: Attempt to Unlock an Invalid Mutex.\n","e");
			break;
		default:
			cacti_log("ERROR: Unknown Mutex Lock Error Code Returned.\n","e");
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

	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if (argc == 1) {
		sprintf(logmessage, "STATS: Execution Time: %.4f s, Method: cactid, Max Processes: 1, Max Threads/Process: %i, Polled Hosts: %i, Hosts/Process: %i\n", (end_time - begin_time), set.threads, num_rows, num_rows);
		cacti_log(logmessage, "s");
	}

	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);
	pthread_mutexattr_destroy(&mutexattr);

	snmp_free();

	php_close();

	free(threads);
	free(ids);
	free(conf_file);

	mysql_free_result(result);
	mysql_close(&mysql);

	exit(0);
}

