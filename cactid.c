/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2003 Ian Berry                                            |
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

#include <errno.h>
#include "common.h"
#include "cactid.h"
#include "poller.h"
#include "locks.h"
#include "sql.h"
#include "util.h"

/* Yes.  Globals. */
char rrdtool_path[128];

int entries = 0;
int num_hosts = 0;
int active_threads = 0;

int main(int argc, char *argv[]) {
	extern char rrdtool_path[128];
	
	struct timeval now;
	double begin_time, end_time;
	char *conf_file = NULL;
	char filename[BUFSIZE];
	
	int num_rows;
	int device_counter = 0;
	int last_active_threads = 0;
	long int THREAD_SLEEP = 10000;
	pthread_t* threads = NULL;
	int* ids = NULL;
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int canexit = 0;
	int host_id;
	
	set.verbose = LOW;
	
	if (set.verbose >= LOW) {
		printf("cactid version %s starting.", VERSION);
	}
	
	/* Read configuration file to establish local environment */
	config_defaults(&set);
	
	if (conf_file == NULL) {
		conf_file = malloc(sizeof(filename));
		strcpy(conf_file, CONFIG1);
	}
	
	if ((init_config(conf_file, &set)) < 0) {
		fprintf(stderr, "Couldn't write config file.\n");
		exit(-1);
	}
	
	db_connect(set.dbdb, &mysql);
	
	/* get the rrdtool path from the cacti settings table */
	sprintf(rrdtool_path, "%s", get_rrdtool_path(&mysql));
	
	/* initilize the rrdtool pipe */
	rrd_open();
	
	snmp_init();
	
	if (set.verbose >= LOW) {
		printf("Cactid Ready.\n");
	}
	
	result = db_query(&mysql, "SELECT id FROM host WHERE disabled='' ORDER BY id");

	num_rows = mysql_num_rows(result);
	threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t));
	ids = (int *)malloc(num_rows * sizeof(int));
	
	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	
	while (device_counter < num_rows) {
		if (mutex_trylock(LOCK_THREAD) != EBUSY) {
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}
			
			while ((active_threads < set.threads) && (device_counter < num_rows)) {
				mysql_row = mysql_fetch_row(result);
				host_id = atoi(mysql_row[0]);
				ids[device_counter] = host_id;
				pthread_create(&threads[device_counter], NULL, child, &ids[device_counter]);
				pthread_detach(threads[device_counter]);
				device_counter++;
				active_threads++;
			}
			
			mutex_unlock(LOCK_THREAD);
		}
		
		usleep(THREAD_SLEEP);
	}

	while (canexit == 0) {
		if (mutex_trylock(LOCK_THREAD) != EBUSY) {
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}
			
			if (active_threads == 0) {
				canexit = 1;
			}
			
			mutex_unlock(LOCK_THREAD);
		}
		
		usleep(THREAD_SLEEP);
	}
	
	/* print out stats and sleep */
	gettimeofday(&now, NULL);
	
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	
	if (set.verbose >= LOW) {
		printf("\n----- Poll complete. (Polling Time: %fs) -----\n\n", (end_time - begin_time));
	}
	
	rrd_close();
	snmp_free();
	
	free(threads);
	free(ids);
	free(conf_file);
	
	mysql_free_result(result);
	mysql_close(&mysql);
	
	exit(1);
}
