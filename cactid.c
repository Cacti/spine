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
	int i;
	
	set.verbose = LOW;
	
	if (set.verbose >= LOW) {
		printf("cactid version %s starting.\n", VERSION);
	}
	
	config_defaults(&set);
	
	/* Read configuration file to establish local environment */
	if (conf_file) {
		if ((read_config(conf_file, &set)) < 0) {
		printf("Could not read config file: %s\n", conf_file);
		exit(-1);
		}
	}else{
		conf_file = malloc(BUFSIZE);
		
		if (!conf_file) {
			printf("Fatal malloc error!\n");
			exit(-1);
		}
		
		for(i=0;i<CONFIG_PATHS;i++) {
			snprintf(conf_file, BUFSIZE, "%s%s", config_paths[i], DEFAULT_CONF_FILE); 
			
			if (read_config(conf_file, &set) >= 0) {
				break;
			} 
			
			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, BUFSIZE, "%s%s", config_paths[0], DEFAULT_CONF_FILE); 
			}
		}
	}
	
	db_connect(set.dbdb, &mysql);
	
	/* get the rrdtool path from the cacti settings table */
	snprintf(rrdtool_path, sizeof(rrdtool_path), "%s", get_rrdtool_path(&mysql));
	
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
		if (thread_mutex_trylock(LOCK_THREAD) != EBUSY) {
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
			
			thread_mutex_unlock(LOCK_THREAD);
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
	
	if (set.verbose >= LOW) {
		printf("\n----- Poll complete. (Polling Time: %fs) -----\n\n", (end_time - begin_time));
	}
	
	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");
	
	rrd_close();
	snmp_free();
	
	free(threads);
	free(ids);
	free(conf_file);
	
	mysql_free_result(result);
	mysql_close(&mysql);
	
	exit(1);
}
