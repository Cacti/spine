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
 |    - Rivo Nurges (rrd support, mysql poller cache, misc functions)      |
 |    - RTG (core poller code, pthreads, snmp, autoconf examples)          |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#define _REENTRANT
#include "common.h"
#include "cactid.h"
#include "locks.c"

/* Yes.  Globals. */
char rrdtool_path[128];
target_t *targets = NULL;
target_t *current = NULL;
host_t *hosts = NULL;
MYSQL mysql;
int entries = 0;
int num_hosts = 0;

/* Main rtgpoll */
int main(int argc, char *argv[]) {
	extern char rrdtool_path[128];
	
	crew_t crew;
	struct timeval now;
	double begin_time, end_time;
	char *conf_file = NULL;
	char filename[BUFSIZE];
	int i;
	
	int current_head = 0;
	int rrd_target_counter=0;
	int current_local_data_id=0;
	int rrd_multids_counter=0;
	int rrd_create_pipe_open=0;
	
	multi_rrd_t *rrd_multids;
	rrd_t *rrd_targets;
	target_t *entry = NULL;
	FILE *rrdtool_stdin;
	
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
	
	if (set.verbose >= LOW) {
		printf("Initializing threads (%d).\n", set.threads);
	}
	
	pthread_cond_init(&(crew.done), NULL);
	pthread_cond_init(&(crew.go), NULL);
	crew.work_count = 0;
	
	/* Initialize the SNMP session */
	if (set.verbose >= LOW) {
		printf("Initializing SNMP (v%d).\n", set.snmp_ver);
	}
	
	init_snmp("Cactid");
	
	/* Attempt to connect to the MySQL Database */
	if (db_connect(set.dbdb, &mysql) < 0) {
		fprintf(stderr, "** Database error - check configuration.\n");
		exit(-1);
	}
	
	if (!mysql_ping(&mysql)) {
		if (set.verbose >= LOW) {
			printf("connected.\n");
		}
	}else{
		printf("server not responding.\n");
		exit(-1);
	}
	
	/* Read list of targets to be polled into linked list of target_structs */
	entries = get_targets();
	
	/* get a list of hosts for status information */
	num_hosts = get_host_list();
	
	/* get the rrdtool path from the cacti settings table */
	sprintf(rrdtool_path, "%s", get_rrdtool_path());
	
	if (entries <= 0) {
		fprintf(stderr, "Error updating target list.");
		exit(-1);
	}
	
	if (set.verbose >= HIGH) {
		printf("\nStarting threads.\n");
	}
	
	for (i = 0; i < set.threads; i++) {
		crew.member[i].index = i;
		crew.member[i].crew = &crew;
		
		if (pthread_create(&(crew.member[i].thread), NULL, poller, (void *) &(crew.member[i])) != 0) {
			printf("pthread_create error\n");
		}
	}
	
	/* give threads time to start up */
	sleep(2);
	
	if (set.verbose >= LOW) {
		printf("Cactid Ready.\n");
	}
	
	lock = TRUE;
	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	
	mutex_lock(LOCK_CREW);
	
	current = targets;
	crew.work_count = entries;
	
	mutex_unlock(LOCK_CREW);
	
	if (set.verbose >= LOW) {
		timestamp("Queue ready, broadcasting thread go condition.");
	}
	
	if (pthread_cond_broadcast(&(crew.go)) != 0) {
		printf("pthread_cond error\n");
	}
	
	mutex_lock(LOCK_CREW);
	
	while (crew.work_count > 0) {
		if (set.verbose >= LOW) {
			printf("Work_count: %i\n",crew.work_count);
		}
		
		if (pthread_cond_wait(&(crew.done), get_lock(LOCK_CREW)) != 0) {
			printf("error waiting for crew to finish\n");
		}
	}
	
	mutex_unlock(LOCK_CREW);
	
	/* reserve memory for the polling list */
	rrd_targets = (rrd_t *)malloc(entries * sizeof(rrd_t));
	
	/* put all of the gathered data into RRD's */
	current = targets;
	
	while (current != NULL && current_head==0) {
		entry = current;
		
		if (current->next != NULL) {
			current = current->next;
		}else{
			current = current->head;
			current_head=1;
		}
		
		if(entry->local_data_id == current->local_data_id) {
			//printf("Multi DS RRA\n");
			
			if(entry->local_data_id != current_local_data_id) {
				//printf("New MultiDS: %i\n", entry->local_data_id);
				rrd_multids = (multi_rrd_t *)malloc(entries * sizeof(multi_rrd_t));
				rrd_multids_counter=0;
				sprintf(rrd_multids[rrd_multids_counter].rrd_name, "%s", entry->rrd_name);
				sprintf(rrd_multids[rrd_multids_counter].rrd_path, "%s", entry->rrd_path);
				sprintf(rrd_multids[rrd_multids_counter].result, "%s", entry->result);
				rrd_multids_counter++;
				current_local_data_id = entry->local_data_id;
			} else if(entry->local_data_id == current_local_data_id){
				//printf("Old MultiDS: %i\n", entry->local_data_id);
				sprintf(rrd_multids[rrd_multids_counter].rrd_name, "%s", entry->rrd_name);
				sprintf(rrd_multids[rrd_multids_counter].rrd_path, "%s", entry->rrd_path);
				sprintf(rrd_multids[rrd_multids_counter].result, "%s", entry->result);
				rrd_multids_counter++;
			}
		} else if(entry->local_data_id == current_local_data_id && current->local_data_id != current_local_data_id){
			//printf("Last MultiDS: %i\n", entry->local_data_id);
			sprintf(rrd_multids[rrd_multids_counter].rrd_name, "%s", entry->rrd_name);
			sprintf(rrd_multids[rrd_multids_counter].rrd_path, "%s", entry->rrd_path);
			sprintf(rrd_multids[rrd_multids_counter].result, "%s", entry->result);
			
			sprintf(rrd_targets[rrd_target_counter].rrdcmd, "%s", rrdcmd_multids(rrd_multids,rrd_multids_counter));
			rrd_target_counter++;
			free(rrd_multids);
			current_local_data_id=0;
		} else if(entry->action==2){
			sprintf(rrd_targets[rrd_target_counter].rrdcmd, "%s", rrdcmd_string(entry->rrd_path, entry->result, entry->local_data_id));
			rrd_target_counter++;
		} else {
			//printf("Single DS RRA\n");
			sprintf(rrd_targets[rrd_target_counter].rrdcmd, "%s", rrdcmd_lli(entry->rrd_name, entry->rrd_path, entry->result));
			rrd_target_counter++;
		}
		
		/* do RRD file path check */
		if (!file_exists(entry->rrd_path)) {
			/* open RRD create pipe if not already open */
			if (rrd_create_pipe_open == 0) {
				rrdtool_stdin=popen(rrdtool_path, "w");
				rrd_create_pipe_open = 1;
			}
			
			/* put RRD create command on the pipe */
			fprintf(rrdtool_stdin, "%s\n", create_rrd(entry->local_data_id, entry->rrd_path));
		}
	}
	
	/* close the RRD create pipe if it is open */
	if (rrd_create_pipe_open == 1) {
		pclose(rrdtool_stdin);
	}
	
	/* commit change to the rrd files */
	update_rrd(rrd_targets, rrd_target_counter);
	
	/* free memory from polling list */
	free(rrd_targets);
	
	/* print out stats and sleep */
	gettimeofday(&now, NULL);
	lock = FALSE;
	
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	
	if (set.verbose >= LOW) {
		printf("\n----- Poll complete. (Polling Time: %fs) -----\n\n", (end_time - begin_time));
	}
	
	/* Disconnect from the MySQL Database, exit. */
	db_disconnect(&mysql);
  	pthread_cond_destroy(&(crew.done));
	pthread_cond_destroy(&(crew.go));
	
	exit(1);
}

int get_host_list() {
	extern host_t *hosts;
	
	char query[256];
	int i = 0, num_hosts;
	
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	sprintf(query, "select host_id,count(host_id) as count from data_input_data_cache group by host_id");
	
	if (mysql_query(&mysql, query)) {
		fprintf(stderr, "Error in query\n");
	}
	
	if ((result = mysql_store_result(&mysql)) == NULL) {
		fprintf(stderr, "Error retrieving data\n");
		exit(1);
	}
	
	num_hosts = (int)mysql_num_rows(result);
	
	hosts = (host_t *)malloc(num_hosts * sizeof(host_t));
	
	while ((row = mysql_fetch_row(result))) {
		hosts[i].host_id = atoi(row[0]);
		hosts[i].status = 0;
		i++;
	}
	
	return num_hosts;
}

int get_targets() {
	extern target_t *targets;
	
	char query[256];
	int target_id = 0;
	int num_rows;
	
	target_t *temp;
	target_t *temp2;
	target_t *head;
	
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	sprintf(query, "select action,command,management_ip,snmp_community, \
		snmp_version, snmp_username, snmp_password, rrd_name, rrd_path, \
		arg1, arg2, arg3,local_data_id,host_id from data_input_data_cache order \
		by local_data_id");
	
	if (mysql_query(&mysql, query)) {
		fprintf(stderr, "Error in query\n");
	}
	
	if ((result = mysql_store_result(&mysql)) == NULL) {
		fprintf(stderr, "Error retrieving data\n");
		exit(1);
	}
	
	free(targets);
	targets=NULL;
	
	while ((row = mysql_fetch_row(result))) {
		temp = (target_t *) malloc(sizeof(target_t));
		
		temp->target_id = target_id;
		temp->action = atoi(row[0]);
		sprintf(temp->command, "%s", row[1]);
		sprintf(temp->management_ip, "%s", row[2]);
		sprintf(temp->snmp_community, "%s", row[3]);
		temp->snmp_version = atoi(row[4]);
		sprintf(temp->snmp_username, "%s", row[5]);
		sprintf(temp->snmp_password, "%s", row[6]);
		sprintf(temp->rrd_name, "%s", row[7]);
		sprintf(temp->rrd_path, "%s", row[8]);
		sprintf(temp->arg1, "%s", row[9]);
		sprintf(temp->arg2, "%s", row[10]);
		sprintf(temp->arg3, "%s", row[11]);
		temp->local_data_id = atoi(row[12]);
		temp->host_id = atoi(row[13]);
		
		temp->prev=NULL;
		temp->next=NULL;
		temp->head=NULL;
		
		if(targets == NULL) {
			targets = temp;
			head = temp;
		}else{
			for(temp2 = targets; temp2->next !=NULL; temp2 = temp2->next);
			
			temp->prev = temp2;
			temp->head = head;
			temp2->next = temp;
		}
		target_id++;
	}
	
	temp=NULL;
	free(temp);
	temp2=NULL;
	free(temp2);
	
	num_rows = (int)mysql_num_rows(result);
	
	mysql_free_result(result);
	
	return num_rows;
}
