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
stats_t stats =
{PTHREAD_MUTEX_INITIALIZER, 0, 0, 0, 0, 0, 0, 0, 0, 0.0};
char *target_file = NULL;
target_t *targets = NULL;
target_t *current = NULL;
MYSQL mysql;
int entries = 0;


/* Main rtgpoll */
int main(int argc, char *argv[]) {
	crew_t crew;
	pthread_t sig_thread;
	sigset_t signal_set;
	struct timeval now;
	double begin_time, end_time, sleep_time;
	char *conf_file = NULL;
	char filename[BUFSIZE];
	char errstr[BUFSIZE];
	int ch, i;
	
	/* Check argument count */
	// if (argc < 3)
	//	usage(argv[0]);
	
	/* Parse the command-line. */
	/* while ((ch = getopt(argc, argv, "c:dht:v")) != EOF)
	switch ((char) ch) {
	case 'c':
		conf_file = optarg;
		break;
	case 'd':
		set.dboff = TRUE;
		break;
	case 'h':
		usage(argv[0]);
		break;
	case 't':
		target_file = optarg;
		break;
	case 'v':
		set.verbose++;
		break;
	}
	*/
	set.verbose = LOW;
	
	if (set.verbose >= LOW) {
		printf("cactid version %s starting.", VERSION);
	}
	
	/* Initialize signal handler */
	sigemptyset(&signal_set);
	sigaddset(&signal_set, SIGHUP);
	sigaddset(&signal_set, SIGUSR1);
	sigaddset(&signal_set, SIGUSR2);
	
	if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0) {
		printf("pthread_sigmask error\n");
	}
	
	/* Read configuration file to establish local environment */
	config_defaults(&set);
	
	if (conf_file == NULL) {
		conf_file = malloc(sizeof(filename));
		strcpy(conf_file, CONFIG1);
	}
	
	if ((read_rtg_config(conf_file, &set)) < 0) {
		fprintf(stderr, "Couldn't write config file.\n");
		exit(-1);
	}
	
	/* Read list of targets to be polled into linked list of target_structs */
	entries = get_targets();
	
	if (entries <= 0) {
		fprintf(stderr, "Error updating target list.");
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
	if (!(set.dboff)) {
		if (rtg_dbconnect(set.dbdb, &mysql) < 0) {
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
	
	if (pthread_create(&sig_thread, NULL, sig_handler, (void *) &(signal_set)) != 0) {
		printf("pthread_create error\n");
	}
	
	/* give threads time to start up */
	sleep(2);
	
	if (set.verbose >= LOW) {
		printf("Cactid Ready.\n");
	}
	
	/* Loop Forever Polling Target List */
	while (1) {
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
			printf("Work_count: %i\n",crew.work_count);
			
			if (pthread_cond_wait(&(crew.done), get_lock(LOCK_CREW)) != 0) {
				printf("error waiting for crew to finish\n");
			}
		}
		
		mutex_unlock(LOCK_CREW);
		
		gettimeofday(&now, NULL);
		lock = FALSE;
		
		end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
		stats.poll_time = end_time - begin_time;
		stats.round++;
		sleep_time = set.interval - stats.poll_time;
		
		if (waiting) {
			if (set.verbose >= HIGH) {
				printf("Processing pending SIGHUP.\n");
			}
			
			entries = get_targets();
			waiting = FALSE;
		}
		
		if (set.verbose >= LOW) {
			printf("\n----- Poll round %d complete. (Polling Time: %fs) -----\n\n", stats.round, stats.poll_time);
			//timestamp(errstr);
			//print_stats(stats);
		}
		
		process_data();
		
		if (sleep_time <= 0) {
			stats.slow++;
		}else{
			sleepy(sleep_time);
		}
	} /* while */
	
	/* Disconnect from the MySQL Database, exit. */
	if (!(set.dboff)) {
		rtg_dbdisconnect(&mysql);
	}
	
  	pthread_cond_destroy(&(crew.done));
	pthread_cond_destroy(&(crew.go));
 	pthread_exit(NULL);
	exit(0);
}


/* Signal Handler.  USR1 increases verbosity, USR2 decreases verbosity. 
   HUP re-reads target list */
void *sig_handler(void *arg) {
	sigset_t *signal_set = (sigset_t *) arg;
	int sig_number;
	
	while (1) {
		sigwait(signal_set, &sig_number);
		if (sig_number == SIGHUP) {
			if (lock) {
				waiting = TRUE;
			}else{
				printf("caught HUP. reloading config.\n");
				entries = get_targets();
				waiting = FALSE;
			}
			
		}else if (sig_number == SIGUSR1) {
			set.verbose++;
		}else if (sig_number == SIGUSR2) {
			set.verbose--;
		}
	}
}

void process_data() {
	int current_head = 0;
	int rrd_target_counter=0;
	int current_local_data_id=0;
	int rrd_multids_counter=0;
	
	rrd_t *rrd_targets = (rrd_t *)malloc(entries * sizeof(rrd_t));
	multi_rrd_t *rrd_multids;
	target_t *entry = NULL;
	
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
				rrd_multids = (rrd_t *)malloc(entries * sizeof(rrd_t));
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
			create_rrd(entry->local_data_id, entry->rrd_path);
		}
	}
		
	update_rrd(rrd_targets, rrd_target_counter);
	free(rrd_targets);
}

void usage(char *prog)
{
    printf("rtgpoll - RTG v%s\n", VERSION);
    printf("Usage: %s [-d] [-vvv] [-c <file>] -t <file>\n", prog);
    printf("\nOptions:\n");
    printf("  -c <file>   Specify configuration file\n");
    printf("  -d          Disable database inserts\n");
    printf("  -t <file>   Specify target file\n");
    printf("  -v          Increase verbosity\n");
    printf("  -h          Help\n");
    exit(-1);
}

int get_targets(){
	extern target_t *targets;
	
	char query[256];
	int target_id = 0;
	
	target_t *temp;
	target_t *temp2;
	target_t *head;
	
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	mysql_init(&mysql);
	
	if (!mysql_real_connect(&mysql, set.dbhost, set.dbuser, set.dbpass, set.dbdb, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(&mysql));
		exit(1);
	}
	
	sprintf(query, "select action,command,management_ip,snmp_community, \
		snmp_version, snmp_username, snmp_password, rrd_name, rrd_path, \
		arg1, arg2, arg3,local_data_id from data_input_data_cache order \
		by local_data_id");
	
	if (mysql_query(&mysql, query)) {
		fprintf(stderr, "Error in query\n");
	}
	
	if ((result = mysql_store_result(&mysql)) == NULL) {
		fprintf(stderr, "Error retrieving data\n");
		exit(1);
	}
	
	mysql_close(&mysql);
	
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
	
	return (int)mysql_num_rows(result);
}
