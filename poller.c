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

#include "common.h"
#include "cactid.h"

#ifdef USE_NET_SNMP
 #include "net-snmp-config.h"
 #include "net-snmp-includes.h"
#else
 #include <ucd-snmp/ucd-snmp-config.h>
 #include <ucd-snmp/ucd-snmp-includes.h>
 #include <ucd-snmp/system.h>
 #include "mib.h"
#endif

extern target_t *current;
extern host_t *hosts;
extern MYSQL mysql;
extern int num_hosts;

void *poller(void *thread_args) {
	/* for actions 1 and 2 */
	FILE *cmd_stdout;
	char cmd_result[255];
	
	worker_t *worker = (worker_t *) thread_args;
	crew_t *crew = worker->crew;
	target_t *entry = NULL;
	
	if (set.verbose >= HIGH){
		printf("Thread [%d] starting.\n", worker->index);
	}
	
	while (1) {
		if (set.verbose >= DEVELOP){
			printf("Thread [%d] locking (wait on work)\n", worker->index);
		}
		
		mutex_lock(LOCK_CREW);
		
		while (current == NULL) {
			if (pthread_cond_wait(&(crew->go), get_lock(LOCK_CREW)) != 0) {
				printf("pthread_wait error\n");
			}
		}
		
		if (set.verbose >= DEVELOP) {
			printf("Thread [%d] done waiting, received go (work cnt: %d)\n", worker->index, crew->work_count);
		}
		
		if (current != NULL) {
			entry = current;
			
			if (current->next != NULL) {
				current = current->next;
			}else{
				current = NULL;
			}
			
			switch(entry->action) {
			case 0:
				mutex_unlock(LOCK_CREW);
				
				if (get_host_status(entry->host_id) == 0) {
					sprintf(entry->result, "%s", snmp_get(entry->management_ip, entry->snmp_community, 1, entry->arg1, entry->host_id, worker->index));
				}else{
					printf("[%i] downed host (%s) detected. ignoring.\n", worker->index, entry->management_ip);
					sprintf(entry->result, "%s", "U");
				}
				
				if (set.verbose >= LOW) {
					printf("[%i] snmp: %s, dsname: %s, oid: %s, value: %s\n", worker->index, entry->management_ip, entry->rrd_name, entry->arg1, entry->result);
				}
				
				break;
			case 1:
				mutex_unlock(LOCK_CREW);
				
				cmd_stdout=popen(entry->command, "r");
				
				if(cmd_stdout != NULL) fgets(cmd_result, 255, cmd_stdout);
				
				if (cmd_result == "") {
					sprintf(entry->result, "%s", "U");
				}else{
					sprintf(entry->result, "%s", cmd_result);
				}
				
				if (set.verbose >= LOW) {
					printf("[%i] command: %s, output: %s\n", worker->index, entry->command, entry->result);
				}
				
				pclose(cmd_stdout);
				break;
			case 2:
				mutex_unlock(LOCK_CREW);
				
				cmd_stdout=popen(entry->command, "r");
				
				if(cmd_stdout != NULL) fgets(cmd_result, 255, cmd_stdout);
				
				sprintf(entry->result, "%s", cmd_result);
				
				if (set.verbose >= LOW) {
					printf("[%i] MUTLI command: %s, output: %s\n", worker->index, entry->command, entry->result);
				}
				
				pclose(cmd_stdout);
				break;
			}
			
			if (set.verbose >= DEVELOP){
				printf("Thread [%d] locking (update work_count)\n", worker->index);
			}
			
			mutex_lock(LOCK_CREW);
			
			crew->work_count--;
			
			if (crew->work_count <= 0) {
				if (set.verbose >= HIGH) {
				    printf("Queue processed. Broadcasting thread done condition.\n");
				}
				
				if (pthread_cond_broadcast(&crew->done) != 0) {
					printf("pthread_cond error\n");
				}
			}
			
			if (set.verbose >= DEVELOP) {
				printf("Thread [%d] unlocking (update work_count)\n", worker->index);
			}
			
			mutex_unlock(LOCK_CREW);
		}
	}
}

char *snmp_get(char *snmp_host, char *snmp_comm, int ver, char *snmp_oid, int host_id, int current_thread) {
	void *sessp = NULL;
	struct snmp_session session;
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	struct variable_list *vars = NULL;
	
	int status;
	
	char query[BUFSIZE];
	char storedoid[BUFSIZE];
	static char result_string[BUFSIZE];
	
	mutex_lock(LOCK_CREW);
	
	snmp_sess_init(&session);
	
	#ifdef USE_NET_SNMP
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	#endif
	
	mutex_unlock(LOCK_CREW);
	
	if (set.snmp_ver == 2) {
		session.version = SNMP_VERSION_2c;
	}else{
		session.version = SNMP_VERSION_1;
	}
	
	session.peername = snmp_host;
	session.community = snmp_comm;
	session.community_len = strlen(snmp_comm);
	
	sessp = snmp_sess_open(&session);
	anOID_len = MAX_OID_LEN;
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	read_objid(snmp_oid, anOID, &anOID_len);
	
	strcpy(storedoid, snmp_oid);
	
	if (set.verbose >= DEVELOP) {
		printf("Thread [%d] unlocking (done grabbing current)\n", current_thread);
	}
	
	snmp_add_null_var(pdu, anOID, anOID_len);
	
	if (sessp != NULL) {
		status = snmp_sess_synch_response(sessp, pdu, &response);
	}else{
		status = STAT_DESCRIP_ERROR;
	}
	
	/* No or Bad SNMP Response */
	if (status == STAT_DESCRIP_ERROR) {
		printf("*** SNMP Error: (%s) Bad descriptor.\n", session.peername);
	}else if (status == STAT_TIMEOUT) {
		printf("*** SNMP No response: (%s@%s).\n", session.peername, storedoid);
		
		mutex_lock(LOCK_CREW);
		set_host_status(host_id, 2);
		mutex_unlock(LOCK_CREW);
	}else if (status != STAT_SUCCESS) {
		printf("*** SNMP Error: (%s@%s) Unsuccessuful (%d).\n", session.peername, storedoid, status);
	}else if (status == STAT_SUCCESS && response->errstat != SNMP_ERR_NOERROR) {
		printf("*** SNMP Error: (%s@%s) %s\n", session.peername, storedoid, snmp_errstring(response->errstat));
	}
	
	/* Liftoff, successful poll, process it */
	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		vars = response->variables;
		
		#ifdef USE_NET_SNMP
		snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
		#else
		sprint_value(result_string, anOID, anOID_len, vars);
		#endif
	}
	
	if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
		sprintf(result_string, "%s", "U");
	}
	
	if (sessp != NULL) {
		snmp_sess_close(sessp);
		
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}
	
	return result_string;
}

int get_host_status(int host_id) {
	int i;
	
	mutex_lock(LOCK_CREW);
	
	for (i=0;i<num_hosts;i++) {
		if (hosts[i].host_id == host_id) {
			mutex_unlock(LOCK_CREW);
			return hosts[i].status;
		}
	}
	
	mutex_unlock(LOCK_CREW);
	
	return 0;
}

void set_host_status(int host_id, int new_status) {
	int i;
	
	for (i=0;i<num_hosts;i++) {
		if (hosts[i].host_id == host_id) {
			hosts[i].status = new_status;
			return;
		}
	}
}
