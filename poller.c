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

#ifdef OLD_UCD_SNMP
 #include "asn1.h"
 #include "snmp_api.h"
 #include "snmp_impl.h"
 #include "snmp_client.h"
 #include "mib.h"
 #include "snmp.h"
#else
 #include "net-snmp-config.h"
 #include "net-snmp-includes.h"
#endif

extern target_t *current;
extern stats_t stats;
extern MYSQL mysql;

void *poller(void *thread_args) {
	/* for actions 1 and 2 */
	FILE *cmd_stdout;
	char cmd_result[64];
	
	worker_t *worker = (worker_t *) thread_args;
	crew_t *crew = worker->crew;
	target_t *entry = NULL;
	
	if (set.verbose >= HIGH){
		printf("Thread [%d] starting.\n", worker->index);
	}
	
	//if (MYSQL_VERSION_ID > 40000){
	//	mysql_thread_init();
	//}else{
	//	my_thread_init();
	//}
	
	while (1) {
		if (set.verbose >= DEVELOP){
			printf("Thread [%d] locking (wait on work)\n", worker->index);
		}
		
		if (pthread_mutex_lock(&crew->mutex) != 0){
			printf("pthread_lock error\n");
		}
		
		while (current == NULL) {
			if (pthread_cond_wait(&crew->go, &crew->mutex) != 0) {
				printf("pthread_wait error\n");
			}
		}
		
		if (set.verbose >= DEVELOP) {
			printf("Thread [%d] done waiting, received go (work cnt: %d)\n", worker->index, crew->work_count);
		}
		
		if (current != NULL) {
			if (pthread_mutex_unlock(&crew->mutex) != 0) {
				printf("pthread_unlock error\n");
			}
			
			entry = current;
			
			if (current->next != NULL) {
				current = current->next;
			}else{
				current = NULL;
			}
			
			switch(entry->action) {
			case 0:
				entry->result = snmp_get(entry->management_ip, entry->snmp_community, 1, entry->arg1, worker->index);
				break;
			case 1:
				cmd_stdout=popen(entry->command, "r");
				
				if(cmd_stdout != NULL) fgets(cmd_result, 64, cmd_stdout);
				if(is_number(cmd_result)) entry->result = atoi(cmd_result);
				
				printf("CMD: [%d] %s result: %lli\n", worker->index, entry->command, entry->result);
				
				pclose(cmd_stdout);
				break;
			case 2:
				pthread_mutex_lock(&crew->mutex);
				
				cmd_stdout=popen(entry->command, "r");
				
				if(cmd_stdout != NULL) fgets(cmd_result, 64, cmd_stdout);
				printf("cmd_result: %s\n", cmd_result);
				sprintf(entry->stringresult, "%s", cmd_result);
				entry->result=0;
				
				printf("MULTI CMD: %s result: %lli\n", entry->command, entry->result);
				
				pclose(cmd_stdout);
				pthread_mutex_unlock(&crew->mutex);
				
				break;
			}
			
			if (set.verbose >= DEVELOP){
				printf("Thread [%d] locking (update work_count)\n", worker->index);
			}
			
			if (pthread_mutex_lock(&crew->mutex) != 0){
				printf("pthread_lock error\n");
			}
			
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
			
			if (pthread_mutex_unlock(&crew->mutex) != 0) {
				printf("pthread_unlock error\n");
			}
		}
	}
}


unsigned long long int snmp_get(char *snmp_host, char *snmp_comm, int ver, char *snmp_oid, int current_thread) {
	void *sessp = NULL;
	struct snmp_session session;
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	struct variable_list *vars = NULL;
	
	unsigned long long result = 0;
	unsigned long long last_value = 0;
	unsigned long long insert_val = 0;
	
	int status, bits, init = 0;
	char query[BUFSIZE];
	char storedoid[BUFSIZE];
	char result_string[BUFSIZE];
	
	snmp_sess_init(&session);
	
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
	
	last_value = 0; /*OOOOO*/
	init = 1; /*OOOOO*/
	insert_val = 0;
	bits = 32; /*OOOOO*/
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
	}else if (status != STAT_SUCCESS) {
		printf("*** SNMP Error: (%s@%s) Unsuccessuful (%d).\n", session.peername, storedoid, status);
	}else if (status == STAT_SUCCESS && response->errstat != SNMP_ERR_NOERROR) {
		printf("*** SNMP Error: (%s@%s) %s\n", session.peername, storedoid, snmp_errstring(response->errstat));
	}
	
	/* Liftoff, successful poll, process it */
	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		stats.polls++;
		
		vars = response->variables;
		
		#ifdef OLD_UCD_SNMP
		sprint_value(result_string, anOID, anOID_len, vars);
		#else
		snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
		#endif
		
		if (vars->type == ASN_COUNTER64) {
			if (set.verbose >= DEBUG) {
				printf("64-bit result: (%s@%s) %s\n", session.peername, storedoid, result_string);
			}
			
			result = vars->val.counter64->high;
			result = result << 32;
			result = result + vars->val.counter64->low;
		}else if (vars->type == ASN_COUNTER) {
			if (set.verbose >= DEBUG) {
				printf("32-bit result: (%s@%s) %s\n", session.peername, storedoid, result_string);
			}
			
			result = (unsigned long) *(vars->val.integer);
		}else if (vars->type == ASN_GAUGE) {
			if (set.verbose >= DEBUG) {
				printf("32-bit gauge: (%s@%s) %s\n", session.peername, storedoid, result_string);
			}
			
			result = (unsigned long) *(vars->val.integer);
		}else if (vars->type == ASN_INTEGER) {
			if (set.verbose >= DEBUG) {
				printf("32-bit result: (%s@%s) %s\n", session.peername, storedoid, result_string);
			}
			
			result = (unsigned long) *(vars->val.integer);
		}else{
			if (set.verbose >= DEBUG) {
				printf("Unknown result type: (%s@%s) %s\n", session.peername, storedoid, result_string);
			}
		}
		
		/* Counter Wrap Condition */
		if (bits == 0) {
			if (result != last_value) {
				insert_val = result;
				
				if (set.verbose >= HIGH) {
					printf("Thread [%d]: Gauge change from %lld to %lld\n", current_thread, last_value, insert_val);
				}
			} else insert_val = 0;
		} else if (result < last_value) {
			if (bits == 32) {
				insert_val = (THIRTYTWO - last_value) + result;
			}else if (bits == 64) {
				insert_val = (SIXTYFOUR - last_value) + result;
			}
			
			if (set.verbose >= LOW) {
				printf("*** Counter Wrap (%s@%s) [poll: %lli][last: %llu][insert: %llu]\n",
					session.peername, storedoid, result, last_value, insert_val);
			}
		/* Not a counter wrap and this is not the first poll */
		} else if ((last_value >= 0) && (init >= 0)) {
			insert_val = result - last_value;
			
			/* Print out SNMP result if verbose */
			if (set.verbose == DEBUG) {
				printf("Thread [%d]: (%lld-%lld) = %lli\n", current_thread, result, last_value, insert_val);
			}
			
			if (set.verbose == HIGH) {
				printf("Thread [%d]: %lli\n", current_thread, insert_val);
			}
		/* last_value < 0, so this must be the first poll */
		} else {
			if (set.verbose >= HIGH) {
				printf("Thread [%d]: First Poll, Normalizing\n", current_thread);
			}
			
			insert_val = 0;
		}
		
		/* Check for bogus data, either negative or unrealistic */
		if (insert_val > set.out_of_range || result < 0) {
			if (set.verbose >= LOW) {
				printf("*** Out of Range (%s@%s) [insert_val: %lli] [oor: %lld]\n",
					session.peername, storedoid, insert_val, set.out_of_range);
			}
			
			insert_val = 0;
		}
	}else{
		result = 0;	
	}
	
	if (sessp != NULL) {
		snmp_sess_close(sessp);
		
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}
	
	return result;
}
