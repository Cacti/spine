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

void poll_host(int host_id) {
	char query[256];
	int target_id = 0;
	int num_rows;
	FILE *cmd_stdout;
	char cmd_result[255];
	
	int ignore_host = 0;
	int rrd_ds_counter = 0;
	
	target_t *entry;
	multi_rrd_t *rrd_multids;
	
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;
	
	sprintf(query, "select action,command,management_ip,snmp_community,snmp_version,snmp_username,snmp_password,rrd_name,rrd_path,arg1,arg2,arg3,local_data_id,rrd_num from data_input_data_cache where host_id=%i order by rrd_path,rrd_name", host_id);
	
	db_connect(set.dbdb, &mysql);
	
	result = db_query(&mysql, query);
	num_rows = (int)mysql_num_rows(result);
	
	entry = (target_t *) malloc(sizeof(target_t));
	
	while ((row = mysql_fetch_row(result))) {
		entry->target_id = 0;
		entry->action = atoi(row[0]);
		sprintf(entry->command, "%s", row[1]);
		sprintf(entry->management_ip, "%s", row[2]);
		sprintf(entry->snmp_community, "%s", row[3]);
		entry->snmp_version = atoi(row[4]);
		sprintf(entry->snmp_username, "%s", row[5]);
		sprintf(entry->snmp_password, "%s", row[6]);
		sprintf(entry->rrd_name, "%s", row[7]);
		sprintf(entry->rrd_path, "%s", row[8]);
		sprintf(entry->arg1, "%s", row[9]);
		sprintf(entry->arg2, "%s", row[10]);
		sprintf(entry->arg3, "%s", row[11]);
		entry->local_data_id = atoi(row[12]);
		entry->rrd_num = atoi(row[13]);
		
		switch(entry->action) {
		case 0:
			if (ignore_host == 0) {
				sprintf(entry->result, "%s", snmp_get(entry->management_ip, entry->snmp_community, 1, entry->arg1, host_id));
			}else{
				sprintf(entry->result, "%s", "U");
			}
			
			if (!strcmp(entry->result, "E")) {
				ignore_host = 1;
				printf("SNMP timeout detected, ignoring host '%s'\n", entry->management_ip);
				sprintf(entry->result, "%s", "U");
			}
			
			if (set.verbose >= LOW) {
				printf("[%i] snmp: %s, dsname: %s, oid: %s, value: %s\n", host_id, entry->management_ip, entry->rrd_name, entry->arg1, entry->result);
			}
			
			break;
		case 1:
			cmd_stdout=popen(entry->command, "r");
			
			if(cmd_stdout != NULL) fgets(cmd_result, 255, cmd_stdout);
			
			if (cmd_result == "") {
				sprintf(entry->result, "%s", "U");
			}else{
				sprintf(entry->result, "%s", cmd_result);
			}
			
			if (set.verbose >= LOW) {
				printf("[%i] command: %s, output: %s\n", host_id, entry->command, entry->result);
			}
			
			pclose(cmd_stdout);
			break;
		case 2:
			cmd_stdout=popen(entry->command, "r");
			
			if(cmd_stdout != NULL) fgets(cmd_result, 255, cmd_stdout);
			
			sprintf(entry->result, "%s", cmd_result);
			
			if (set.verbose >= LOW) {
				printf("[%i] MUTLI command: %s, output: %s\n", host_id, entry->command, entry->result);
			}
			
			pclose(cmd_stdout);
			break;
		}
		
		if (entry->rrd_num == 1) {
			if (entry->action == 2) {
				rrd_cmd(rrdcmd_string(entry->rrd_path, entry->result, entry->local_data_id, &mysql));
			}else{
				rrd_cmd(rrdcmd_lli(entry->rrd_name, entry->rrd_path, entry->result));
			}
		}else if (entry->rrd_num > 1) {
			if (rrd_ds_counter == 0) {
				rrd_multids = (multi_rrd_t *)malloc(entry->rrd_num * sizeof(multi_rrd_t));
			}
			
			sprintf(rrd_multids[rrd_ds_counter].rrd_name, "%s", entry->rrd_name);
			sprintf(rrd_multids[rrd_ds_counter].rrd_path, "%s", entry->rrd_path);
			sprintf(rrd_multids[rrd_ds_counter].result, "%s", entry->result);
			
			rrd_ds_counter++;
			
			if (rrd_ds_counter == entry->rrd_num) {
				rrd_cmd(rrdcmd_multids(rrd_multids, (rrd_ds_counter-1)));
				
				rrd_ds_counter = 0;
				free(rrd_multids);
			}
		}
		
		/* do RRD file path check */
		if (!file_exists(entry->rrd_path)) {
			rrd_cmd(create_rrd(entry->local_data_id, entry->rrd_path, &mysql));
		}
	}
	
	free(entry);
	
	mysql_free_result(result);
	mysql_close(&mysql);
}

char *snmp_get(char *snmp_host, char *snmp_comm, int ver, char *snmp_oid, int host_id) {
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
	
	mutex_lock(LOCK_THREAD);
	
	snmp_sess_init(&session);
	
	#ifdef USE_NET_SNMP
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	#endif
	
	mutex_unlock(LOCK_THREAD);
	
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
		vars = response->variables;
		
		#ifdef USE_NET_SNMP
		snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
		#else
		sprint_value(result_string, anOID, anOID_len, vars);
		#endif
	}
	
	if (status == STAT_TIMEOUT) {
		sprintf(result_string, "%s", "E");
	}else if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
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
