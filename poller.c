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
#include "sql.h"
#include "snmp.h"
#include "poller.h"
#include "nft_popen.h"

void *child(void * arg) {
	extern int active_threads;
	int host_id = *(int *) arg;

	if (set.verbose >= HIGH) {
		printf("POLLER: In Thread, About to Start Polling of Host.\n");
	}

	if (active_threads == 1) {
		if (set.verbose >= HIGH) {
			printf("--------->>>>This is where errors occur<<<<-----------\n");
		}
	}

	poll_host(host_id);

	thread_mutex_lock(LOCK_THREAD);
	active_threads = active_threads - 1;
	thread_mutex_unlock(LOCK_THREAD);

	if (set.verbose >= HIGH) {
		printf("The Value of Active Threads is ->%i\n",active_threads);
	}

	pthread_exit(0);
}

void poll_host(int host_id) {
	char query1[256];
	char query2[256];
	char *query3;
	int target_id = 0;
	int num_rows;
	int failcount = 0;
	FILE *cmd_stdout;
	int cmd_fd;
	int return_value;
	char cmd_result[512];
	char *snmp_result;
	char logmessage[255];

	target_t *entry;
	host_t *host;

	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;

	if (MYSQL_VERSION_ID > 40000) {
		mysql_thread_init();
	}else{
		my_thread_init();
	}

	snprintf(query1, sizeof(query1), "select action,hostname,snmp_community,snmp_version,snmp_username,snmp_password,rrd_name,rrd_path,arg1,arg2,arg3,local_data_id,rrd_num,snmp_port,snmp_timeout from poller_item where host_id=%i order by rrd_path,rrd_name", host_id);
	snprintf(query2, sizeof(query2), "select hostname,snmp_community,snmp_version,snmp_port,snmp_timeout from host where id=%i", host_id);

	db_connect(set.dbdb, &mysql);

	/* get data about this host */
	result = db_query(&mysql, query2);
	num_rows = (int)mysql_num_rows(result);

	if (num_rows != 1) {
		sprintf(logmessage,"ERROR: Unknown host id, %i!", host_id);
		cacti_log(logmessage,"e");
		return;
	}

	row = mysql_fetch_row(result);

	/* preload host structure with appropriate values */
	host = (host_t *) malloc(sizeof(host_t));

	if (row[0] != NULL) snprintf(host->hostname, sizeof(host->hostname), "%s", row[0]);
	if (row[1] != NULL) snprintf(host->snmp_community, sizeof(host->snmp_community), "%s", row[1]);
	host->snmp_version = atoi(row[2]);
	host->snmp_port = atoi(row[3]);
	host->snmp_timeout = atoi(row[4]);
	host->ignore_host = 0;

	/* initialize SNMP */
	snmp_host_init(host);

	/* retreive each hosts polling items from poller cache */
	entry = (target_t *) malloc(sizeof(target_t));

	result = db_query(&mysql, query1);
	num_rows = (int)mysql_num_rows(result);

	while ((row = mysql_fetch_row(result)) && (!host->ignore_host)) {
		/* initialize monitored object */
		entry->target_id = 0;
		entry->action = atoi(row[0]);
		if (row[1] != NULL) snprintf(entry->hostname, sizeof(entry->hostname), "%s", row[2]);
		if (row[2] != NULL) snprintf(entry->snmp_community, sizeof(entry->snmp_community), "%s", row[3]);
		entry->snmp_version = atoi(row[3]);
		if (row[4] != NULL) snprintf(entry->snmp_username, sizeof(entry->snmp_username), "%s", row[5]);
		if (row[5] != NULL) snprintf(entry->snmp_password, sizeof(entry->snmp_password), "%s", row[6]);
		if (row[6] != NULL) snprintf(entry->rrd_name, sizeof(entry->rrd_name), "%s", row[7]);
		if (row[7] != NULL) snprintf(entry->rrd_path, sizeof(entry->rrd_path), "%s", row[8]);
		if (row[8] != NULL) snprintf(entry->arg1, sizeof(entry->arg1), "%s", row[9]);
		if (row[9] != NULL) snprintf(entry->arg2, sizeof(entry->arg2), "%s", row[10]);
		if (row[10] != NULL) snprintf(entry->arg3, sizeof(entry->arg3), "%s", row[11]);
		entry->local_data_id = atoi(row[11]);
		entry->rrd_num = atoi(row[12]);
		entry->snmp_port = atoi(row[13]);
		entry->snmp_timeout = atoi(row[14]);
		snprintf(entry->result, sizeof(entry->result), "%s", "U");

		/* perform a check to see if the host is alive by polling it's SysName
		 * if the host down from an snmp perspective, don't poll it.
		 * function sets the ignore_host bit */
		snmp_result = snmp_get(host, ".1.3.6.1.2.1.1.5.0");

		if (!host->ignore_host) {
			switch(entry->action) {
			case 0: /* raw SNMP poll */
				if ((entry->snmp_version == 1) || (entry->snmp_version == 2)) {
					snmp_result = snmp_get(host, entry->arg1);
					snprintf(entry->result, sizeof(entry->result), "%s", snmp_result);
					free(snmp_result);
				}else {
					sprintf(logmessage,"ERROR: SNMP v3 is not yet supported in cactid [host: %s]\n", host->hostname);
					cacti_log(logmessage,"e");
				}

				if (host->ignore_host) {
					sprintf(logmessage,"ERROR: SNMP timeout detected [%i milliseconds], ignoring host '%s'\n", host->snmp_timeout, host->hostname);
					cacti_log(logmessage,"e");
					snprintf(entry->result, sizeof(entry->result), "%s", "U");
				}

				if (set.verbose >= HIGH) {
					printf("SNMPGET COMPLETE: Host [%i]: v%i: %s, dsname: %s, oid: %s, value: %s\n", host_id, host->snmp_version, host->hostname, entry->rrd_name, entry->arg1, entry->result);
				}

				break;
			case 1: /* execute script file */
				thread_mutex_lock(LOCK_PIPE);
				cmd_fd = nft_popen((char *)clean_string(entry->arg1), "r");

				if (cmd_fd >= 0) {
					cmd_stdout = fdopen(cmd_fd, "r");

					while ((fgets(cmd_result, 512, cmd_stdout) != NULL)) {
						usleep(50000);
					}

					if (set.verbose >= HIGH) {
						printf("ACTION1: Command Result->%s\n",cmd_result);
					}

					/* Cleanup File and Pipe */
					fflush(cmd_stdout);
					fclose(cmd_stdout);
					return_value = nft_pclose(cmd_fd);

					thread_mutex_unlock(LOCK_PIPE);

					if (return_value != 0) {
						sprintf(logmessage,"ERROR: Problem executing command [%i]: '%s'\n", host_id, entry->arg1);
						cacti_log(logmessage,"e");
						snprintf(entry->result, sizeof(entry->result), "%s", "U");
					}else if (strlen(cmd_result) == 0) {
						sprintf(logmessage,"ERROR: Empty result [%i]: '%s'\n", host_id, entry->arg1);
						cacti_log(logmessage,"e");
						snprintf(entry->result, sizeof(entry->result), "%s", "U");
					}else {
						snprintf(entry->result, sizeof(entry->result), "%s", cmd_result);
					}
				}else{
					thread_mutex_unlock(LOCK_PIPE);
					sprintf(logmessage,"ERROR: Problem executing popen [%i]: '%s'\n", host_id, entry->arg1);
					cacti_log(logmessage,"e");
					snprintf(entry->result, sizeof(entry->result), "%s", "U");
				}

				if (set.verbose >= HIGH) {
					printf("POLL COMPLETE: Command [%i]: %s, output: %s\n", host_id, entry->arg1, entry->result);
				}

				break;
			case 2: /* execute multi script file */
				thread_mutex_lock(LOCK_PIPE);
				cmd_fd = nft_popen((char *)clean_string(entry->arg1), "r");

				if (cmd_fd > 0) {
					cmd_stdout = fdopen(cmd_fd, "r");

					while ((fgets(cmd_result, 512, cmd_stdout) != NULL)) {
						usleep(50000);
					}

					if (set.verbose >= HIGH) {
						printf("ACTION2: Command Result->%s\n",cmd_result);
					}

					/* Cleanup File and Pipe */
					fflush(cmd_stdout);
					fclose(cmd_stdout);
					return_value = nft_pclose(cmd_fd);

					thread_mutex_unlock(LOCK_PIPE);

					if (return_value != 0) {
						sprintf(logmessage,"ERROR: Problem executing command [%i]: '%s'\n", host_id, entry->arg1);
						cacti_log(logmessage,"e");
						snprintf(entry->result, sizeof(entry->result), "%s", "U");
					}else if (strlen(cmd_result) == 0) {
						sprintf(logmessage,"ERROR: Empty result [%i]: '%s'\n", host_id, entry->arg1);
						cacti_log(logmessage,"e");
						snprintf(entry->result, sizeof(entry->result), "%s", "U");
					}else {
						snprintf(entry->result, sizeof(entry->result), "%s", cmd_result);
					}
				}else{
					thread_mutex_unlock(LOCK_PIPE);
					sprintf(logmessage,"ERROR: Problem executing popen [%i]: '%s'\n", host_id, entry->arg1);
					cacti_log(logmessage,"e");
					snprintf(entry->result, sizeof(entry->result), "%s", "U");
				}

				if (set.verbose >= HIGH) {
					printf("POLL COMPLETE: MUTLI command [%i]: %s, output: %s\n", host_id, entry->arg1, entry->result);
				}

				break;
			default: /* unknown action, generate error */
				sprintf(logmessage,"ERROR: Unknown Poller Action for Host [%i] Command: %s\n",host_id,entry->arg1);
				cacti_log(logmessage,"e");

				break;
			}
		}

		if (entry->result != NULL) {
			query3 = (char *)malloc(sizeof(entry->result) + sizeof(entry->local_data_id) + 128);
			sprintf(query3, "insert into poller_output (local_data_id,time,output) values (%i,NOW(),'%s')", entry->local_data_id, entry->result);
			db_insert(&mysql, query3);
			free(query3);
		}
	}

	/* cleanup memory and prepare for function exit */
	snmp_host_cleanup(host);

	free(entry);
	free(host);

	mysql_free_result(result);

	if (MYSQL_VERSION_ID > 40000) {
		mysql_thread_end();
	}else{
		my_thread_end();
	}

	mysql_close(&mysql);

	if (set.verbose >= HIGH) {
		printf("HOST COMPLETE: About to Exit Host Polling Thread Function\n");
	}
}
