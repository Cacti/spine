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
#include "util.h"
#include "php.h"
#include "locks.h"
#include "poller.h"
#include "nft_popen.h"

void *child(void * arg) {
	extern int active_threads;
	int host_id = *(int *) arg;
	char logmessage[255];

	if (set.verbose >= DEBUG) {
		cacti_log("DEBUG: In Poller, About to Start Polling of Host.\n");
	}

	if (active_threads == 1) {
		if (set.verbose >= DEBUG) {
			cacti_log("DEBUG: This is where popen DEADLOCKs errors occur\n");
		}
	}

	poll_host(host_id);

	thread_mutex_lock(LOCK_THREAD);
	active_threads = active_threads - 1;
	thread_mutex_unlock(LOCK_THREAD);

	if (set.verbose >= DEBUG) {
		sprintf(logmessage,"DEBUG: The Value of Active Threads is ->%i\n",active_threads);
		cacti_log(logmessage);
	}

	pthread_exit(0);
}

void poll_host(int host_id) {
	char query1[256];
	char query2[256];
	char *query3;
	char query4[256];
	int num_rows;
	char *poll_result;
	char logmessage[255];

	reindex_t *reindex;
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
	snprintf(query4, sizeof(query4), "select data_query_id,action,op,assert_value,arg1 from poller_reindex where host_id=%i", host_id);

	db_connect(set.dbdb, &mysql);

	/* get data about this host */
	result = db_query(&mysql, query2);
	num_rows = (int)mysql_num_rows(result);

	if (num_rows != 1) {
		sprintf(logmessage,"ERROR: Unknown host id, %i!", host_id);
		cacti_log(logmessage);
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

	/* perform a check to see if the host is alive by polling it's SysName
	 * if the host down from an snmp perspective, don't poll it.
	 * function sets the ignore_host bit */
	poll_result = snmp_get(host, ".1.3.6.1.2.1.1.5.0");
	free(poll_result);

	/* do the reindex check for this host */
	if (!host->ignore_host) {
		reindex = (reindex_t *) malloc(sizeof(reindex_t));

		result = db_query(&mysql, query4);
		num_rows = (int)mysql_num_rows(result);

		if (num_rows > 0) {
			printf("CACTID: Processing %i items in the auto reindex cache for '%s'.\n", num_rows, host->hostname);
		}

		while ((row = mysql_fetch_row(result))) {
			reindex->data_query_id = atoi(row[0]);
			reindex->action = atoi(row[1]);
			if (row[2] != NULL) snprintf(reindex->op, sizeof(reindex->op), "%s", row[2]);
			if (row[3] != NULL) snprintf(reindex->assert_value, sizeof(reindex->assert_value), "%s", row[3]);
			if (row[4] != NULL) snprintf(reindex->arg1, sizeof(reindex->arg1), "%s", row[4]);

			switch(reindex->action) {
			case POLLER_ACTION_SNMP: /* snmp */
				poll_result = snmp_get(host, reindex->arg1);
				break;
			case POLLER_ACTION_SCRIPT: /* script (popen) */
				poll_result = exec_poll(host, reindex->arg1);
				break;
			}

			if ((!strcmp(reindex->op, "=")) && (strcmp(reindex->assert_value,poll_result) != 0)) {
				printf("Assert '%s=%s' failed. Recaching host '%s', data query #%i.\n", reindex->assert_value, poll_result, host->hostname, reindex->data_query_id);

				query3 = (char *)malloc(128);
				sprintf(query3, "insert into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host_id, reindex->data_query_id);
				db_insert(&mysql, query3);
				free(query3);
			}else if ((!strcmp(reindex->op, ">")) && (atoi(reindex->assert_value) <= atoi(poll_result))) {
				printf("Assert '%s>%s' failed. Recaching host '%s', data query #%i.\n", reindex->assert_value, poll_result, host->hostname, reindex->data_query_id);

				query3 = (char *)malloc(128);
				sprintf(query3, "insert into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host_id, reindex->data_query_id);
				db_insert(&mysql, query3);
				free(query3);
			}else if ((!strcmp(reindex->op, "<")) && (atoi(reindex->assert_value) >= atoi(poll_result))) {
				printf("Assert '%s<%s' failed. Recaching host '%s', data query #%i.\n", reindex->assert_value, poll_result, host->hostname, reindex->data_query_id);

				query3 = (char *)malloc(128);
				sprintf(query3, "insert into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host_id, reindex->data_query_id);
				db_insert(&mysql, query3);
				free(query3);
			}

			free(poll_result);
		}
	}

	/* retreive each hosts polling items from poller cache */
	entry = (target_t *) malloc(sizeof(target_t));

	result = db_query(&mysql, query1);
	num_rows = (int)mysql_num_rows(result);

	while ((row = mysql_fetch_row(result)) && (!host->ignore_host)) {
		/* initialize monitored object */
		entry->target_id = 0;
		entry->action = atoi(row[0]);
		if (row[1] != NULL) snprintf(entry->hostname, sizeof(entry->hostname), "%s", row[1]);
		if (row[2] != NULL) snprintf(entry->snmp_community, sizeof(entry->snmp_community), "%s", row[2]);
		entry->snmp_version = atoi(row[3]);
		if (row[4] != NULL) snprintf(entry->snmp_username, sizeof(entry->snmp_username), "%s", row[4]);
		if (row[5] != NULL) snprintf(entry->snmp_password, sizeof(entry->snmp_password), "%s", row[5]);
		if (row[6] != NULL) snprintf(entry->rrd_name, sizeof(entry->rrd_name), "%s", row[6]);
		if (row[7] != NULL) snprintf(entry->rrd_path, sizeof(entry->rrd_path), "%s", row[7]);
		if (row[8] != NULL) snprintf(entry->arg1, sizeof(entry->arg1), "%s", row[8]);
		if (row[9] != NULL) snprintf(entry->arg2, sizeof(entry->arg2), "%s", row[9]);
		if (row[10] != NULL) snprintf(entry->arg3, sizeof(entry->arg3), "%s", row[10]);
		entry->local_data_id = atoi(row[11]);
		entry->rrd_num = atoi(row[12]);
		entry->snmp_port = atoi(row[13]);
		entry->snmp_timeout = atoi(row[14]);
		snprintf(entry->result, sizeof(entry->result), "%s", "U");

		if (!host->ignore_host) {
			switch(entry->action) {
			case POLLER_ACTION_SNMP: /* raw SNMP poll */
				poll_result = snmp_get(host, entry->arg1);
				snprintf(entry->result, sizeof(entry->result), "%s", poll_result);
				free(poll_result);

				if (host->ignore_host) {
					sprintf(logmessage,"ERROR: SNMP timeout detected [%i milliseconds], ignoring host '%s'\n", host->snmp_timeout, host->hostname);
					cacti_log(logmessage);
					snprintf(entry->result, sizeof(entry->result), "%s", "U");
				}

				if (set.verbose >= HIGH) {
					printf("SNMPGET: Host [%i]: v%i: %s, dsname: %s, oid: %s, value: %s\n", host_id, host->snmp_version, host->hostname, entry->rrd_name, entry->arg1, entry->result);
				}

				break;
			case POLLER_ACTION_SCRIPT: /* execute script file */
				poll_result = exec_poll(host, entry->arg1);
				snprintf(entry->result, sizeof(entry->result), "%s", poll_result);
				free(poll_result);

				if (set.verbose >= HIGH) {
					printf("SCRIPT: CMD [%i]: %s, output: %s\n", host_id, entry->arg1, entry->result);
				}

				break;
			case POLLER_ACTION_PHP_SCRIPT_SERVER: /* execute script server */
				poll_result = php_cmd(entry->arg1);
				snprintf(entry->result, sizeof(entry->result), "%s", poll_result);
				free(poll_result);

				if (set.verbose >= HIGH) {
					printf("PHPSERVER: CMD [%i]: %s, output: %s\n", host_id, entry->arg1, entry->result);
				}

				break;
			default: /* unknown action, generate error */
				sprintf(logmessage,"ERROR: Unknown Poller Action for Host [%i] Command: %s\n",host_id,entry->arg1);
				cacti_log(logmessage);

				break;
			}
		}

		if (entry->result != NULL) {
			query3 = (char *)malloc(sizeof(entry->result) + sizeof(entry->local_data_id) + 128);
			sprintf(query3, "insert into poller_output (local_data_id,rrd_name,time,output) values (%i,'%s',NOW(),'%s')", entry->local_data_id, entry->rrd_name, entry->result);
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

	if (set.verbose >= DEBUG) {
		printf("DEBUG: HOST COMPLETE: About to Exit Host Polling Thread Function.\n");
	}
}

char *exec_poll(host_t *current_host, char *command) {
	FILE *cmd_stdout;
	int cmd_fd;
	int return_value;
	char cmd_result[BUFSIZE];
	char logmessage[255];
	char *result_string = (char *) malloc(BUFSIZE);

	thread_mutex_lock(LOCK_PIPE);
	cmd_fd = nft_popen((char *)clean_string(command), "r");

	if (cmd_fd >= 0) {
		cmd_stdout = fdopen(cmd_fd, "r");

		while ((fgets(cmd_result, 512, cmd_stdout) != NULL)) {
			usleep(50000);
		}

		if (set.verbose >= HIGH) {
			printf("ACTION1: Command Result->%s\n", cmd_result);
		}

		/* Cleanup File and Pipe */
		fflush(cmd_stdout);
		fclose(cmd_stdout);
		return_value = nft_pclose(cmd_fd);

		thread_mutex_unlock(LOCK_PIPE);

		if (return_value != 0) {
			sprintf(logmessage,"ERROR: Problem executing command [%s]: '%s'\n", current_host->hostname, command);
			cacti_log(logmessage);
			snprintf(result_string, BUFSIZE, "%s", "U");
		}else if (strlen(cmd_result) == 0) {
			sprintf(logmessage,"ERROR: Empty result [%s]: '%s'\n", current_host->hostname, command);
			cacti_log(logmessage);
			snprintf(result_string, BUFSIZE, "%s", "U");
		}else {
			snprintf(result_string, BUFSIZE, "%s", cmd_result);
		}
	}else{
		thread_mutex_unlock(LOCK_PIPE);
		sprintf(logmessage,"ERROR: Problem executing popen [%s]: '%s'\n", current_host->hostname, command);
		cacti_log(logmessage);
		snprintf(result_string, BUFSIZE, "%s", "U");
	}

	return result_string;
}
