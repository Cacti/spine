/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2006 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         | 
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "cactid.h"
#include "sql.h"
#include "snmp.h"
#include "util.h"
#include "php.h"
#include "ping.h"
#include "locks.h"
#include "poller.h"
#include "nft_popen.h"
#include <errno.h>
#include <math.h>

/*! \fn void *child(void *arg)
 *  \brief function is called via the fork command and initiates a poll of a host
 *  \param arg a pointer to an integer point to the host_id to be polled
 *
 *	This function will call the primary Cactid polling function to poll a host
 *  and then reduce the number of active threads by one so that the next host
 *  can be polled.
 *
 */
void *child(void *arg) {
	int host_id = *(int *) arg;

	CACTID_LOG_DEBUG(("DEBUG: In Poller, About to Start Polling of Host\n"));

	poll_host(host_id);

	thread_mutex_lock(LOCK_THREAD);
	active_threads--;
	thread_mutex_unlock(LOCK_THREAD);

	CACTID_LOG_DEBUG(("DEBUG: The Value of Active Threads is %i\n" ,active_threads));

	pthread_exit(0);
}

/*! \fn void poll_host(int host_id)
 *  \brief core Cactid function that polls a host
 *  \param host_id integer value for the host_id from the hosts table in Cacti
 *
 *	This function is core to Cactid.  It will take a host_id and then poll it.
 *
 *  Prior to the poll, the system will ping the host to verifiy that it is up.
 *  In addition, the system will check to see if any reindexing of data query's 
 *  is required.
 *
 *  If reindexing is required, the Cacti poller.php function will spawn that
 *  reindexing process.
 *
 *  In the case of hosts that require reindexing because of a sysUptime
 *  rollback, Cactid will store an unknown (NaN) value for all objects to prevent
 *  spikes in the graphs.
 *
 *  With regard to snmp calls, if the host has multiple snmp agents running
 *  Cactid will re-initialize the snmp session and poll under those new ports
 *  as the host poller_items table dictates.
 *
 */
void poll_host(int host_id) {
	char query1[BUFSIZE];
	char query2[BUFSIZE];
	char *query3;
	char query4[BUFSIZE];
	char query5[BUFSIZE];
	char query6[BUFSIZE];
	char query7[BUFSIZE];
	char query8[BUFSIZE];
	char errstr[BUFSIZE];
	char *sysUptime;
	char result_string[BUFSIZE];

	int num_rows;
	int assert_fail = 0;
	int spike_kill = 0;
	int rows_processed = 0;
	int i;
	int j;
	int num_oids = 0;
	int snmp_poller_items = 0;
	int out_buffer;
	int php_process;

	char *poll_result = NULL;
	char *host_time = NULL;
	char update_sql[BUFSIZE];
	char temp_result[BUFSIZE];

	int last_snmp_version = 0;
	int last_snmp_port = 0;
	char last_snmp_username[50];
	char last_snmp_password[50];

	reindex_t *reindex;
	host_t *host;
	ping_t *ping;
	target_t *poller_items;
	snmp_oids_t *snmp_oids;

	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;

	#ifndef OLD_MYSQL   
	mysql_thread_init();
	#endif 

	db_connect(set.dbdb, &mysql);
	
	/* allocate host and ping structures with appropriate values */
	if (!(host = (host_t *) malloc(sizeof(host_t)))) {
		die("ERROR: Fatal malloc error: poller.c host struct!\n");
	}
	memset(host, 0, sizeof(host));

	if (!(ping = (ping_t *) malloc(sizeof(ping_t)))) {
		die("ERROR: Fatal malloc error: poller.c ping struct!\n");
	}
	memset(ping, 0, sizeof(ping_t));

	if (!(reindex = (reindex_t *) malloc(sizeof(reindex_t)))) {
		die("ERROR: Fatal malloc error: poller.c reindex poll!\n");
	}
	memset(reindex, 0, sizeof(reindex_t));

	if (!(sysUptime = (char *) malloc(BUFSIZE))) {
		die("ERROR: Fatal malloc error: poller.c sysUptime\n");
	}
	memset(sysUptime, 0, BUFSIZE);

	/* initialize query strings */
	snprintf(query1, sizeof(query1)-1,
		"SELECT action,hostname,snmp_community,"
			"snmp_version,snmp_username,snmp_password,"
			"rrd_name,rrd_path,arg1,arg2,arg3,local_data_id,"
			"rrd_num,snmp_port,snmp_timeout"
		" FROM poller_item"
		" WHERE host_id=%i"
		" ORDER BY arg1", host_id);

	snprintf(query2, sizeof(query2)-1,
		"SELECT id, hostname,snmp_community,"
			"snmp_username,snmp_password,snmp_version,"
			"snmp_port,snmp_timeout,status,"
			"status_event_count,status_fail_date,"
			"status_rec_date,status_last_error,"
			"min_time,max_time,cur_time,avg_time,"
			"total_polls,failed_polls,availability"
		" FROM host"
		" WHERE id=%i", host_id);

	snprintf(query4, sizeof(query4)-1,
		"SELECT data_query_id,action,op,assert_value,arg1"
			" FROM poller_reindex"
			" WHERE host_id=%i", host_id);

	snprintf(query5, sizeof(query5)-1,
		"SELECT action,hostname,snmp_community,snmp_version,"
			"snmp_username,snmp_password,rrd_name,"
			"rrd_path,arg1,arg2,arg3,local_data_id,"
			"rrd_num,snmp_port,snmp_timeout"
		" FROM poller_item"
		" WHERE host_id=%i and rrd_next_step <=0"
		" ORDER by rrd_path,rrd_name", host_id);

	snprintf(query6, sizeof(query6)-1,
		"UPDATE poller_item"
		" SET rrd_next_step=rrd_next_step-%i"
		" WHERE host_id=%i", set.poller_interval, host_id);

	snprintf(query7, sizeof(query7)-1,
		"UPDATE poller_item"
		" SET rrd_next_step=rrd_step-%i"
		" WHERE rrd_next_step < 0 and host_id=%i",
			set.poller_interval, host_id);
			
	snprintf(query8, sizeof(query8)-1,
		"INSERT INTO poller_output"
		" (local_data_id,rrd_name,time,output) VALUES");

	/* get the host polling time */
	host_time = get_host_poll_time();

	/* initialize the ping structure variables */
	snprintf(ping->ping_status, sizeof(ping->ping_status)-1, "down");
	snprintf(ping->ping_response, sizeof(ping->ping_response)-1, "Ping not performed due to setting.");
	snprintf(ping->snmp_status, sizeof(ping->snmp_status)-1, "down");
	snprintf(ping->snmp_response, sizeof(ping->snmp_response)-1, "SNMP not performed due to setting or ping result");

	if (host_id) {
		/* get data about this host */
		result = db_query(&mysql, query2);
		num_rows = (int)mysql_num_rows(result);

		if (num_rows != 1) {
			CACTID_LOG(("Host[%i] ERROR: Unknown Host ID", host_id));

			mysql_free_result(result);
			#ifndef OLD_MYSQL   
			mysql_thread_end();
			#endif 
			mysql_close(&mysql);

			return;
		}

		row = mysql_fetch_row(result);

		/* populate host structure */
		host->ignore_host = 0;
		host->id = atoi(row[0]);

		host->hostname[0] = '\0';
		host->snmp_community[0] = '\0';
		host->snmp_username[0] = '\0';
		host->snmp_password[0] = '\0';

		if (row[1] != NULL) STRNCOPY(host->hostname,       row[1]);
		if (row[2] != NULL) STRNCOPY(host->snmp_community, row[2]);
		if (row[3] != NULL) STRNCOPY(host->snmp_username,  row[3]);
		if (row[4] != NULL) STRNCOPY(host->snmp_password,  row[4]);

		host->snmp_version = atoi(row[5]);
		host->snmp_port = atoi(row[6]);
		host->snmp_timeout = atoi(row[7]);
		host->status = atoi(row[8]);
		host->status_event_count = atoi(row[9]);

		STRNCOPY(host->status_fail_date, row[10]);
		STRNCOPY(host->status_rec_date,  row[11]);

		host->status_last_error[0] = '\0';

		if (row[12] != NULL) STRNCOPY(host->status_last_error, row[12]);

		host->min_time = atof(row[13]);
		host->max_time = atof(row[14]);
		host->cur_time = atof(row[15]);
		host->avg_time = atof(row[16]);
		host->total_polls = atoi(row[17]);
		host->failed_polls = atoi(row[18]);
		host->availability = atof(row[19]);

		if (((host->snmp_version <= 2) && (strlen(host->snmp_community) > 0)) || (host->snmp_version == 3)) {
			host->snmp_session = snmp_host_init(host->id, host->hostname, host->snmp_version, host->snmp_community,
									host->snmp_username, host->snmp_password, host->snmp_port, host->snmp_timeout);
		}else{
			host->snmp_session = NULL;
		}

		/* save snmp status data for future use */
		last_snmp_port = host->snmp_port;
		last_snmp_version = host->snmp_version;
		snprintf(last_snmp_username, sizeof(last_snmp_username)-1, "%s", host->snmp_username);
		snprintf(last_snmp_password, sizeof(last_snmp_password)-1, "%s", host->snmp_password);

		/* perform a check to see if the host is alive by polling it's SysDesc
		 * if the host down from an snmp perspective, don't poll it.
		 * function sets the ignore_host bit */
		if ((set.availability_method == AVAIL_SNMP) && (strlen(host->snmp_community) == 0)) {
			host->ignore_host = 0;
			update_host_status(HOST_UP, host, ping, set.availability_method);

			CACTID_LOG_MEDIUM(("Host[%i] No host availability check possible for '%s'\n", host->id, host->hostname));
		}else{
			if (ping_host(host, ping) == HOST_UP) {
				host->ignore_host = 0;
				update_host_status(HOST_UP, host, ping, set.availability_method);
			}else{
				host->ignore_host = 1;
				update_host_status(HOST_DOWN, host, ping, set.availability_method);
			}
		}

		/* update host table */
		snprintf(update_sql, sizeof(update_sql)-1, "update host set status='%i',status_event_count='%i', status_fail_date='%s',status_rec_date='%s',status_last_error='%s',min_time='%f',max_time='%f',cur_time='%f',avg_time='%f',total_polls='%i',failed_polls='%i',availability='%.4f' where id='%i'",
			host->status,
			host->status_event_count,
			host->status_fail_date,
			host->status_rec_date,
			host->status_last_error,
			host->min_time,
			host->max_time,
			host->cur_time,
			host->avg_time,
			host->total_polls,
			host->failed_polls,
			host->availability,
			host->id);

		db_insert(&mysql, update_sql);
	}else{
		host->id = 0;
		host->ignore_host = 0;
	}

	/* do the reindex check for this host if not script based */
	if ((!host->ignore_host) && (host_id)) {
		result = db_query(&mysql, query4);
		num_rows = (int)mysql_num_rows(result);

		if (num_rows > 0) {
			CACTID_LOG_DEBUG(("Host[%i] RECACHE: Processing %i items in the auto reindex cache for '%s'\n", host->id, num_rows, host->hostname));

			while ((row = mysql_fetch_row(result))) {
				assert_fail = 0;

				reindex->data_query_id = atoi(row[0]);
				reindex->action = atoi(row[1]);
				if (row[2] != NULL) snprintf(reindex->op,           sizeof(reindex->op)-1,           "%s", row[2]);
				if (row[3] != NULL) snprintf(reindex->assert_value, sizeof(reindex->assert_value)-1, "%s", row[3]);
				if (row[4] != NULL) snprintf(reindex->arg1,         sizeof(reindex->arg1)-1,         "%s", row[4]);

				switch(reindex->action) {
				case POLLER_ACTION_SNMP: /* snmp */
					/* check to see if you are checking uptime */
					if (!strcmp(reindex->arg1,".1.3.6.1.2.1.1.3.0")) {
						if (strlen(sysUptime) > 0) {
							if (!(poll_result = (char *) malloc(BUFSIZE))) {
								die("ERROR: Fatal malloc error: poller.c poll_result\n");
							}
							memset(poll_result, 0, BUFSIZE);

							snprintf(poll_result, BUFSIZE-1, "%s", sysUptime);
						}else{
							poll_result = snmp_get(host, reindex->arg1);
							snprintf(sysUptime, BUFSIZE-1, "%s", poll_result);
						}
					}else{
						poll_result = snmp_get(host, reindex->arg1);
					}
					break;
				case POLLER_ACTION_SCRIPT: /* script (popen) */
					poll_result = exec_poll(host, reindex->arg1);
					break;
				}

				if (!(query3 = (char *)malloc(BUFSIZE))) {
					die("ERROR: Fatal malloc error: poller.c reindex insert!\n");
				}
				memset(query3, 0, BUFSIZE);

				/* assume ok if host is up and result wasn't obtained */
				if(IS_UNDEFINED(poll_result)) {
					assert_fail = 0;
				}else if ((!strcmp(reindex->op, "=")) && (strcmp(reindex->assert_value,poll_result))) {
					CACTID_LOG_HIGH(("Host[%i] ASSERT: '%s' .eq. '%s' failed. Recaching host '%s', data query #%i\n", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

					snprintf(query3, BUFSIZE, "replace into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
					db_insert(&mysql, query3);
					assert_fail = 1;
				}else if ((!strcmp(reindex->op, ">")) && (strtoll(reindex->assert_value, (char **)NULL, 10) < strtoll(poll_result, (char **)NULL, 10))) {
					CACTID_LOG_HIGH(("Host[%i] ASSERT: '%s' .gt. '%s' failed. Recaching host '%s', data query #%i\n", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

					snprintf(query3, BUFSIZE, "replace into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
					db_insert(&mysql, query3);
					assert_fail = 1;
				}else if ((!strcmp(reindex->op, "<")) && (strtoll(reindex->assert_value, (char **)NULL, 10) > strtoll(poll_result, (char **)NULL, 10))) {
					CACTID_LOG_HIGH(("Host[%i] ASSERT: '%s' .lt. '%s' failed. Recaching host '%s', data query #%i\n", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

					snprintf(query3, BUFSIZE, "replace into poller_command (poller_id,time,action,command) values (0,NOW(),%i,'%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
					db_insert(&mysql, query3);
					assert_fail = 1;
				}

				/* update 'poller_reindex' with the correct information if:
				 * 1) the assert fails
				 * 2) the OP code is > or < meaning the current value could have changed without causing
				 *     the assert to fail */
				if ((assert_fail == 1) || (!strcmp(reindex->op, ">")) || (!strcmp(reindex->op, "<"))) {
					snprintf(query3, 254, "update poller_reindex set assert_value='%s' where host_id='%i' and data_query_id='%i' and arg1='%s'", poll_result, host_id, reindex->data_query_id, reindex->arg1);
					db_insert(&mysql, query3);

					if ((assert_fail == 1) && (!strcmp(reindex->arg1,".1.3.6.1.2.1.1.3.0"))) {
						spike_kill = 1;
						CACTID_LOG_MEDIUM(("Host[%i] NOTICE: Spike Kill in Effect for '%s'", host_id, host->hostname));
					}
				}

				free(query3);
				free(poll_result);
			}
		}
	}

	/* calculate the number of poller items to poll this cycle */
	if (set.poller_interval == 0) {
		result = db_query(&mysql, query1);
		num_rows = (int)mysql_num_rows(result);
	}else{
		result = db_query(&mysql, query5);
		num_rows = (int)mysql_num_rows(result);
		
		/* update poller_items table for next polling interval */
		db_query(&mysql, query6);
		db_query(&mysql, query7);
	}

	if (num_rows > 0) {
		/* retreive each hosts polling items from poller cache and load into array */
		poller_items = (target_t *) calloc(num_rows, sizeof(target_t));
		memset(poller_items, 0, sizeof(target_t)*num_rows);

		i = 0;
		while ((row = mysql_fetch_row(result))) {
			/* initialize monitored object */
			poller_items[i].target_id = 0;
			poller_items[i].action = atoi(row[0]);

			if (row[1] != NULL) snprintf(poller_items[i].hostname, sizeof(poller_items[i].hostname)-1, "%s", row[1]);
			if (row[2] != NULL) {
				snprintf(poller_items[i].snmp_community, sizeof(poller_items[i].snmp_community)-1, "%s", row[2]);
			}else{
				poller_items[i].snmp_community[0] = '\0';
			}
			poller_items[i].snmp_version = atoi(row[3]);
			if (row[4] != NULL) {
				snprintf(poller_items[i].snmp_username, sizeof(poller_items[i].snmp_username)-1, "%s", row[4]);
			}else{
				poller_items[i].snmp_username[0] = '\0';
			}
			if (row[5] != NULL) {
				snprintf(poller_items[i].snmp_password, sizeof(poller_items[i].snmp_password)-1, "%s", row[5]);
			}else{
				poller_items[i].snmp_password[0] = '\0';
			}
			if (row[6] != NULL) snprintf(poller_items[i].rrd_name, sizeof(poller_items[i].rrd_name)-1, "%s", row[6]);
			if (row[7] != NULL) snprintf(poller_items[i].rrd_path, sizeof(poller_items[i].rrd_path)-1, "%s", row[7]);
			if (row[8] != NULL) snprintf(poller_items[i].arg1, sizeof(poller_items[i].arg1)-1, "%s", row[8]);
			if (row[9] != NULL) snprintf(poller_items[i].arg2, sizeof(poller_items[i].arg2)-1, "%s", row[9]);
			if (row[10] != NULL) snprintf(poller_items[i].arg3, sizeof(poller_items[i].arg3)-1, "%s", row[10]);
			poller_items[i].local_data_id = atoi(row[11]);
			poller_items[i].rrd_num = atoi(row[12]);
			poller_items[i].snmp_port = atoi(row[13]);
			poller_items[i].snmp_timeout = atoi(row[14]);
			SET_UNDEFINED(poller_items[i].result);

			if (poller_items[i].action == POLLER_ACTION_SNMP) {
				snmp_poller_items++;
			}
		
			i++;
		}

		/* create an array for snmp oids */
		snmp_oids = (snmp_oids_t *) calloc(set.snmp_max_get_size, sizeof(snmp_oids_t));
		memset(snmp_oids, 0, sizeof(snmp_oids_t)*set.snmp_max_get_size);

		i = 0;
		while ((i < num_rows) && (!host->ignore_host)) {
			if (!host->ignore_host) {
				switch(poller_items[i].action) {
				case POLLER_ACTION_SNMP: /* raw SNMP poll */
					/* initialize or reinitialize snmp as required */
					if (host->snmp_session == NULL) {
						last_snmp_port = poller_items[i].snmp_port;
						last_snmp_version = poller_items[i].snmp_version;

						STRNCOPY(last_snmp_username, poller_items[i].snmp_username);
						STRNCOPY(last_snmp_password, poller_items[i].snmp_password);

						host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname, poller_items[i].snmp_version,
												poller_items[i].snmp_community,poller_items[i].snmp_username,
												poller_items[i].snmp_password, poller_items[i].snmp_port, poller_items[i].snmp_timeout);
					}
				
					/* catch snmp initialization issues */
					if (host->snmp_session == NULL) {
						host->ignore_host = 1;
						break;
					}
				
					/* some snmp data changed from poller item to poller item.  therefore, poll host and store data */
					if ((last_snmp_port != poller_items[i].snmp_port) || 
						(last_snmp_version != poller_items[i].snmp_version) ||
						(strcmp(last_snmp_username, poller_items[i].snmp_username) != 0) ||
						(strcmp(last_snmp_password, poller_items[i].snmp_password) != 0)) {
					
						if (num_oids > 0) {
							snmp_get_multi(host, snmp_oids, num_oids);

							for (j = 0; j < num_oids; j++) {
								if (host->ignore_host) {
									CACTID_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
									SET_UNDEFINED(snmp_oids[j].result);
								}else {
									/* remove double or single quotes from string */
									snprintf(temp_result, BUFSIZE-1, "%s", strip_quotes(snmp_oids[j].result));
									snprintf(snmp_oids[j].result, sizeof(snmp_oids[j].result)-1, "%s", strip_alpha(temp_result));
								
									/* detect erroneous non-numeric result */
									if (!validate_result(snmp_oids[j].result)) {
										snprintf(errstr, sizeof(errstr)-1, "%s", snmp_oids[j].result);
										CACTID_LOG(("Host[%i] DS[%i] WARNING: Result from SNMP not valid. Partial Result: %.100s...\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, errstr));
										SET_UNDEFINED(snmp_oids[j].result);
									}
								}

								snprintf(poller_items[snmp_oids[j].array_position].result, 254, "%s", snmp_oids[j].result);
							
								CACTID_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
							}

							/* clear snmp_oid's memory and reset num_snmps */
							memset(snmp_oids, 0, sizeof(snmp_oids_t)*set.snmp_max_get_size);
							num_oids = 0;
						}
					
						snmp_host_cleanup(host->snmp_session);
						host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname, poller_items[i].snmp_version,
												poller_items[i].snmp_community,poller_items[i].snmp_username,
												poller_items[i].snmp_password, poller_items[i].snmp_port, poller_items[i].snmp_timeout);

						last_snmp_port = poller_items[i].snmp_port;
						last_snmp_version = poller_items[i].snmp_version;

						STRNCOPY(last_snmp_username, poller_items[i].snmp_username);
						STRNCOPY(last_snmp_password, poller_items[i].snmp_password);
					}

					if (num_oids >= set.snmp_max_get_size) {
						snmp_get_multi(host, snmp_oids, num_oids);

						for (j = 0; j < num_oids; j++) {
							if (host->ignore_host) {
								CACTID_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
								SET_UNDEFINED(snmp_oids[j].result);
							}else {
								/* remove double or single quotes from string */
								snprintf(temp_result, BUFSIZE-1, "%s", strip_quotes(snmp_oids[j].result));
								snprintf(snmp_oids[j].result, sizeof(snmp_oids[j].result)-1, "%s", strip_alpha(temp_result));

								/* detect erroneous non-numeric result */
								if (!validate_result(snmp_oids[j].result)) {
									snprintf(errstr, sizeof(errstr)-1, "%s", snmp_oids[j].result);
									CACTID_LOG(("Host[%i] DS[%i] WARNING: Result from SNMP not valid. Partial Result: %.20s...\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, errstr));
									SET_UNDEFINED(snmp_oids[j].result);
								}
							}

							snprintf(poller_items[snmp_oids[j].array_position].result, 254, "%s", snmp_oids[j].result);
							
							CACTID_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));

							if (poller_items[snmp_oids[j].array_position].result != NULL) {
								/* insert a NaN in place of the actual value if the snmp agent restarts */
								if ((spike_kill) && (!strstr(poller_items[snmp_oids[j].array_position].result,":"))) {
									SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
								}
							}
						}

						/* clear snmp_oid's memory and reset num_snmps */
						memset(snmp_oids, 0, sizeof(snmp_oids_t)*set.snmp_max_get_size);
						num_oids = 0;
					}
						
					snprintf(snmp_oids[num_oids].oid, sizeof(snmp_oids[num_oids].oid)-1, "%s", poller_items[i].arg1);
					snmp_oids[num_oids].array_position = i;
					num_oids++;
				
					break;
				case POLLER_ACTION_SCRIPT: /* execute script file */
					poll_result = exec_poll(host, poller_items[i].arg1);

					/* remove double or single quotes from string */
					snprintf(temp_result, BUFSIZE-1, "%s", strip_quotes(poll_result));
					snprintf(poller_items[i].result, sizeof(poller_items[i].result)-1, "%s", strip_alpha(temp_result));

					free(poll_result);

					/* detect erroneous result. can be non-numeric */
					if (!validate_result(poller_items[i].result)) {
						snprintf(errstr, sizeof(errstr)-1, "%s", poller_items[i].result);
						CACTID_LOG(("Host[%i] DS[%i] WARNING: Result from SCRIPT not valid. Partial Result: %.20s...\n", host_id, poller_items[i].local_data_id, errstr));
						SET_UNDEFINED(poller_items[i].result);
					}

					CACTID_LOG_MEDIUM(("Host[%i] DS[%i] SCRIPT: %s, output: %s\n", host_id, poller_items[i].local_data_id, poller_items[i].arg1, poller_items[i].result));

					if (poller_items[i].result != NULL) {
						/* insert a NaN in place of the actual value if the snmp agent restarts */
						if ((spike_kill) && (!strstr(poller_items[i].result,":"))) {
							SET_UNDEFINED(poller_items[i].result);
						}
					}

					break;
				case POLLER_ACTION_PHP_SCRIPT_SERVER: /* execute script server */
					php_process = php_get_process();

					poll_result = php_cmd(poller_items[i].arg1, php_process);

					/* remove double or single quotes from string */
					snprintf(temp_result, BUFSIZE-1, "%s", strip_quotes(poll_result));
					snprintf(poller_items[i].result, sizeof(poller_items[i].result)-1, "%s", strip_alpha(temp_result));

					free(poll_result);

					/* detect erroneous result. can be non-numeric */
					if (!validate_result(poller_items[i].result)) {
						snprintf(errstr, sizeof(errstr)-1, "%s", poller_items[i].result);
						CACTID_LOG(("Host[%i] DS[%i] SS[%i] WARNING: Result from SERVER not valid.  Partial Result: %.20s...\n", host_id, poller_items[i].local_data_id, php_process, errstr));
						SET_UNDEFINED(poller_items[i].result);
					}

					CACTID_LOG_MEDIUM(("Host[%i] DS[%i] SS[%i] SERVER: %s, output: %s\n", host_id, poller_items[i].local_data_id, php_process, poller_items[i].arg1, poller_items[i].result));

					if (poller_items[i].result != NULL) {
						/* insert a NaN in place of the actual value if the snmp agent restarts */
						if ((spike_kill) && (!strstr(poller_items[i].result,":"))) {
							SET_UNDEFINED(poller_items[i].result);
						}
					}

					break;
				default: /* unknown action, generate error */
					CACTID_LOG(("Host[%i] DS[%i] ERROR: Unknown Poller Action: %s\n", host_id, poller_items[i].local_data_id, poller_items[i].arg1));

					break;
				}
			}

			i++;
			rows_processed++;
		}

		/* process last multi-get request if applicable */
		if (num_oids > 0) {
			snmp_get_multi(host, snmp_oids, num_oids);

			for (j = 0; j < num_oids; j++) {
				if (host->ignore_host) {
					CACTID_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
					SET_UNDEFINED(snmp_oids[j].result);
				}else{
					/* remove double or single quotes from string */
					snprintf(temp_result, BUFSIZE-1, "%s", strip_quotes(snmp_oids[j].result));
					snprintf(snmp_oids[j].result, sizeof(snmp_oids[j].result)-1, "%s", strip_alpha(temp_result));

					/* detect erroneous non-numeric result */
					if (!validate_result(snmp_oids[j].result)) {
						snprintf(errstr, sizeof(errstr)-1, "%s", snmp_oids[j].result);
						CACTID_LOG(("Host[%i] DS[%i] WARNING: Result from SNMP not valid. Partial Result: %.20s...\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, errstr));
						SET_UNDEFINED(snmp_oids[j].result);
					}
				}

				snprintf(poller_items[snmp_oids[j].array_position].result, 254, "%s", snmp_oids[j].result);
					
				CACTID_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s\n", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));

				if (poller_items[snmp_oids[j].array_position].result != NULL) {
					/* insert a NaN in place of the actual value if the snmp agent restarts */
					if ((spike_kill) && (!strstr(poller_items[snmp_oids[j].array_position].result,":"))) {
						SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
					}
				}
			}
		}

		/* insert the query results into the database */
		if (!(query3 = (char *)malloc(MAX_MYSQL_BUF_SIZE))) {
			die("ERROR: Fatal malloc error: poller.c query3 oids!\n");
		}
		query3[0] = '\0';

		int new_buffer = TRUE;
		
		strncopy(query3, query8, strlen(query8));
		out_buffer = strlen(query3);
		
		i = 0;
		while (i < rows_processed) {
			snprintf(result_string, sizeof(result_string)-1, " (%i,'%s','%s','%s')", poller_items[i].local_data_id, poller_items[i].rrd_name, host_time, poller_items[i].result);
			
			/* if the next element to the buffer will overflow it, write to the database */
			if ((out_buffer + strlen(result_string)) >= MAX_MYSQL_BUF_SIZE) {
				/* insert the record */
				db_insert(&mysql, query3);

				/* re-initialize the query buffer */
				strncopy(query3, query8, strlen(query8));

				/* reset the output buffer length */
				out_buffer = strlen(query3);

				/* set binary, let the system know we are a new buffer */
				new_buffer = TRUE;
			}
			
			/* if this is our first pass, or we just outputted to the database, need to change the delimeter */
			if (new_buffer) {
				result_string[0] = ' ';
			}else{
				result_string[0] = ',';
			}
							
			out_buffer = out_buffer + strlen(result_string);
			strncat(query3, result_string, strlen(result_string));

			new_buffer = FALSE;
			i++;
		}

		/* perform the last insert if there is data to process */
		if (out_buffer > strlen(query8)) {
			/* insert records into database */
			db_insert(&mysql, query3);
		}

		/* cleanup memory and prepare for function exit */
		if (host_id) {
			snmp_host_cleanup(host->snmp_session);
		}

		free(query3);
		free(poller_items);
		free(snmp_oids);
	}

	free(host);
	free(host_time);
	free(reindex);
	free(sysUptime);
	free(ping);

	mysql_free_result(result);

	#ifndef OLD_MYSQL   
	mysql_thread_end();
	#endif 

	mysql_close(&mysql);

	CACTID_LOG_DEBUG(("Host[%i] DEBUG: HOST COMPLETE: About to Exit Host Polling Thread Function\n", host_id));
}

/*! \fn int validate_result(char *result)
 *  \brief validates the output from the polling action is valid
 *  \param result the value to be checked for legality
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return TRUE if the result is valid, otherwise FALSE.
 *
 */
int validate_result(char *result) {
	int space_cnt = 0;
	int delim_cnt = 0;
	int i;

	/* check the easy case first */
	if (is_numeric(result)) {
		return TRUE;
	}else{
		/* it must have delimiters */
		if (((strstr(result, ":") != 0) || (strstr(result, "!") != 0))) {
			if (strstr(result, " ") == 0) {
				return TRUE;
			}

			if (strstr(result, " ") != 0) {
				const int len = strlen(result);

				for(i=0; i<len; i++) {
					if ((result[i] == ':') || (result[i] == '!')) {
						delim_cnt = delim_cnt + 1;
					}else if (result[i] == ' ') {
						space_cnt = space_cnt + 1;
					}
				}

				if (space_cnt+1 == delim_cnt) {
					return TRUE;
				}else{
					return FALSE;
				}
			}
		}
	}

	return FALSE;
}

/*! \fn char *exec_poll(host_t *current_host, char *command)
 *  \brief polls a host using a script
 *  \param current_host a pointer to the current host structure
 *  \param command the command to be executed
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return a pointer to a character buffer containing the result.
 *
 */
char *exec_poll(host_t *current_host, char *command) {
	int cmd_fd;
	int bytes_read;
	fd_set fds;
	int numfds;
	double begin_time = 0;
	double end_time = 0;
	struct timeval timeout;
	char *proc_command;
	char *result_string;

	if (!(result_string = (char *) malloc(BUFSIZE))) {
		die("ERROR: Fatal malloc error: poller.c exec_poll!\n");
	}
	memset(result_string, 0, BUFSIZE);

	/* establish timeout of 25 seconds for pipe response */
	timeout.tv_sec = set.script_timeout;
	timeout.tv_usec = 0;

	/* compensate for back slashes in arguments */
	proc_command = add_slashes(command, 2);

	/* record start time */
	begin_time = get_time_as_double();

	cmd_fd = nft_popen((char *)proc_command, "r");
	free(proc_command);

	CACTID_LOG_DEBUG(("Host[%i] DEBUG: The POPEN returned the following File Descriptor %i\n", current_host->id, cmd_fd));

	if (cmd_fd >= 0) {
		/* Initialize File Descriptors to Review for Input/Output */
		FD_ZERO(&fds);
		FD_SET(cmd_fd,&fds);

		numfds = cmd_fd + 1;

		/* wait x seonds for pipe response */
		retry:
		switch (select(numfds, &fds, NULL, NULL, &timeout)) {
		case -1:
			switch (errno) {
			case EBADF:
				CACTID_LOG(("Host[%i] ERROR: One or more of the file descriptor sets specified a file descriptor that is not a valid open file descriptor.\n", current_host->id));
				SET_UNDEFINED(result_string);
				break;
			case EINTR:
				/* take a moment */
				usleep(2000);
				
				/* record end time */
				end_time = get_time_as_double();

				/* re-establish new timeout value */
				timeout.tv_sec = rint(floor(set.script_timeout-(end_time-begin_time)));
				timeout.tv_usec = rint((set.script_timeout-(end_time-begin_time)-timeout.tv_sec)*1000000);
				
				if ((end_time - begin_time) < set.script_timeout) {
					goto retry;
				}else{
					CACTID_LOG(("WARNING: A script timed out while processing EINTR's.\n"));
					SET_UNDEFINED(result_string);
				}
				break;
			case EINVAL:
				CACTID_LOG(("Host[%i] ERROR: Possible invalid timeout specified in select() statement.\n", current_host->id));
				SET_UNDEFINED(result_string);
				break;
			default:
				CACTID_LOG(("Host[%i] ERROR: The script/command select() failed\n", current_host->id));
				SET_UNDEFINED(result_string);
				break;
			}
		case 0:
			CACTID_LOG(("Host[%i] ERROR: The POPEN timed out\n", current_host->id));
			SET_UNDEFINED(result_string);
			break;
		default:
			/* get only one line of output, we will ignore the rest */
			bytes_read = read(cmd_fd, result_string, BUFSIZE-1);
			if (bytes_read > 0) {
				result_string[bytes_read] = '\0';
			}else{
				CACTID_LOG(("Host[%i] ERROR: Empty result [%s]: '%s'\n", current_host->id, current_host->hostname, command));
				SET_UNDEFINED(result_string);
			}
		}

		/* close pipe */
		nft_pclose(cmd_fd);
	}else{
		CACTID_LOG(("Host[%i] ERROR: Problem executing POPEN [%s]: '%s'\n", current_host->id, current_host->hostname, command));
		SET_UNDEFINED(result_string);
	}

	return result_string;
}
