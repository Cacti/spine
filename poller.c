/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2008 The Cacti Group                                 |
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
 | spine: a backend data gatherer for cacti                                |
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
#include "spine.h"

/*! \fn void *child(void *arg)
 *  \brief function is called via the fork command and initiates a poll of a host
 *  \param arg a pointer to an integer point to the host_id to be polled
 *
 *	This function will call the primary Spine polling function to poll a host
 *  and then reduce the number of active threads by one so that the next host
 *  can be polled.
 *
 */
void *child(void *arg) {
	int host_id = *(int *) arg;

	SPINE_LOG_DEBUG(("DEBUG: In Poller, About to Start Polling of Host"));

	poll_host(host_id);

	thread_mutex_lock(LOCK_THREAD);

	active_threads--;

	SPINE_LOG_DEBUG(("DEBUG: The Value of Active Threads is %i" ,active_threads));

	thread_mutex_unlock(LOCK_THREAD);

	/* end the thread */
	pthread_exit(0);

	exit(0);
}

/*! \fn void poll_host(int host_id)
 *  \brief core Spine function that polls a host
 *  \param host_id integer value for the host_id from the hosts table in Cacti
 *
 *	This function is core to Spine.  It will take a host_id and then poll it.
 *
 *  Prior to the poll, the system will ping the host to verifiy that it is up.
 *  In addition, the system will check to see if any reindexing of data query's
 *  is required.
 *
 *  If reindexing is required, the Cacti poller.php function will spawn that
 *  reindexing process.
 *
 *  In the case of hosts that require reindexing because of a sysUptime
 *  rollback, Spine will store an unknown (NaN) value for all objects to prevent
 *  spikes in the graphs.
 *
 *  With regard to snmp calls, if the host has multiple snmp agents running
 *  Spine will re-initialize the snmp session and poll under those new ports
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
	char query9[BUFSIZE];
	char query10[BUFSIZE];
	char sysUptime[BUFSIZE];
	char result_string[RESULTS_BUFFER+SMALL_BUFSIZE];
	int  result_length;
	char temp_result[RESULTS_BUFFER];

	int    num_rows;
	int    assert_fail = 0;
	int    spike_kill = 0;
	int    rows_processed = 0;
	int    i;
	int    j;
	int    num_oids = 0;
	int    snmp_poller_items = 0;
	size_t out_buffer;
	int    php_process;

	char *poll_result = NULL;
	char *host_time   = NULL;
	char update_sql[BUFSIZE];

	int  num_snmp_agents   = 0;
	int  last_snmp_version = 0;
	int  last_snmp_port    = 0;
	char last_snmp_community[50];
	char last_snmp_username[50];
	char last_snmp_password[50];
	char last_snmp_auth_protocol[5];
	char last_snmp_priv_passphrase[200];
	char last_snmp_priv_protocol[6];
	char last_snmp_context[65];

	/* reindex shortcuts to speed polling */
	int previous_assert_failure = FALSE;
	int last_data_query_id      = 0;
	int perform_assert          = TRUE;
	int new_buffer              = TRUE;

	reindex_t   *reindex;
	host_t      *host;
	ping_t      *ping;
	target_t    *poller_items;
	snmp_oids_t *snmp_oids;

	MYSQL     mysql;
	MYSQL_RES *result;
	MYSQL_ROW row;

	db_connect(set.dbdb, &mysql);

	/* allocate host and ping structures with appropriate values */
	if (!(host = (host_t *) malloc(sizeof(host_t)))) {
		die("ERROR: Fatal malloc error: poller.c host struct!");
	}

	if (!(ping = (ping_t *) malloc(sizeof(ping_t)))) {
		die("ERROR: Fatal malloc error: poller.c ping struct!");
	}

	if (!(reindex = (reindex_t *) malloc(sizeof(reindex_t)))) {
		die("ERROR: Fatal malloc error: poller.c reindex poll!");
	}

	sysUptime[0] = '\0';

	/* single polling interval query for items */
	snprintf(query1, BUFSIZE,
		"SELECT action, hostname, snmp_community, "
			"snmp_version, snmp_username, snmp_password, "
			"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
			"rrd_num, snmp_port, snmp_timeout, "
			"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context "
		" FROM poller_item"
		" WHERE host_id=%i"
		" ORDER BY snmp_port", host_id);

	/* host structure for uptime checks */
	snprintf(query2, BUFSIZE,
		"SELECT id, hostname, snmp_community, snmp_version, "
			"snmp_username, snmp_password, snmp_auth_protocol, "
			"snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_port, snmp_timeout, max_oids, "
			"availability_method, ping_method, ping_port, ping_timeout, ping_retries, "
			"status, status_event_count, status_fail_date, "
			"status_rec_date, status_last_error, "
			"min_time, max_time, cur_time, avg_time, "
			"total_polls, failed_polls, availability "
		" FROM host"
		" WHERE id=%i", host_id);

	/* data query structure for reindex detection */
	snprintf(query4, BUFSIZE,
		"SELECT data_query_id, action, op, assert_value, arg1"
			" FROM poller_reindex"
			" WHERE host_id=%i", host_id);

	/* multiple polling interval query for items */
	snprintf(query5, BUFSIZE,
		"SELECT action, hostname, snmp_community, "
			"snmp_version, snmp_username, snmp_password, "
			"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
			"rrd_num, snmp_port, snmp_timeout, "
			"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context "
		" FROM poller_item"
		" WHERE host_id=%i and rrd_next_step <=0"
		" ORDER by snmp_port", host_id);

	/* query to setup the next polling interval in cacti */
	snprintf(query6, BUFSIZE,
		"UPDATE poller_item"
		" SET rrd_next_step=rrd_next_step-%i"
		" WHERE host_id=%i", set.poller_interval, host_id);

	/* query to setup the next polling interval in cacti */
	snprintf(query7, BUFSIZE,
		"UPDATE poller_item"
		" SET rrd_next_step=rrd_step-%i"
		" WHERE rrd_next_step < 0 and host_id=%i",
			set.poller_interval, host_id);

	/* query to add output records to the poller output table */
	snprintf(query8, BUFSIZE,
		"INSERT INTO poller_output"
		" (local_data_id, rrd_name, time, output) VALUES");

	/* number of agent's count for single polling interval */
	snprintf(query9, BUFSIZE,
		"SELECT snmp_port, count(snmp_port)"
		" FROM poller_item"
		" WHERE host_id=%i"
		" GROUP BY snmp_port", host_id);

	/* number of agent's count for multiple polling intervals */
	snprintf(query10, BUFSIZE,
		"SELECT snmp_port, count(snmp_port)"
		" FROM poller_item"
		" WHERE host_id=%i"
		" AND rrd_next_step < 0"
		" GROUP BY snmp_port", host_id);

	/* get the host polling time */
	host_time = get_host_poll_time();

	/* initialize the ping structure variables */
	snprintf(ping->ping_status,   50,            "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "Ping not performed due to setting.");
	snprintf(ping->snmp_status,   50,            "down");
	snprintf(ping->snmp_response, SMALL_BUFSIZE, "SNMP not performed due to setting or ping result");

	/* if the host is a real host.  Note host_id=0 is not host based data source */
	if (host_id) {
		/* get data about this host */
		if ((result = db_query(&mysql, query2)) != 0) {
			num_rows = mysql_num_rows(result);

			if (num_rows != 1) {
				SPINE_LOG(("Host[%i] ERROR: Multiple Hosts with Host ID", host_id));

				mysql_free_result(result);
				mysql_close(&mysql);

				#ifndef OLD_MYSQL
				mysql_thread_end();
				#endif

				return;
			}

			/* fetch the result */
			row = mysql_fetch_row(result);

			if (row) {
				/* initialize variables first */
				host->id                      = 0;
				host->hostname[0]             = '\0';
				host->snmp_community[0]       = '\0';
				host->snmp_version            = 1;
				host->snmp_username[0]        = '\0';
				host->snmp_password[0]        = '\0';
				host->snmp_auth_protocol[0]   = '\0';
				host->snmp_priv_passphrase[0] = '\0';
				host->snmp_priv_protocol[0]   = '\0';
				host->snmp_context[0]         = '\0';
				host->snmp_port               = 161;
				host->snmp_timeout            = 500;
				host->max_oids                = 10;
				host->availability_method     = 0;
				host->ping_method             = 0;
				host->ping_port               = 23;
				host->ping_timeout            = 500;
				host->ping_retries            = 2;
				host->status                  = HOST_UP;
				host->status_event_count      = 0;
				host->status_fail_date[0]     = '\0';
				host->status_rec_date[0]      = '\0';
				host->status_last_error[0]    = '\0';
				host->min_time                = 0;
				host->max_time                = 0;
				host->cur_time                = 0;
				host->avg_time                = 0;
				host->total_polls             = 0;
				host->failed_polls            = 0;
				host->availability            = 100;

				/* populate host structure */
				host->ignore_host = FALSE;
				if (row[0]  != NULL) host->id = atoi(row[0]);

				if (row[1]  != NULL) STRNCOPY(host->hostname,             row[1]);
				if (row[2]  != NULL) STRNCOPY(host->snmp_community,       row[2]);

				if (row[3]  != NULL) host->snmp_version = atoi(row[3]);

				if (row[4]  != NULL) STRNCOPY(host->snmp_username,        row[4]);
				if (row[5]  != NULL) STRNCOPY(host->snmp_password,        row[5]);
				if (row[6]  != NULL) STRNCOPY(host->snmp_auth_protocol,   row[6]);
				if (row[7]  != NULL) STRNCOPY(host->snmp_priv_passphrase, row[7]);
				if (row[8]  != NULL) STRNCOPY(host->snmp_priv_protocol,   row[8]);
				if (row[9]  != NULL) STRNCOPY(host->snmp_context,         row[9]);

				if (row[10] != NULL) host->snmp_port           = atoi(row[10]);
				if (row[11] != NULL) host->snmp_timeout        = atoi(row[11]);
				if (row[12] != NULL) host->max_oids            = atoi(row[12]);

				if (row[13] != NULL) host->availability_method = atoi(row[13]);
				if (row[14] != NULL) host->ping_method         = atoi(row[14]);
				if (row[15] != NULL) host->ping_port           = atoi(row[15]);
				if (row[16] != NULL) host->ping_timeout        = atoi(row[16]);
				if (row[17] != NULL) host->ping_retries        = atoi(row[17]);

				if (row[18] != NULL) host->status              = atoi(row[18]);
				if (row[19] != NULL) host->status_event_count  = atoi(row[19]);

				if (row[20] != NULL) STRNCOPY(host->status_fail_date, row[20]);
				if (row[21] != NULL) STRNCOPY(host->status_rec_date,  row[21]);

				if (row[22] != NULL) STRNCOPY(host->status_last_error, row[22]);

				if (row[23] != NULL) host->min_time     = atof(row[23]);
				if (row[24] != NULL) host->max_time     = atof(row[24]);
				if (row[25] != NULL) host->cur_time     = atof(row[25]);
				if (row[26] != NULL) host->avg_time     = atof(row[26]);
				if (row[27] != NULL) host->total_polls  = atoi(row[27]);
				if (row[28] != NULL) host->failed_polls = atoi(row[28]);
				if (row[29] != NULL) host->availability = atof(row[29]);

				/* free the host result */
				mysql_free_result(result);

				if (((host->snmp_version >= 1) && (host->snmp_version <= 2) &&
					(strlen(host->snmp_community) > 0)) ||
					(host->snmp_version == 3)) {
					host->snmp_session = snmp_host_init(host->id,
						host->hostname,
						host->snmp_version,
						host->snmp_community,
						host->snmp_username,
						host->snmp_password,
						host->snmp_auth_protocol,
						host->snmp_priv_passphrase,
						host->snmp_priv_protocol,
						host->snmp_context,
						host->snmp_port,
						host->snmp_timeout);
				}else{
					host->snmp_session = NULL;
				}

				/* save snmp status data for future use */
				last_snmp_port    = host->snmp_port;
				last_snmp_version = host->snmp_version;

				STRNCOPY(last_snmp_community, host->snmp_community);
				STRNCOPY(last_snmp_username, host->snmp_username);
				STRNCOPY(last_snmp_password, host->snmp_password);
				STRNCOPY(last_snmp_context, host->snmp_context);
				STRNCOPY(last_snmp_auth_protocol, host->snmp_auth_protocol);
				STRNCOPY(last_snmp_priv_passphrase, host->snmp_priv_passphrase);
				STRNCOPY(last_snmp_priv_protocol, host->snmp_priv_protocol);

				/* perform a check to see if the host is alive by polling it's SysDesc
				 * if the host down from an snmp perspective, don't poll it.
				 * function sets the ignore_host bit */
				if ((host->availability_method == AVAIL_SNMP) &&
					(strlen(host->snmp_community) == 0) &&
					(host->snmp_version < 3)) {
					host->ignore_host = FALSE;
					update_host_status(HOST_UP, host, ping, host->availability_method);

					SPINE_LOG_MEDIUM(("Host[%i] No host availability check possible for '%s'", host->id, host->hostname));
				}else{
					if (ping_host(host, ping) == HOST_UP) {
						host->ignore_host = FALSE;
						update_host_status(HOST_UP, host, ping, host->availability_method);
					}else{
						host->ignore_host = TRUE;
						update_host_status(HOST_DOWN, host, ping, host->availability_method);
					}
				}

				/* update host table */
				snprintf(update_sql, BUFSIZE, "UPDATE host "
					"SET status='%i', status_event_count='%i', status_fail_date='%s',"
						" status_rec_date='%s', status_last_error='%s', min_time='%f',"
						" max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
						" failed_polls='%i', availability='%.4f' "
					"WHERE id='%i'",
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
				SPINE_LOG(("Host[%i] ERROR: Could MySQL Returned a Null Host Result", host->id));
				num_rows = 0;
				host->ignore_host = TRUE;
			}
		}else{
			num_rows = 0;
			host->ignore_host = TRUE;
		}
	}else{
		host->id = 0;
		host->ignore_host = FALSE;
	}

	/* do the reindex check for this host if not script based */
	if ((!host->ignore_host) && (host_id)) {
		if ((result = db_query(&mysql, query4)) != 0) {
			num_rows = mysql_num_rows(result);

			if (num_rows > 0) {
				SPINE_LOG_DEBUG(("Host[%i] RECACHE: Processing %i items in the auto reindex cache for '%s'", host->id, num_rows, host->hostname));

				while ((row = mysql_fetch_row(result))) {
					assert_fail = FALSE;

					/* initialize the reindex struction */
					reindex->data_query_id   = 0;
					reindex->action          = -1;
					reindex->op[0]           = '\0';
					reindex->assert_value[0] = '\0';
					reindex->arg1[0]         = '\0';

					if (row[0] != NULL) reindex->data_query_id = atoi(row[0]);
					if (row[1] != NULL) reindex->action        = atoi(row[1]);

					if (row[2] != NULL) snprintf(reindex->op,           sizeof(reindex->op),           "%s", row[2]);
					if (row[3] != NULL) snprintf(reindex->assert_value, sizeof(reindex->assert_value), "%s", row[3]);
					if (row[4] != NULL) snprintf(reindex->arg1,         sizeof(reindex->arg1),         "%s", row[4]);

					/* shortcut assertion checks if a data query reindex has already been queued */
					if ((last_data_query_id == reindex->data_query_id) &&
						(!previous_assert_failure)) {
						perform_assert = TRUE;
					}else if (last_data_query_id != reindex->data_query_id) {
						last_data_query_id = reindex->data_query_id;
						perform_assert = TRUE;
						previous_assert_failure = FALSE;
					}else{
						perform_assert = FALSE;
					}

					if (perform_assert) {
						switch(reindex->action) {
						case POLLER_ACTION_SNMP: /* snmp */
							/* check to see if you are checking uptime */
							if (strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0")) {
								if (strlen(sysUptime) > 0) {
									if (!(poll_result = (char *) malloc(BUFSIZE))) {
										die("ERROR: Fatal malloc error: poller.c poll_result");
									}
									poll_result[0] = '\0';

									snprintf(poll_result, BUFSIZE, "%s", sysUptime);
								}else{
									poll_result = snmp_get(host, reindex->arg1);
									snprintf(sysUptime, BUFSIZE, "%s", poll_result);
								}
							}else{
								poll_result = snmp_get(host, reindex->arg1);
							}

							break;
						case POLLER_ACTION_SCRIPT: /* script (popen) */
							poll_result = exec_poll(host, reindex->arg1);

							break;
						default:
							SPINE_LOG(("Host[%i] ERROR: Unknown Assert Action!", host->id));
							poll_result = strdup("U");
						}

						if (!(query3 = (char *)malloc(BUFSIZE))) {
							die("ERROR: Fatal malloc error: poller.c reindex insert!");
						}
						query3[0] = '\0';

						/* assume ok if host is up and result wasn't obtained */
						if ((IS_UNDEFINED(poll_result)) || (STRIMATCH(poll_result, "No Such Instance"))) {
							assert_fail = FALSE;
						}else if ((!strcmp(reindex->op, "=")) && (strcmp(reindex->assert_value,poll_result))) {
							SPINE_LOG_HIGH(("Host[%i] ASSERT: '%s' .eq. '%s' failed. Recaching host '%s', data query #%i", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

							snprintf(query3, BUFSIZE, "REPLACE INTO poller_command (poller_id, time, action,command) values (0, NOW(), %i, '%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
							db_insert(&mysql, query3);
							assert_fail = TRUE;
							previous_assert_failure = TRUE;
						}else if ((!strcmp(reindex->op, ">")) && (strtoll(reindex->assert_value, (char **)NULL, 10) < strtoll(poll_result, (char **)NULL, 10))) {
							SPINE_LOG_HIGH(("Host[%i] ASSERT: '%s' .gt. '%s' failed. Recaching host '%s', data query #%i", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

							snprintf(query3, BUFSIZE, "REPLACE INTO poller_command (poller_id, time, action, command) values (0, NOW(), %i, '%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
							db_insert(&mysql, query3);
							assert_fail = TRUE;
							previous_assert_failure = TRUE;
						}else if ((!strcmp(reindex->op, "<")) && (strtoll(reindex->assert_value, (char **)NULL, 10) > strtoll(poll_result, (char **)NULL, 10))) {
							SPINE_LOG_HIGH(("Host[%i] ASSERT: '%s' .lt. '%s' failed. Recaching host '%s', data query #%i", host->id, reindex->assert_value, poll_result, host->hostname, reindex->data_query_id));

							snprintf(query3, BUFSIZE, "REPLACE INTO poller_command (poller_id, time, action, command) values (0, NOW(), %i, '%i:%i')", POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);
							db_insert(&mysql, query3);
							assert_fail = TRUE;
							previous_assert_failure = TRUE;
						}

						/* update 'poller_reindex' with the correct information if:
						 * 1) the assert fails
						 * 2) the OP code is > or < meaning the current value could have changed without causing
						 *     the assert to fail */
						if ((assert_fail) || (!strcmp(reindex->op, ">")) || (!strcmp(reindex->op, "<"))) {
							snprintf(query3, BUFSIZE, "UPDATE poller_reindex SET assert_value='%s' WHERE host_id='%i' AND data_query_id='%i' and arg1='%s'", poll_result, host_id, reindex->data_query_id, reindex->arg1);
							db_insert(&mysql, query3);

							if ((assert_fail) &&
								((!strcmp(reindex->op, "<")) || (!strcmp(reindex->arg1,".1.3.6.1.2.1.1.3.0")))) {
								spike_kill = TRUE;
								SPINE_LOG_MEDIUM(("Host[%i] NOTICE: Spike Kill in Effect for '%s'", host_id, host->hostname));
							}
						}

						free(query3);
						free(poll_result);
					}
				}
			}else{
				SPINE_LOG_HIGH(("Host[%i] Host has no information for recache.", host->id));
			}

			/* free the host result */
			mysql_free_result(result);
		}else{
			SPINE_LOG(("Host[%i] ERROR: Recache Query Returned Null Result!", host->id));
		}
	}

	/* calculate the number of poller items to poll this cycle */
	num_rows = 0;
	if (set.poller_interval == 0) {
		/* get the number of agents */
		if ((result = db_query(&mysql, query9)) != 0) {
			num_snmp_agents = mysql_num_rows(result);
			mysql_free_result(result);

			/* get the poller items */
			if ((result = db_query(&mysql, query1)) != 0) {
				num_rows = mysql_num_rows(result);
			}else{
				SPINE_LOG(("Host[%i] ERROR: Unable to Retrieve Rows due to Null Result!", host->id));
			}
		}else{
			SPINE_LOG(("Host[%i] ERROR: Agent Count Query Returned Null Result!", host->id));
		}
	}else{
		/* get the number of agents */
		if ((result = db_query(&mysql, query10)) != 0) {
			num_snmp_agents = (int)mysql_num_rows(result);
			mysql_free_result(result);

			/* get the poller items */
			if ((result = db_query(&mysql, query5)) != 0) {
				num_rows = mysql_num_rows(result);

				/* update poller_items table for next polling interval */
				db_query(&mysql, query6);
				db_query(&mysql, query7);
			}else{
				SPINE_LOG(("Host[%i] ERROR: Unable to Retrieve Rows due to Null Result!", host->id));
			}
		}else{
			SPINE_LOG(("Host[%i] ERROR: Agent Count Query Returned Null Result!", host->id));
		}
	}

	if (num_rows > 0) {
		/* retreive each hosts polling items from poller cache and load into array */
		poller_items = (target_t *) calloc(num_rows, sizeof(target_t));

		i = 0;
		while ((row = mysql_fetch_row(result))) {
			/* initialize monitored object */
			poller_items[i].target_id                = 0;
			poller_items[i].action                   = -1;
			poller_items[i].hostname[0]              = '\0';
			poller_items[i].snmp_community[0]        = '\0';
			poller_items[i].snmp_version             = 1;
			poller_items[i].snmp_username[0]         = '\0';
			poller_items[i].snmp_password[0]         = '\0';
			poller_items[i].snmp_auth_protocol[0]    = '\0';
			poller_items[i].snmp_priv_passphrase[0]  = '\0';
			poller_items[i].snmp_priv_protocol[0]    = '\0';
			poller_items[i].snmp_context[0]          = '\0';
			poller_items[i].snmp_port                = 161;
			poller_items[i].snmp_timeout             = 500;
			poller_items[i].rrd_name[0]              = '\0';
			poller_items[i].rrd_path[0]              = '\0';
			poller_items[i].arg1[0]                  = '\0';
			poller_items[i].arg2[0]                  = '\0';
			poller_items[i].arg3[0]                  = '\0';
			poller_items[i].local_data_id            = 0;
			poller_items[i].rrd_num                  = 0;

			if (row[0] != NULL)  poller_items[i].action = atoi(row[0]);

			if (row[1] != NULL)  snprintf(poller_items[i].hostname, sizeof(poller_items[i].hostname), "%s", row[1]);
			if (row[2] != NULL)  snprintf(poller_items[i].snmp_community, sizeof(poller_items[i].snmp_community), "%s", row[2]);

			if (row[3] != NULL)  poller_items[i].snmp_version = atoi(row[3]);

			if (row[4] != NULL)  snprintf(poller_items[i].snmp_username, sizeof(poller_items[i].snmp_username), "%s", row[4]);
			if (row[5] != NULL)  snprintf(poller_items[i].snmp_password, sizeof(poller_items[i].snmp_password), "%s", row[5]);

			if (row[6]  != NULL) snprintf(poller_items[i].rrd_name,      sizeof(poller_items[i].rrd_name),      "%s", row[6]);
			if (row[7]  != NULL) snprintf(poller_items[i].rrd_path,      sizeof(poller_items[i].rrd_path),      "%s", row[7]);
			if (row[8]  != NULL) snprintf(poller_items[i].arg1,          sizeof(poller_items[i].arg1),          "%s", row[8]);
			if (row[9]  != NULL) snprintf(poller_items[i].arg2,          sizeof(poller_items[i].arg2),          "%s", row[9]);
			if (row[10] != NULL) snprintf(poller_items[i].arg3,          sizeof(poller_items[i].arg3),          "%s", row[10]);

			if (row[11] != NULL) poller_items[i].local_data_id = atoi(row[11]);

			if (row[12] != NULL) poller_items[i].rrd_num       = atoi(row[12]);
			if (row[13] != NULL) poller_items[i].snmp_port     = atoi(row[13]);
			if (row[14] != NULL) poller_items[i].snmp_timeout  = atoi(row[14]);

			if (row[15] != NULL)  snprintf(poller_items[i].snmp_auth_protocol,
				sizeof(poller_items[i].snmp_auth_protocol), "%s", row[15]);
			if (row[16] != NULL)  snprintf(poller_items[i].snmp_priv_passphrase,
				sizeof(poller_items[i].snmp_priv_passphrase), "%s", row[16]);
			if (row[17] != NULL)  snprintf(poller_items[i].snmp_priv_protocol,
				sizeof(poller_items[i].snmp_priv_protocol), "%s", row[17]);
			if (row[18] != NULL)  snprintf(poller_items[i].snmp_context,
				sizeof(poller_items[i].snmp_context), "%s", row[18]);

			SET_UNDEFINED(poller_items[i].result);

			if (poller_items[i].action == POLLER_ACTION_SNMP) {
				snmp_poller_items++;
			}

			i++;
		}

		/* free the mysql result */
		mysql_free_result(result);

		/* create an array for snmp oids */
		snmp_oids = (snmp_oids_t *) calloc(host->max_oids, sizeof(snmp_oids_t));

		/* initialize all the memory to insure we don't get issues */
		memset(snmp_oids, 0, sizeof(snmp_oids_t)*host->max_oids);

		/* log an informative message */
		SPINE_LOG_MEDIUM(("Host[%i] NOTE: There are '%i' Polling Items for this Host", host_id, num_rows));

		i = 0;
		while ((i < num_rows) && (!host->ignore_host)) {
			if (!host->ignore_host) {
				switch(poller_items[i].action) {
				case POLLER_ACTION_SNMP: /* raw SNMP poll */
					/* initialize or reinitialize snmp as required */
					if (!host->snmp_session) {
						last_snmp_port = poller_items[i].snmp_port;
						last_snmp_version = poller_items[i].snmp_version;

						STRNCOPY(last_snmp_community,       poller_items[i].snmp_community);
						STRNCOPY(last_snmp_username,        poller_items[i].snmp_username);
						STRNCOPY(last_snmp_password,        poller_items[i].snmp_password);
						STRNCOPY(last_snmp_auth_protocol,   poller_items[i].snmp_auth_protocol);
						STRNCOPY(last_snmp_priv_passphrase, poller_items[i].snmp_priv_passphrase);
						STRNCOPY(last_snmp_priv_protocol,   poller_items[i].snmp_priv_protocol);
						STRNCOPY(last_snmp_context,         poller_items[i].snmp_context);

						host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname,
							poller_items[i].snmp_version, poller_items[i].snmp_community,
							poller_items[i].snmp_username, poller_items[i].snmp_password,
							poller_items[i].snmp_auth_protocol, poller_items[i].snmp_priv_passphrase,
							poller_items[i].snmp_priv_protocol, poller_items[i].snmp_context,
							poller_items[i].snmp_port, poller_items[i].snmp_timeout);
					}

					/* catch snmp initialization issues */
					if (!host->snmp_session) {
						host->ignore_host = TRUE;
						break;
					}

					/* some snmp data changed from poller item to poller item.  therefore, poll host and store data */
					if ((last_snmp_port != poller_items[i].snmp_port) ||
						(last_snmp_version != poller_items[i].snmp_version) ||
						(strcmp(last_snmp_community,       poller_items[i].snmp_community)       != 0) ||
						(strcmp(last_snmp_username,        poller_items[i].snmp_username)        != 0) ||
						(strcmp(last_snmp_password,        poller_items[i].snmp_password)        != 0) ||
						(strcmp(last_snmp_auth_protocol,   poller_items[i].snmp_auth_protocol)   != 0) ||
						(strcmp(last_snmp_priv_passphrase, poller_items[i].snmp_priv_passphrase) != 0) ||
						(strcmp(last_snmp_priv_protocol,   poller_items[i].snmp_priv_protocol)   != 0) ||
						(strcmp(last_snmp_context,         poller_items[i].snmp_context)         != 0)) {

						if (num_oids > 0) {
							snmp_get_multi(host, snmp_oids, num_oids);

							for (j = 0; j < num_oids; j++) {
								if (host->ignore_host) {
									SPINE_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
									SET_UNDEFINED(snmp_oids[j].result);
								}else if ((is_numeric(snmp_oids[j].result)) ||
									(is_multipart_output(snmp_oids[j].result)) ||
									(is_hexadecimal(snmp_oids[j].result, TRUE))) {
									/* continue */
								}else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
									(STRIMATCH(snmp_oids[j].result, "Nan"))) {
									/* is valid output, continue */
								}else{
									/* remove double or single quotes from string */
									snprintf(temp_result, RESULTS_BUFFER, "%s", strip_alpha(trim(snmp_oids[j].result)));
									snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

									/* detect erroneous non-numeric result */
									if (!validate_result(snmp_oids[j].result)) {
										SET_UNDEFINED(snmp_oids[j].result);
									}
								}

								snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

								SPINE_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
							}

							/* reset num_snmps */
							num_oids = 0;

							/* initialize all the memory to insure we don't get issues */
							memset(snmp_oids, 0, sizeof(snmp_oids_t)*host->max_oids);
						}

						snmp_host_cleanup(host->snmp_session);
						host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname,
												poller_items[i].snmp_version, poller_items[i].snmp_community,
												poller_items[i].snmp_username, poller_items[i].snmp_password,
												poller_items[i].snmp_auth_protocol, poller_items[i].snmp_priv_passphrase,
												poller_items[i].snmp_priv_protocol, poller_items[i].snmp_context,
												poller_items[i].snmp_port, poller_items[i].snmp_timeout);

						last_snmp_port    = poller_items[i].snmp_port;
						last_snmp_version = poller_items[i].snmp_version;

						STRNCOPY(last_snmp_community,       poller_items[i].snmp_community);
						STRNCOPY(last_snmp_username,        poller_items[i].snmp_username);
						STRNCOPY(last_snmp_password,        poller_items[i].snmp_password);
						STRNCOPY(last_snmp_auth_protocol,   poller_items[i].snmp_auth_protocol);
						STRNCOPY(last_snmp_priv_passphrase, poller_items[i].snmp_priv_passphrase);
						STRNCOPY(last_snmp_priv_protocol,   poller_items[i].snmp_priv_protocol);
						STRNCOPY(last_snmp_context,         poller_items[i].snmp_context);
					}

					if (num_oids >= host->max_oids) {
						snmp_get_multi(host, snmp_oids, num_oids);

						for (j = 0; j < num_oids; j++) {
							if (host->ignore_host) {
								SPINE_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
								SET_UNDEFINED(snmp_oids[j].result);
							}else if ((is_numeric(snmp_oids[j].result)) ||
								(is_multipart_output(snmp_oids[j].result)) ||
								(is_hexadecimal(snmp_oids[j].result, TRUE))) {
								/* continue */
							}else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
								(STRIMATCH(snmp_oids[j].result, "Nan"))) {
								/* is valid output, continue */
							}else{
								/* remove double or single quotes from string */
								snprintf(temp_result, RESULTS_BUFFER, "%s", strip_alpha(trim(snmp_oids[j].result)));
								snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

								/* detect erroneous non-numeric result */
								if (!validate_result(snmp_oids[j].result)) {
									SET_UNDEFINED(snmp_oids[j].result);
								}
							}

							snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

							SPINE_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));

							if (poller_items[snmp_oids[j].array_position].result != NULL) {
								/* insert a NaN in place of the actual value if the snmp agent restarts */
								if ((spike_kill) && (!strstr(poller_items[snmp_oids[j].array_position].result,":"))) {
									SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
								}
							}
						}

						/* reset num_snmps */
						num_oids = 0;

						/* initialize all the memory to insure we don't get issues */
						memset(snmp_oids, 0, sizeof(snmp_oids_t)*host->max_oids);
					}

					snprintf(snmp_oids[num_oids].oid, sizeof(snmp_oids[num_oids].oid), "%s", poller_items[i].arg1);
					snmp_oids[num_oids].array_position = i;
					num_oids++;

					break;
				case POLLER_ACTION_SCRIPT: /* execute script file */
					poll_result = exec_poll(host, poller_items[i].arg1);

					/* remove double or single quotes from string */
					if ((is_numeric(poll_result)) ||
						(is_multipart_output(poll_result)) ||
						(is_hexadecimal(poll_result, TRUE))) {
						snprintf(poller_items[i].result, RESULTS_BUFFER, "%s", poll_result);
					}else{
						/* remove double or single quotes from string */
						snprintf(temp_result, RESULTS_BUFFER, "%s", strip_alpha(trim(poll_result)));
						snprintf(poller_items[i].result , RESULTS_BUFFER, "%s", temp_result);

						/* detect erroneous result. can be non-numeric */
						if (!validate_result(poller_items[i].result)) {
							SET_UNDEFINED(poller_items[i].result);
						}
					}

					free(poll_result);

					SPINE_LOG_MEDIUM(("Host[%i] DS[%i] SCRIPT: %s, output: %s", host_id, poller_items[i].local_data_id, poller_items[i].arg1, poller_items[i].result));

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
					if ((is_numeric(poll_result)) ||
						(is_multipart_output(poll_result)) ||
						(is_hexadecimal(poll_result, TRUE))) {
						snprintf(poller_items[i].result, RESULTS_BUFFER, "%s", poll_result);
					}else{
						/* remove double or single quotes from string */
						snprintf(temp_result, RESULTS_BUFFER, "%s", strip_alpha(trim(poll_result)));
						snprintf(poller_items[i].result , RESULTS_BUFFER, "%s", temp_result);

						/* detect erroneous result. can be non-numeric */
						if (!validate_result(poller_items[i].result)) {
							SET_UNDEFINED(poller_items[i].result);
						}
					}

					free(poll_result);

					SPINE_LOG_MEDIUM(("Host[%i] DS[%i] SS[%i] SERVER: %s, output: %s", host_id, poller_items[i].local_data_id, php_process, poller_items[i].arg1, poller_items[i].result));

					if (poller_items[i].result != NULL) {
						/* insert a NaN in place of the actual value if the snmp agent restarts */
						if ((spike_kill) && (!strstr(poller_items[i].result,":"))) {
							SET_UNDEFINED(poller_items[i].result);
						}
					}

					break;
				default: /* unknown action, generate error */
					SPINE_LOG(("Host[%i] DS[%i] ERROR: Unknown Poller Action: %s", host_id, poller_items[i].local_data_id, poller_items[i].arg1));

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
					SPINE_LOG(("Host[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
					SET_UNDEFINED(snmp_oids[j].result);
				}else if ((is_numeric(snmp_oids[j].result)) ||
					(is_multipart_output(snmp_oids[j].result)) ||
					(is_hexadecimal(snmp_oids[j].result, TRUE))) {
					/* continue */
				}else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
					(STRIMATCH(snmp_oids[j].result, "Nan"))) {
					/* is valid output, continue */
				}else{
					/* remove double or single quotes from string */
					snprintf(temp_result, RESULTS_BUFFER, "%s", strip_alpha(trim(snmp_oids[j].result)));
					snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

					/* detect erroneous non-numeric result */
					if (!validate_result(snmp_oids[j].result)) {
						SET_UNDEFINED(snmp_oids[j].result);
					}
				}

				snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

				SPINE_LOG_MEDIUM(("Host[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));

				if (poller_items[snmp_oids[j].array_position].result != NULL) {
					/* insert a NaN in place of the actual value if the snmp agent restarts */
					if ((spike_kill) && (!strstr(poller_items[snmp_oids[j].array_position].result,":"))) {
						SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
					}
				}
			}
		}

		/* insert the query results into the database */
		if (!(query3 = (char *)malloc(MAX_MYSQL_BUF_SIZE+RESULTS_BUFFER))) {
			die("ERROR: Fatal malloc error: poller.c query3 oids!");
		}
		query3[0] = '\0';

		strncat(query3, query8, strlen(query8));
		out_buffer = strlen(query3);

		i = 0;
		while (i < rows_processed) {
			snprintf(result_string, RESULTS_BUFFER+SMALL_BUFSIZE, " (%i,'%s','%s','%s')",
				poller_items[i].local_data_id,
				poller_items[i].rrd_name,
				host_time,
				poller_items[i].result);

			result_length = strlen(result_string);

			/* if the next element to the buffer will overflow it, write to the database */
			if ((out_buffer + result_length) >= MAX_MYSQL_BUF_SIZE) {
				/* insert the record */
				db_insert(&mysql, query3);

				/* re-initialize the query buffer */
				query3[0] = '\0';
				strncat(query3, query8, strlen(query8));

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

			strncat(query3, result_string, strlen(result_string));
			out_buffer = out_buffer + strlen(result_string);
			new_buffer = FALSE;
			i++;
		}

		/* perform the last insert if there is data to process */
		if (out_buffer > strlen(query8)) {
			/* insert records into database */
			db_insert(&mysql, query3);
		}

		/* cleanup memory and prepare for function exit */
		if (host->snmp_session) {
			snmp_host_cleanup(host->snmp_session);
		}

		free(query3);
		free(poller_items);
		free(snmp_oids);
	}

	free(host);
	free(host_time);
	free(reindex);
	free(ping);

	mysql_close(&mysql);

	#ifndef OLD_MYSQL
	mysql_thread_end();
	#endif

	SPINE_LOG_DEBUG(("Host[%i] DEBUG: HOST COMPLETE: About to Exit Host Polling Thread Function", host_id));
}

/*! \fn int is_multipart_output(char *result)
 *  \brief validates the output syntax is a valid name value pair syntax
 *  \param result the value to be checked for legality
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return TRUE if the result is valid, otherwise FALSE.
 *
 */
int is_multipart_output(char *result) {
	int space_cnt = 0;
	int delim_cnt = 0;
	int i;

	/* check the easy cases first */
	if (result) {
		/* it must have delimiters */
		if ((strstr(result, ":")) || (strstr(result, "!"))) {
			if (!strstr(result, " ")) {
				return TRUE;
			}else{
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
	/* check the easy cases first */
	if (result) {
		if (is_numeric(result)) {
			return TRUE;
		}else{
			if (is_multipart_output(result)) {
				return TRUE;
			}else{
				return FALSE;
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
	extern int active_scripts;
	int cmd_fd;
	int pid;
	int close_fd = TRUE;
	FILE *fd;
	int bytes_read;
	fd_set fds;
	double begin_time = 0;
	double end_time = 0;
	double script_timeout;
	struct timeval timeout;
	char *proc_command;
	char *result_string;

	/* compensate for back slashes in arguments */
	#if defined(__CYGWIN__)
	proc_command = add_slashes(command, 2);
	#else
	proc_command = command;
	#endif

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: poller.c exec_poll!");
	}
	memset(result_string, 0, RESULTS_BUFFER);

	/* set script timeout as double */
	script_timeout = set.script_timeout;

	/* establish timeout of 25 seconds for pipe response */
	timeout.tv_sec = set.script_timeout;
	timeout.tv_usec = 0;

	/* record start time */
	begin_time = get_time_as_double();

	/* don't run too many scripts, operating systems do not like that. */
	while (1) {
		thread_mutex_lock(LOCK_PIPE);
		if (active_scripts > MAX_SIMULTANEOUS_SCRIPTS) {
			thread_mutex_unlock(LOCK_PIPE);
			usleep(50000);
		}else{
			active_scripts++;
			thread_mutex_unlock(LOCK_PIPE);
			break;
		}
	}

	#ifdef USING_NIFTY
	cmd_fd = nft_popen((char *)proc_command, "r");
	#else
	fd = popen((char *)proc_command, "r");
	cmd_fd = fileno(fd);
	#endif

	SPINE_LOG_DEBUG(("Host[%i] DEBUG: The POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));

	if (cmd_fd > 0) {
		/* Initialize File Descriptors to Review for Input/Output */
		FD_ZERO(&fds);
		FD_SET(cmd_fd, &fds);

		/* wait x seonds for pipe response */
		retry:
		switch (select(FD_SETSIZE, &fds, NULL, NULL, &timeout)) {
		case -1:
			switch (errno) {
			case EBADF:
				SPINE_LOG(("Host[%i] ERROR: One or more of the file descriptor sets specified a file descriptor that is not a valid open file descriptor.", current_host->id));
				SET_UNDEFINED(result_string);
				close_fd = FALSE;
				break;
			case EAGAIN:
			case EINTR:
				#ifndef SOLAR_THREAD
				/* take a moment */
				usleep(2000);
				#endif

				/* record end time */
				end_time = get_time_as_double();

				/* re-establish new timeout value */
				timeout.tv_sec = rint(floor(script_timeout-(end_time-begin_time)));
				timeout.tv_usec = rint((script_timeout-(end_time-begin_time)-timeout.tv_sec)*1000000);

				if ((end_time - begin_time) < set.script_timeout) {
					goto retry;
				}else{
					SPINE_LOG(("WARNING: A script timed out while processing EINTR's."));
					SET_UNDEFINED(result_string);
					close_fd = FALSE;
				}
				break;
			case EINVAL:
				SPINE_LOG(("Host[%i] ERROR: Possible invalid timeout specified in select() statement.", current_host->id));
				SET_UNDEFINED(result_string);
				close_fd = FALSE;
				break;
			default:
				SPINE_LOG(("Host[%i] ERROR: The script/command select() failed", current_host->id));
				SET_UNDEFINED(result_string);
				close_fd = FALSE;
				break;
			}
		case 0:
			SPINE_LOG(("Host[%i] ERROR: The POPEN timed out", current_host->id));

			#ifdef USING_NIFTY
			pid = nft_pchild(cmd_fd);
			kill(pid, SIGTERM);
			#else
			close_fd = FALSE;
			#endif

			SET_UNDEFINED(result_string);
			break;
		default:
			/* get only one line of output, we will ignore the rest */
			bytes_read = read(cmd_fd, result_string, RESULTS_BUFFER-1);
			if (bytes_read > 0) {
				result_string[bytes_read] = '\0';
			}else{
				SPINE_LOG(("Host[%i] ERROR: Empty result [%s]: '%s'", current_host->id, current_host->hostname, command));
				SET_UNDEFINED(result_string);
			}
		}

		/* close pipe */
		#ifdef USING_NIFTY
		nft_pclose(cmd_fd);
		#else
		/* we leave the old fd open if it timed out */
		if (close_fd) {
			pclose(fd);
		}
		#endif
	}else{
		SPINE_LOG(("Host[%i] ERROR: Problem executing POPEN [%s]: '%s'", current_host->id, current_host->hostname, command));
		SET_UNDEFINED(result_string);
	}

	#if defined(__CYGWIN__)
	free(proc_command);
	#endif

	/* reduce the active script count */
	thread_mutex_lock(LOCK_PIPE);
	active_scripts--;
	thread_mutex_unlock(LOCK_PIPE);

	return result_string;
}
