/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"
#include "database/persistence.h"

static char *allocate_output_query(const char *prefix, const char *failure_message) {
	char *query = malloc(MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER);
	if (query == NULL) die("%s", failure_message);
	memset(query, 0, MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER);
	strncat(query, prefix, spine_count_to_int(strlen(prefix)));
	return query;
}

static bool flush_output_query(MYSQL *mysql, int mode, char *query,
	const char *suffix, const char *prefix) {
	if (query == NULL) return TRUE;
	strncat(query, suffix, spine_count_to_int(strlen(suffix)));
	bool success = db_insert(mysql, mode, query);
	if (prefix != NULL) {
		memset(query, 0, MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER);
		strncat(query, prefix, spine_count_to_int(strlen(prefix)));
	}
	return success;
}

poll_output_buffers_t write_poll_results(MYSQL *mysql, MYSQL *mysqlr,
	const poller_queries_t *queries, const target_t *poller_items,
	int rows_processed, const char *host_time) {
	char *query3 = NULL;
	char *query12 = NULL;
	bool failed = FALSE;
	/* Escaping can double the result and the data source name. */
	char result_string[RESULTS_BUFFER * 2 + DBL_BUFSIZE + SMALL_BUFSIZE];
	int result_length;
	int new_buffer = TRUE;
	size_t out_buffer;
	MYSQL *mysqlt;
	int i;

	/* insert the query results into the database */
	query3 = allocate_output_query(queries->output, "ERROR: Fatal malloc error: poller.c query3 output buffer!");

	out_buffer = strlen(query3);

	if (set.boost.boost_redirect && set.boost.boost_enabled) {
		query12 = allocate_output_query(queries->boost_output, "ERROR: Fatal malloc error: poller.c query12 boost output buffer!");
	}

	int mode;
	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		SPINE_LOG_DEBUG(("DEBUG: Setting up writes to remote database"));
		mysqlt = mysqlr;
		mode = REMOTE;
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Setting up writes to local database"));
		mysqlt = mysql;
		mode = LOCAL;
	}

	i = 0;
	while (i < rows_processed) {
		char escaped_result[RESULTS_BUFFER * 2 + 1];
		char escaped_rrd_name[DBL_BUFSIZE];

		db_escape(mysqlt, escaped_result, sizeof(escaped_result), poller_items[i].result);
		db_escape(mysqlt, escaped_rrd_name, sizeof(escaped_rrd_name), poller_items[i].rrd_name);

		if (!format_poller_output_row(result_string, sizeof(result_string),
				poller_items[i].local_data_id,
				escaped_rrd_name,
				host_time,
				escaped_result)) {
			SPINE_LOG(("ERROR: Poller output for DS[%i] exceeds the configured result buffer and was skipped",
				poller_items[i].local_data_id));
			i++;
			continue;
		}

		result_length = spine_count_to_int(strlen(result_string));

		/* if the next element to the buffer will overflow it, write to the database */
		if ((out_buffer + result_length) >= MAX_MYSQL_BUF_SIZE) {
			if (!flush_output_query(mysqlt, mode, query3, queries->suffix, queries->output)) failed = TRUE;
			if (!flush_output_query(mysqlt, mode, query12, queries->suffix, queries->boost_output)) failed = TRUE;

			/* reset the output buffer length */
			out_buffer = strlen(query3);

			/* set binary, let the system know we are a new buffer */
			new_buffer = TRUE;
		}

		/* if this is our first pass, or we just outputted to the database, need to change the delimiter */
		result_string[0] = new_buffer ? ' ' : ',';

		strncat(query3, result_string, result_length);

		if (query12 != NULL) {
			strncat(query12, result_string, result_length);
		}

		out_buffer = out_buffer + strlen(result_string);
		new_buffer = FALSE;
		i++;
	}

	/* perform the last insert if there is data to process */
	if (out_buffer > strlen(queries->output)) {
		if (!flush_output_query(mysqlt, mode, query3, queries->suffix, NULL)) failed = TRUE;
		if (!flush_output_query(mysqlt, mode, query12, queries->suffix, NULL)) failed = TRUE;
	}
	/* MEMORY output tables can retain earlier rows after a rejected write.
	 * Confirmed partial output remains; keep due items eligible for recollection. */
	return (poll_output_buffers_t){query3, query12, failed};
}

void persist_poll_completion(MYSQL *mysql, MYSQL *mysqlr, int mode) {
	char querybuf[MEGA_BUFSIZE];
	/* push data back to the main server */
	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE && !set.poller.SQL_readonly) {
		poller_push_data_to_main();
	}

	/* update the db for |data_time| on graphs */
	if (!set.availability.ping_only) {
		if (set.poller.poller_id == 1) {
			db_insert(mysql, LOCAL, "REPLACE INTO settings (name,value) VALUES ('date',NOW())");
		}

		snprintf(querybuf, BIG_BUFSIZE, "UPDATE poller_time SET end_time=NOW() WHERE poller_id=%i AND pid=%i", set.poller.poller_id, getpid());

		if (mode == REMOTE) {
			db_insert(mysqlr, REMOTE, querybuf);
		} else {
			db_insert(mysql, LOCAL, querybuf);
		}
	}

	if (db_pool_local) {
		db_close_connection_pool(LOCAL);
	}

	if (db_pool_remote) {
		db_close_connection_pool(REMOTE);
	}
}

void persist_host_status(MYSQL *mysql, const host_t *host, bool include_system_information) {
	char update_sql[BIG_BUFSIZE];
	char escaped_last_error[BUFSIZE];
	db_escape(mysql, escaped_last_error, sizeof(escaped_last_error), host->state.status_last_error);
	if (include_system_information) {
		snprintf(update_sql, BIG_BUFSIZE, "UPDATE host "
										  "SET status='%i', status_event_count='%i', status_fail_date=FROM_UNIXTIME(%s),"
										  " status_rec_date=FROM_UNIXTIME(%s), status_last_error='%s', min_time='%f',"
										  " max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
										  " failed_polls='%i', availability='%.4f', snmp_sysDescr='%s', "
										  " snmp_sysObjectID='%s', snmp_sysUpTimeInstance='%llu', "
										  " snmp_sysContact='%s', snmp_sysName='%s', snmp_sysLocation='%s' "
										  "WHERE id='%i'",
			host->state.status,
			host->state.status_event_count,
			host->state.status_fail_date,
			host->state.status_rec_date,
			escaped_last_error,
			host->statistics.min_time,
			host->statistics.max_time,
			host->statistics.cur_time,
			host->statistics.avg_time,
			host->statistics.total_polls,
			host->statistics.failed_polls,
			host->statistics.availability,
			host->system.snmp_sysDescr,
			host->system.snmp_sysObjectID,
			host->system.snmp_sysUpTimeInstance,
			host->system.snmp_sysContact,
			host->system.snmp_sysName,
			host->system.snmp_sysLocation,
			host->id);
	} else {
		snprintf(update_sql, BIG_BUFSIZE, "UPDATE host "
										  "SET status='%i', status_event_count='%i', status_fail_date=FROM_UNIXTIME(%s),"
										  " status_rec_date=FROM_UNIXTIME(%s), status_last_error='%s', min_time='%f',"
										  " max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
										  " failed_polls='%i', availability='%.4f' "
										  "WHERE id='%i'",
			host->state.status,
			host->state.status_event_count,
			host->state.status_fail_date,
			host->state.status_rec_date,
			escaped_last_error,
			host->statistics.min_time,
			host->statistics.max_time,
			host->statistics.cur_time,
			host->statistics.avg_time,
			host->statistics.total_polls,
			host->statistics.failed_polls,
			host->statistics.availability,
			host->id);
	}
	db_insert(mysql, LOCAL, update_sql);
}
