/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

int format_poller_output_row(char *output, size_t output_size,
		int local_data_id, const char *escaped_rrd_name,
		const char *host_time, const char *escaped_result) {
	const char *timep;
	int decimal_points = 0;
	int digits = 0;
	int written;

	if (output == NULL || output_size == 0 || escaped_rrd_name == NULL ||
	    host_time == NULL || host_time[0] == '\0' || escaped_result == NULL) {
		return FALSE;
	}

	/* host_time is emitted outside SQL quotes. Accept the integer timestamps
	 * Spine generates and a single fractional part, but no SQL syntax. */
	for (timep = host_time; *timep != '\0'; timep++) {
		if (*timep == '.') {
			decimal_points++;
			if (decimal_points > 1) {
				return FALSE;
			}
		} else if (!isdigit((unsigned char)*timep)) {
			return FALSE;
		} else {
			digits++;
		}
	}
	if (digits == 0) {
		return FALSE;
	}

	written = snprintf(output, output_size,
		" (%i, '%s', FROM_UNIXTIME(%s), '%s')",
		local_data_id, escaped_rrd_name, host_time, escaped_result);

	return written >= 0 && (size_t)written < output_size;
}

void child_cleanup(void *arg) {
	poller_thread_t poller_details = *(poller_thread_t*) arg;

	SPINE_LOG_DEVDBG(("Device[%i] HT[%i] DEBUG: The Device Thread has cleaned up.", poller_details.host_id, poller_details.host_thread));

	free(arg);
	child_cleanup_thread(NULL);
}

void child_cleanup_thread(void *arg) {
	(void)arg;
	int a_threads_value;
	a_threads_value = spine_permits_available(&available_threads) + 1;

	SPINE_LOG_DEVDBG(("DEBUG: Available Threads is %i (%i outstanding)", a_threads_value, set.poller.threads - a_threads_value));
	/* Releasing the permit publishes completion: no shared state is used after it. */
	spine_permits_release(&available_threads);
}

void child_cleanup_script(void *arg) {
	(void)arg;
	spine_permits_release(&available_scripts);

	int a_scripts_value;
	a_scripts_value = spine_permits_available(&available_scripts);

	SPINE_LOG_DEVDBG(("DEBUG: Available Scripts is %i (%i outstanding)", a_scripts_value, MAX_SIMULTANEOUS_SCRIPTS - a_scripts_value));
}

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
	pthread_cleanup_push(child_cleanup, arg);

	int host_errors = 0;
	poller_thread_t poller_details = *(poller_thread_t*)arg;
	/* Allows main thread to proceed with creation of other threads. */
	spine_permits_release(poller_details.thread_init_sem);
	SPINE_LOG_DEVICE(poller_details.host_id, POLLER_VERBOSITY_DEBUG, ("Device[%i] HT[%i] DEBUG: In Poller, About to Start Polling", poller_details.host_id, poller_details.host_thread));
	if (mysql_thread_init() != 0) die("ERROR: Unable to initialize polling thread database state");
	poll_host(&poller_details, &host_errors);

	pthread_cleanup_pop(1);

	/* end the thread */
	pthread_exit(0);
}

/*! \fn void poll_host(const poller_thread_t *work, int *host_errors)
 *  \brief core Spine function that polls a host
 *  \param work borrowed polling instructions, valid until the synchronous call returns
 *  \param host_errors receives the count of invalid polling results
 *
 *  This function is core to Spine. It takes a host_id and polls it, first
 *  checking reachability and any required data-query reindexing.
 */
/*! \fn int poller_store_hex_result(char *result, size_t result_size, const char *hex, int *errors)
 *  \brief convert a hexadecimal poll result and account for rejected values
 *
 *  result must name at least two writable bytes so failures can be represented
 *  by the normal undefined marker. Invalid output arguments are rejected
 *  without modifying memory whose writable extent cannot be established.
 */
int poller_store_hex_result(char *result, size_t result_size, const char *hex, int *errors) {
	unsigned long long value;
	int written;

	if (result == NULL || result_size < 2 || hex == NULL) {
		if (errors != NULL) {
			(*errors)++;
		}
		return FALSE;
	}

	if (!hex2dec(hex, &value)) {
		/* An over-wide or malformed OctetString is unusable poll data. */
		SET_UNDEFINED(result);
		if (errors != NULL) {
			(*errors)++;
		}
		return FALSE;
	}

	written = snprintf(result, result_size, "%llu", value);
	if (written < 0 || (size_t) written >= result_size) {
		SET_UNDEFINED(result);
		if (errors != NULL) {
			(*errors)++;
		}
		return FALSE;
	}

	return TRUE;
}

enum poll_result_status normalize_poll_result(char *result, bool snmp) {
	if (IS_UNDEFINED(result)) return POLL_RESULT_UNDEFINED;
	if (is_numeric(result) || is_multipart_output(snmp ? result : trim(result))) {
		return POLL_RESULT_VALID;
	}
	if (is_hexadecimal(result, TRUE)) {
		/* Values wider than 64 bits become U and count as collection errors. */
		return poller_store_hex_result(result, RESULTS_BUFFER, result, NULL) ? POLL_RESULT_VALID : POLL_RESULT_INVALID;
	}
	if (snmp && (STRIMATCH(result, "U") || STRIMATCH(result, "Nan"))) {
		return POLL_RESULT_UNDEFINED;
	}
	/* trim a non-numeric prefix or suffix, then validate below */
	char normalized[RESULTS_BUFFER];
	snprintf(normalized, sizeof(normalized), "%s", strip_alpha(result));
	strncopy(result, normalized, RESULTS_BUFFER);
	return validate_result(result) ? POLL_RESULT_VALID : POLL_RESULT_INVALID;
}

typedef struct poll_error_context {
	char *buffer;
	int *size;
	int *count;
	int *errors;
	int host_id;
	int thread_id;
} poll_error_context_t;

static void record_result_error(const poll_error_context_t *context, const host_t *host,
		const target_t *item, const char *result, bool snmp) {
	buffer_output_errors(context->buffer, context->size, context->count,
		context->host_id, context->thread_id, item->local_data_id, false);
	(*context->errors)++;
	if (set.logging.spine_log_level != 2) return;
	if (snmp) {
		SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
			context->host_id, context->thread_id, item->local_data_id,
			host->snmp.profile.version, host->hostname, item->rrd_name, item->arg1, result));
	} else {
		char script[SMALL_BUFSIZE];

		php_command_script(item->arg1, script, sizeof(script));
		SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SCRIPT: %s, output: %s",
			context->host_id, context->thread_id, item->local_data_id, script, result));
	}
}

static void normalize_snmp_item(const host_t *host, const target_t *item,
	char *result, const poll_error_context_t *errors) {
	if (host->ignore_host) {
		SPINE_LOG(("Device[%i] HT[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'",
			errors->host_id, errors->thread_id, item->local_data_id, host->snmp.profile.timeout, host->hostname));
		SET_UNDEFINED(result);
		return;
	}
	enum poll_result_status status = normalize_poll_result(result, true);
	if (status == POLL_RESULT_VALID) return;
	record_result_error(errors, host, item, result, true);
	if (status == POLL_RESULT_INVALID) SET_UNDEFINED(result);
}


static void store_snmp_results(const host_t *host, target_t *poller_items, snmp_oids_t *snmp_oids,
	int num_oids, const poll_error_context_t *errors, double thread_start, bool spike_kill) {
	for (int j = 0; j < num_oids; j++) {
		const target_t *item = &poller_items[snmp_oids[j].array_position];
		normalize_snmp_item(host, item, snmp_oids[j].result, errors);

		if (strlen(item->output_regex)) {
			char temp_result[RESULTS_BUFFER];
			snprintf(temp_result, sizeof(temp_result), "%s", regex_replace(item->output_regex, snmp_oids[j].result));
			snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%s", temp_result);
		}

		snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

		double thread_end = get_time_as_double();

		SPINE_LOG_DEVICE(errors->host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", errors->host_id, errors->thread_id, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp.profile.version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));

		if ((!IS_UNDEFINED(poller_items[snmp_oids[j].array_position].result)) && (spike_kill && (!strstr(poller_items[snmp_oids[j].array_position].result,":")))) {
			SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
		}
	}
}

typedef struct {
	int host_id;
	const char *limits;
	bool due_only;
	bool group_ports;
} poller_query_filter_t;

static void poller_item_query(char *buffer, size_t capacity, const char *columns, const poller_query_filter_t *filter) {
	char *cursor = buffer;
	cursor += spine_snprintf(cursor, capacity, "SELECT SQL_NO_CACHE %s FROM poller_item WHERE host_id = %i", columns, filter->host_id);
	if (set.poller.poller_id != 0) cursor += spine_snprintf(cursor, capacity - (size_t)(cursor - buffer), " AND poller_id = %i", set.poller.poller_id);
	if (filter->due_only) cursor += spine_snprintf(cursor, capacity - (size_t)(cursor - buffer), " AND rrd_next_step <= 0");
	if (filter->group_ports) {
		cursor += spine_snprintf(cursor, capacity - (size_t)(cursor - buffer), " GROUP BY snmp_port");
	} else if (set.snmp.total_snmp_ports != 1) {
		cursor += spine_snprintf(cursor, capacity - (size_t)(cursor - buffer), " ORDER BY snmp_port");
	}
	spine_snprintf(cursor, capacity - (size_t)(cursor - buffer), " %s", filter->limits);
}

void poller_prepare_queries(poller_queries_t *queries, int host_id, int host_thread, int host_data_ids) {
	char limits[SMALL_BUFSIZE] = "";
	if (host_data_ids > 0) {
		if (host_thread < 1) die("ERROR: Invalid device thread for poller item selection");
		long long offset = (long long)host_data_ids * ((long long)host_thread - 1);
		spine_snprintf(limits, sizeof(limits), "LIMIT %lld, %i", offset, host_data_ids);
	}
	char columns[BUFSIZE];
	/* optional output_regex column (added in Cacti 1.3.1) */
	spine_snprintf(columns, sizeof(columns), "%s%s",
		"action, hostname, snmp_community, snmp_version, snmp_username, snmp_password, "
		"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, rrd_num, snmp_port, snmp_timeout, "
		"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id",
		set.hosts.has_output_regex ? ", output_regex" : "");
	poller_query_filter_t filter = {host_id, limits, FALSE, FALSE};
	poller_item_query(queries->items, sizeof(queries->items), columns, &filter);
	filter.due_only = set.poller.active_profiles != 1;
	poller_item_query(queries->due_items, sizeof(queries->due_items), columns, &filter);
	filter.group_ports = TRUE;
	filter.due_only = FALSE;
	poller_item_query(queries->agents, sizeof(queries->agents), "snmp_port, count(snmp_port)", &filter);
	filter.due_only = set.poller.active_profiles != 1;
	poller_item_query(queries->due_agents, sizeof(queries->due_agents), "snmp_port, count(snmp_port)", &filter);
	spine_snprintf(queries->host, sizeof(queries->host),
		"SELECT SQL_NO_CACHE id, hostname, snmp_community, snmp_version, snmp_username, snmp_password, snmp_auth_protocol, "
		"snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id, snmp_port, snmp_timeout, max_oids, "
		"availability_method, ping_method, ping_port, ping_timeout, ping_retries, status, status_event_count, "
		"UNIX_TIMESTAMP(status_fail_date), UNIX_TIMESTAMP(status_rec_date), status_last_error, min_time, max_time, "
		"cur_time, avg_time, total_polls, failed_polls, availability, snmp_sysUpTimeInstance, snmp_sysDescr, snmp_sysObjectID, "
		"snmp_sysContact, snmp_sysName, snmp_sysLocation FROM host WHERE id = %i AND deleted = ''", host_id);
	spine_snprintf(queries->reindex, sizeof(queries->reindex),
		"SELECT SQL_NO_CACHE data_query_id, action, op, assert_value, arg1 FROM poller_reindex WHERE host_id = %i", host_id);
	spine_snprintf(queries->schedule, sizeof(queries->schedule),
		"UPDATE poller_item SET rrd_next_step = IF(rrd_step = %i, 0, IF(rrd_next_step - %i < 0, rrd_step - %i, rrd_next_step - %i)) WHERE host_id = %i",
		set.poller.poller_interval, set.poller.poller_interval, set.poller.poller_interval, set.poller.poller_interval, host_id);
	if (set.poller.poller_id != 0) {
		size_t length = strlen(queries->schedule);
		spine_snprintf(queries->schedule + length, sizeof(queries->schedule) - length, " AND poller_id = %i", set.poller.poller_id);
	}
	strncopy(queries->output, "INSERT INTO poller_output (local_data_id, rrd_name, time, output) VALUES", sizeof(queries->output));
	strncopy(queries->boost_output, "INSERT INTO poller_output_boost (local_data_id, rrd_name, time, output) VALUES", sizeof(queries->boost_output));
	/* The cached upsert capability describes the local connection, while output can
	 * go to the remote one. VALUES() is accepted by both MySQL and MariaDB. */
	strncopy(queries->suffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)", sizeof(queries->suffix));
}

static void host_metadata_defaults(host_t *host) {
	/* initialize variables first */
	host->id                      = 0;                 // 0
	host->hostname[0]             = '\0';              // 1
	host->snmp.session            = NULL;              // -
	host->snmp.profile.community[0]       = '\0';              // 2
	host->snmp.profile.version            = 1;                 // 3
	host->snmp.profile.username[0]        = '\0';              // 4
	host->snmp.profile.password[0]        = '\0';              // 5
	host->snmp.profile.auth_protocol[0]   = '\0';              // 6
	host->snmp.profile.priv_passphrase[0] = '\0';              // 7
	host->snmp.profile.priv_protocol[0]   = '\0';              // 8
	host->snmp.profile.context[0]         = '\0';              // 9
	host->snmp.profile.engine_id[0]       = '\0';              // 10
	host->snmp.profile.port               = 161;               // 11
	host->snmp.profile.timeout            = 500;               // 12
	host->snmp.retries            = set.snmp.snmp_retries;  // -
	host->snmp.max_oids                = 10;                // 13
	host->availability.method     = 0;                 // 14
	host->availability.ping_method             = 0;                 // 15
	host->availability.port               = 23;                // 16
	host->availability.timeout            = 500;               // 17
	host->availability.retries            = 2;                 // 18
	host->state.status                  = HOST_UP;           // 19
	host->state.status_event_count      = 0;                 // 20
	host->state.status_fail_date[0]     = '\0';              // 21
	host->state.status_rec_date[0]      = '\0';              // 22
	host->state.status_last_error[0]    = '\0';              // 23
	host->statistics.min_time                = 0;                 // 24
	host->statistics.max_time                = 0;                 // 25
	host->statistics.cur_time                = 0;                 // 26
	host->statistics.avg_time                = 0;                 // 27
	host->statistics.total_polls             = 0;                 // 28
	host->statistics.failed_polls            = 0;                 // 29
	host->statistics.availability            = 100;               // 30
	host->system.snmp_sysUpTimeInstance  = 0;                 // 31
	host->system.snmp_sysDescr[0]        = '\0';              // 32
	host->system.snmp_sysObjectID[0]     = '\0';              // 33
	host->system.snmp_sysContact[0]      = '\0';              // 34
	host->system.snmp_sysName[0]         = '\0';              // 35
	host->system.snmp_sysLocation[0]     = '\0';              // 36
}

static void host_metadata_connection(host_t *host, MYSQL_ROW row) {
	/* populate host structure */
	host->ignore_host = FALSE;
	if (row[0]  != NULL) host->id = atoi(row[0]);

	if (row[1]  != NULL) {
		name_t *name = get_namebyhost(row[1], NULL);
		STRNCOPY(host->hostname, name->hostname);
		host->availability.port = name->port;
		SPINE_FREE(name);
	}

	if (row[2]  != NULL) STRNCOPY(host->snmp.profile.community,       row[2]);

	if (row[3]  != NULL) host->snmp.profile.version = atoi(row[3]);

	if (row[4]  != NULL) STRNCOPY(host->snmp.profile.username,        row[4]);
	if (row[5]  != NULL) STRNCOPY(host->snmp.profile.password,        row[5]);
	if (row[6]  != NULL) STRNCOPY(host->snmp.profile.auth_protocol,   row[6]);
	if (row[7]  != NULL) STRNCOPY(host->snmp.profile.priv_passphrase, row[7]);
	if (row[8]  != NULL) STRNCOPY(host->snmp.profile.priv_protocol,   row[8]);
	if (row[9]  != NULL) STRNCOPY(host->snmp.profile.context,         row[9]);
	if (row[10]  != NULL) STRNCOPY(host->snmp.profile.engine_id,       row[10]);

	if (row[11] != NULL) host->snmp.profile.port           = atoi(row[11]);
	if (row[12] != NULL) host->snmp.profile.timeout        = atoi(row[12]);
	if (row[13] != NULL) host->snmp.max_oids            = atoi(row[13]);
}

static void host_metadata_status(host_t *host, MYSQL_ROW row) {
	if (row[14] != NULL) host->availability.method = atoi(row[14]);
	if (row[15] != NULL) host->availability.ping_method         = atoi(row[15]);
	if (row[16] != NULL) host->availability.port           = atoi(row[16]);
	if (row[17] != NULL) host->availability.timeout        = atoi(row[17]);
	if (row[18] != NULL) host->availability.retries        = atoi(row[18]);

	if (row[19] != NULL) host->state.status              = atoi(row[19]);
	if (row[20] != NULL) host->state.status_event_count  = atoi(row[20]);

	if (row[21] != NULL) STRNCOPY(host->state.status_fail_date, row[21]);
	if (row[22] != NULL) STRNCOPY(host->state.status_rec_date,  row[22]);

	if (row[23] != NULL) STRNCOPY(host->state.status_last_error, row[23]);
}

static void host_metadata_statistics(host_t *host, MYSQL_ROW row) {
	if (row[24] != NULL) host->statistics.min_time     = atof(row[24]);
	if (row[25] != NULL) host->statistics.max_time     = atof(row[25]);
	if (row[26] != NULL) host->statistics.cur_time     = atof(row[26]);
	if (row[27] != NULL) host->statistics.avg_time     = atof(row[27]);
	if (row[28] != NULL) host->statistics.total_polls  = atoi(row[28]);
	if (row[29] != NULL) host->statistics.failed_polls = atoi(row[29]);
	if (row[30] != NULL) host->statistics.availability = atof(row[30]);
}

static void host_metadata_system(host_t *host, MYSQL_ROW row, MYSQL *mysql) {
	if (row[31] != NULL) host->system.snmp_sysUpTimeInstance=atoll(row[31]);
	if (row[32] != NULL) db_escape(mysql, host->system.snmp_sysDescr, sizeof(host->system.snmp_sysDescr), row[32]);
	if (row[33] != NULL) db_escape(mysql, host->system.snmp_sysObjectID, sizeof(host->system.snmp_sysObjectID), row[33]);
	if (row[34] != NULL) db_escape(mysql, host->system.snmp_sysContact, sizeof(host->system.snmp_sysContact), row[34]);
	if (row[35] != NULL) db_escape(mysql, host->system.snmp_sysName, sizeof(host->system.snmp_sysName), row[35]);
	if (row[36] != NULL) db_escape(mysql, host->system.snmp_sysLocation, sizeof(host->system.snmp_sysLocation), row[36]);
}

static void persist_host_status(MYSQL *mysql, const host_t *host, bool include_system_information) {
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

static void load_host_metadata(MYSQL *mysql, MYSQL_ROW row, host_t *host, const poller_thread_t *work) {
	host_metadata_defaults(host);
	host_metadata_connection(host, row);
	host_metadata_status(host, row);
	host_metadata_statistics(host, row);
	host_metadata_system(host, row, mysql);

	/* correct max_oid bounds issues */
	if ((host->snmp.max_oids == 0) || (host->snmp.max_oids > 100)) {
		SPINE_LOG(("Device[%i] HT[%i] WARNING: Max OIDS is out of range with value of '%i'.  Resetting to default of 5", work->host_id, work->host_thread, host->snmp.max_oids));
		host->snmp.max_oids = 5;
	}
}

static void initialize_host_snmp(host_t *host) {
	if (((host->snmp.profile.version >= 1) && (host->snmp.profile.version <= 2) &&
		(strlen(host->snmp.profile.community) > 0)) ||
		(host->snmp.profile.version == 3)) {
		host->snmp.session = snmp_host_init(&(snmp_connection_t){
			.host_id = host->id,
			.hostname = host->hostname,
			.snmp_version = host->snmp.profile.version,
			.snmp_community = host->snmp.profile.community,
			.snmp_username = host->snmp.profile.username,
			.snmp_password = host->snmp.profile.password,
			.snmp_auth_protocol = host->snmp.profile.auth_protocol,
			.snmp_priv_passphrase = host->snmp.profile.priv_passphrase,
			.snmp_priv_protocol = host->snmp.profile.priv_protocol,
			.snmp_context = host->snmp.profile.context,
			.snmp_engine_id = host->snmp.profile.engine_id,
			.snmp_port = host->snmp.profile.port,
			.snmp_timeout = host->snmp.profile.timeout,
		});
	} else {
		host->snmp.session = NULL;
	}
}

static bool refresh_host_availability(MYSQL *mysql, host_t *host, ping_t *ping, int host_thread) {
	if (host->availability.method == AVAIL_SNMP && strlen(host->snmp.profile.community) == 0 && host->snmp.profile.version < 3) {
		host->ignore_host = FALSE;
		update_host_status(HOST_UP, host, ping, host->availability.method);
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] No host availability check possible for '%s'", host->id, host_thread, host->hostname));
		return FALSE;
	}
	if (host->availability.method == AVAIL_STREAM) {
		update_host_status(HOST_UP, host, ping, host->availability.method);
		return FALSE;
	}
	bool alive = ping_host(host, ping) == HOST_UP;
	host->ignore_host = !alive;
	if (host_thread != 1) return FALSE;
	update_host_status(alive ? HOST_UP : HOST_DOWN, host, ping, host->availability.method);
	if (!alive || host->availability.method == AVAIL_PING || host->availability.method == AVAIL_NONE || host->snmp.session == NULL || !set.snmp.mibs) return FALSE;
	get_system_information(host, mysql, 1);
	return TRUE;
}

typedef struct {
	MYSQL *local;
	MYSQL *remote;
	const host_t *host;
	const poller_thread_t *work;
	int *errors;
	int *spike_kill;
} reindex_evaluation_t;

static bool reindex_assertion_failed(const reindex_t *reindex, const char *value) {
	if (value == NULL || IS_UNDEFINED(value) || STRIMATCH(value, "No Such Instance")) return FALSE;
	if (STRMATCH(reindex->op, "=")) return strcmp(reindex->assert_value, value) != 0;
	if (STRMATCH(reindex->op, ">")) return atoll(reindex->assert_value) < atoll(value);
	if (STRMATCH(reindex->op, "<")) return !STRMATCH(reindex->assert_value, "0") && atoll(reindex->assert_value) > atoll(value);
	return FALSE;
}

static void log_reindex_assertion(const reindex_evaluation_t *evaluation, const reindex_t *reindex, const char *value, bool failed) {
	bool highlighted = is_debug_device(evaluation->host->id) || set.logging.spine_log_level == 2;
	if (!failed && !highlighted) return;
	if (failed && !highlighted && set.logging.spine_log_level == 1) (*evaluation->errors)++;
	SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE ASSERT FAILED: '%s%s%s'", evaluation->host->id, evaluation->work->host_thread, reindex->data_query_id, reindex->assert_value, failed ? reindex->op : "=", value != NULL ? value : "(null)"));
}

/* FALSE only when the queue write failed; other partitions never queue. */
static bool queue_reindex(const reindex_evaluation_t *evaluation, const reindex_t *reindex) {
	if (evaluation->work->host_thread != 1) return TRUE;
	char query[LRG_BUFSIZE];
	snprintf(query, sizeof(query), "REPLACE INTO poller_command (poller_id, time, action, command) VALUES (%i, NOW(), %i, '%i:%i')", set.poller.poller_id, POLLER_COMMAND_REINDEX, evaluation->host->id, reindex->data_query_id);
	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) return db_insert(evaluation->remote, REMOTE, query);
	return db_insert(evaluation->local, LOCAL, query);
}

static void update_reindex_value(const reindex_evaluation_t *evaluation, const reindex_t *reindex, const char *value) {
	/* An unavailable result cannot replace the stored assertion with uninitialized bytes. */
	if (evaluation->work->host_thread != 1 || value == NULL) return;
	char escaped_value[BUFSIZE];
	char escaped_argument[BUFSIZE];
	char query[LRG_BUFSIZE];
	db_escape(evaluation->local, escaped_value, sizeof(escaped_value), value);
	db_escape(evaluation->local, escaped_argument, sizeof(escaped_argument), reindex->arg1);
	snprintf(query, sizeof(query), "UPDATE poller_reindex SET assert_value='%s' WHERE host_id='%i' AND data_query_id='%i' AND arg1='%s'", escaped_value, evaluation->work->host_id, reindex->data_query_id, escaped_argument);
	db_insert(evaluation->local, LOCAL, query);
}

static void discard_reindex_spike(const reindex_evaluation_t *evaluation) {
	*evaluation->spike_kill = TRUE;
	if (is_debug_device(evaluation->host->id) || set.logging.spine_log_level == 2) {
		SPINE_LOG(("Device[%i] HT[%i] NOTICE: Spike Kill in Effect for '%s'", evaluation->work->host_id, evaluation->work->host_thread, evaluation->host->hostname));
	} else {
		if (set.logging.spine_log_level == 1) (*evaluation->errors)++;
		SPINE_LOG_MEDIUM(("Device[%i] HT[%i] NOTICE: Spike Kill in Effect for '%s'", evaluation->work->host_id, evaluation->work->host_thread, evaluation->host->hostname));
	}
}

static bool evaluate_reindex_assertion(const reindex_evaluation_t *evaluation, const reindex_t *reindex, const char *value) {
	bool failed = reindex_assertion_failed(reindex, value);
	bool unavailable = value == NULL || IS_UNDEFINED(value) || STRIMATCH(value, "No Such Instance");
	if (failed || unavailable) log_reindex_assertion(evaluation, reindex, value, failed);
	/* Advancing the stored value without a queued reindex would lose the
	 * reindex for good: the next poll compares against the new value. */
	bool queued = !failed || queue_reindex(evaluation, reindex);
	if (queued && (failed || STRMATCH(reindex->op, ">") || STRMATCH(reindex->op, "<"))) update_reindex_value(evaluation, reindex, value);
	/* A failed uptime assertion means the counters reset, so the sample is a spike. */
	if (failed && (STRMATCH(reindex->op, "<") ||
		STRMATCH(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
		STRMATCH(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0"))) {
		discard_reindex_spike(evaluation);
	}
	return failed;
}

static char *poll_reindex_snmp(host_t *host, reindex_t *reindex, int host_thread, char *sysUptime, bool *unavailable) {
	if (host->snmp.session == NULL) {
		*unavailable = TRUE;
		SPINE_LOG(("WARNING: Device[%i] HT[%i] DQ[%i] Reindex Check FAILED: No SNMP Session.  If not an SNMP host, don't use Uptime Goes Backwards!", host->id, host_thread, reindex->data_query_id));
		return NULL;
	}
	char *poll_result = NULL;
	if ((strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
		strstr(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")) && strlen(sysUptime) > 0) {

		if (!(poll_result = (char *) malloc(BUFSIZE))) {
			die("ERROR: Fatal malloc error: poller.c poll_result");
		}

		poll_result[0] = '\0';

		snprintf(poll_result, BUFSIZE, "%s", sysUptime);
	} else if (strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
		strstr(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")) {
		// Ensure uptime is empty to start with
		sysUptime[0] = '\0';

		/* Pin the uptime-goes-backward calculation to a single OID for this poll.
		   The legacy (centisecond) and modern (second) OIDs are different counters,
		   and letting either supply the value on different rows or cycles caused
		   false "uptime went backward" detections and constant reindexing. Prefer
		   the modern engine OID and fall back to the legacy OID only when the
		   engine OID is not present with numeric data. */
		poll_result = snmp_get_base(host, ".1.3.6.1.6.3.10.2.1.3.0", false);

		bool uptime_use_engine_oid = (poll_result != NULL && is_numeric(poll_result));

		if (uptime_use_engine_oid) {
			snprintf(sysUptime, BUFSIZE, "%lld", atoll(poll_result) * 100);
		}

		SPINE_FREE(poll_result);

		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Engine Uptime OID Present: %d", host->id, host_thread, reindex->data_query_id, uptime_use_engine_oid));

		if (!uptime_use_engine_oid) {
			// Engine OID unavailable, fall back to the legacy sysUpTime OID
			poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");

			if (poll_result && is_numeric(poll_result)) {
				snprintf(sysUptime, BUFSIZE, "%s", poll_result);
			}

			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Legacy Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result != NULL ? poll_result : "U", is_numeric(poll_result) ));

			SPINE_FREE(poll_result);
		}

		// Use the primed uptime to repopulate the poll_result
		// This ensures whichever response was valid gets used
		poll_result = strdup(sysUptime);
		if (poll_result == NULL) {
			die("ERROR: Fatal malloc error: poller.c uptime result");
		}

		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Extended Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, is_numeric(poll_result) ));
	} else {
		poll_result = snmp_get(host, reindex->arg1);
	}

	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE OID: %s, (assert: %s %s output: %s)", host->id, host_thread, reindex->data_query_id, reindex->arg1, reindex->assert_value, reindex->op, poll_result));
	return poll_result;
}

static char *poll_reindex_action(host_t *host, reindex_t *reindex, int host_thread, char *sysUptime, bool *unavailable) {
	char *poll_result = NULL;
	int php_process;
	char script[SMALL_BUFSIZE];
	switch(reindex->action) {
	case POLLER_ACTION_SNMP:
		poll_result = poll_reindex_snmp(host, reindex, host_thread, sysUptime, unavailable);
		break;
	case POLLER_ACTION_SCRIPT: /* script (popen) */
		/* Reject empty script commands that could cause unexpected behavior */
		if (strlen(reindex->arg1) == 0) {
			SPINE_LOG(("WARNING: Device[%i] HT[%i] DQ[%i] empty script command, skipping",
				host->id, host_thread, reindex->data_query_id));
			break;
		}

		poll_result = trim(exec_poll(host, reindex->arg1, reindex->data_query_id, "DQ"));

		php_command_script(reindex->arg1, script, sizeof(script));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE CMD: %s, output: %s", host->id, host_thread, reindex->data_query_id, script, poll_result));

		break;
	case POLLER_ACTION_PHP_SCRIPT_SERVER: /* script (php script server) */
		php_process = php_get_process();

		poll_result = trim(php_cmd(reindex->arg1, php_process));

		php_command_script(reindex->arg1, script, sizeof(script));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE SERVER: %s, output: %s", host->id, host_thread, reindex->data_query_id, script, poll_result));

		break;
	case POLLER_ACTION_SNMP_COUNT: { /* snmp; count items */
		if (!(poll_result = (char *) malloc(BUFSIZE))) {
			die("ERROR: Fatal malloc error: poller.c poll_result");
		}
		poll_result[0] = '\0';

		int snmp_items = snmp_count(host, reindex->arg1);
		if (snmp_items < 0) {
			SET_UNDEFINED(poll_result);
		} else {
			snprintf(poll_result, BUFSIZE, "%d", snmp_items);
		}

		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE OID COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));

		break;
	}
	case POLLER_ACTION_SCRIPT_COUNT: { /* script (popen); count line feeds */
		if (!(poll_result = (char *) malloc(BUFSIZE))) {
			die("ERROR: Fatal malloc error: poller.c poll_result");
		}
		poll_result[0] = '\0';

		char *count_result = exec_poll(host, reindex->arg1, reindex->data_query_id, "DQ");
		snprintf(poll_result, BUFSIZE, "%d", char_count(count_result, '\n'));
		SPINE_FREE(count_result);

		php_command_script(reindex->arg1, script, sizeof(script));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE CMD COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, script, poll_result));

		break;
	}
	case POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT: { /* script (php script server); count number of lines */
		if (!(poll_result = (char *) malloc(BUFSIZE))) {
			die("ERROR: Fatal malloc error: poller.c poll_result");
		}
		poll_result[0] = '\0';

		php_process = php_get_process();

		char *count_result = php_cmd(reindex->arg1, php_process);
		spine_snprintf(poll_result, BUFSIZE, "%d", char_count(count_result, '\n'));
		SPINE_FREE(count_result);

		php_command_script(reindex->arg1, script, sizeof(script));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE SERVER COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, script, poll_result));

		break;
	}
	default:
		SPINE_LOG(("Device[%i] HT[%i] ERROR: Unknown Assert Action!", host->id, host_thread));
	}
	return poll_result;
}

static void load_reindex_item(reindex_t *reindex, MYSQL_ROW row) {
	/* initialize the reindex struction */
	reindex->data_query_id   = 0;
	reindex->action          = -1;
	reindex->op[0]           = '\0';
	reindex->assert_value[0] = '\0';
	reindex->arg1[0]         = '\0';

	if (row[0] != NULL) reindex->data_query_id = atoi(row[0]);
	if (row[1] != NULL) reindex->action        = atoi(row[1]);

	if (row[2] != NULL) snprintf(reindex->op, sizeof(reindex->op), "%s", row[2]);

	if (row[3] != NULL) snprintf(reindex->assert_value, sizeof(reindex->assert_value), "%s", row[3]);

	if (row[4] != NULL) snprintf(reindex->arg1, sizeof(reindex->arg1), "%s", row[4]);
}

static void poll_host_reindex(host_t *host, reindex_t *reindex, const char *query,
	const reindex_evaluation_t *evaluation) {
	if (host->ignore_host || evaluation->work->host_id == 0) return;
	int thread = evaluation->work->host_thread;
	MYSQL_RES *result = db_query(evaluation->local, LOCAL, query);
	if (result == NULL) {
		SPINE_LOG(("Device[%i] HT[%i] ERROR: RECACHE Query Returned Null Result!", host->id, thread));
	} else {
		int count = spine_count_to_int(mysql_num_rows(result));
		if (count == 0) {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] HT[%i] Device has no information for recache.", host->id, thread));
		} else {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] HT[%i] DEBUG: RECACHE: Processing %i items in the auto reindex cache for '%s'", host->id, thread, count, host->hostname));
		}
		char sysUptime[BUFSIZE] = "";
		int last_data_query_id = 0;
		bool previous_assert_failure = FALSE;
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result))) {
			load_reindex_item(reindex, row);
			if (last_data_query_id != reindex->data_query_id) {
				last_data_query_id = reindex->data_query_id;
				previous_assert_failure = FALSE;
			}
			if (previous_assert_failure) continue;
			bool unavailable = FALSE;
			char *value = poll_reindex_action(host, reindex, thread, sysUptime, &unavailable);
			if (unavailable) continue;
			if (evaluate_reindex_assertion(evaluation, reindex, value)) previous_assert_failure = TRUE;
			SPINE_FREE(value);
		}
		db_free_result(result);
	}
	/* Item polling opens a new session after reindex work has finished. */
	if (host->snmp.session != NULL) {
		snmp_host_cleanup(host->snmp.session);
		host->snmp.session = NULL;
	}
}

static void load_poll_item(target_t *item, MYSQL_ROW row) {
	/* initialize monitored object */
	item->target_id                = 0;
	item->action                   = -1;
	item->hostname[0]              = '\0';
	item->snmp.community[0]        = '\0';
	item->snmp.version             = 1;
	item->snmp.username[0]         = '\0';
	item->snmp.password[0]         = '\0';
	item->snmp.auth_protocol[0]    = '\0';
	item->snmp.priv_passphrase[0]  = '\0';
	item->snmp.priv_protocol[0]    = '\0';
	item->snmp.context[0]          = '\0';
	item->snmp.engine_id[0]        = '\0';
	item->snmp.port                = 161;
	item->snmp.timeout             = 500;
	item->rrd_name[0]              = '\0';
	item->rrd_path[0]              = '\0';
	item->arg1[0]                  = '\0';
	item->arg2[0]                  = '\0';
	item->arg3[0]                  = '\0';
	item->local_data_id            = 0;
	item->rrd_num                  = 0;
	item->output_regex[0]          = '\0';

	if (row[0] != NULL)  item->action = atoi(row[0]);

	if (row[1] != NULL)  snprintf(item->hostname, sizeof(item->hostname), "%s", row[1]);
	if (row[2] != NULL)  snprintf(item->snmp.community, sizeof(item->snmp.community), "%s", row[2]);

	if (row[3] != NULL)  item->snmp.version = atoi(row[3]);

	if (row[4] != NULL)  snprintf(item->snmp.username, sizeof(item->snmp.username), "%s", row[4]);
	if (row[5] != NULL)  snprintf(item->snmp.password, sizeof(item->snmp.password), "%s", row[5]);

	if (row[6]  != NULL) snprintf(item->rrd_name,      sizeof(item->rrd_name),      "%s", row[6]);
	if (row[7]  != NULL) snprintf(item->rrd_path,      sizeof(item->rrd_path),      "%s", row[7]);
	if (row[8]  != NULL) snprintf(item->arg1,          sizeof(item->arg1),          "%s", row[8]);
	if (row[9]  != NULL) snprintf(item->arg2,          sizeof(item->arg2),          "%s", row[9]);
	if (row[10] != NULL) snprintf(item->arg3,          sizeof(item->arg3),          "%s", row[10]);

	if (row[11] != NULL) item->local_data_id = atoi(row[11]);

	if (row[12] != NULL) item->rrd_num       = atoi(row[12]);
	if (row[13] != NULL) item->snmp.port     = atoi(row[13]);
	if (row[14] != NULL) item->snmp.timeout  = atoi(row[14]);

	if (row[15] != NULL)  snprintf(item->snmp.auth_protocol,
		sizeof(item->snmp.auth_protocol), "%s", row[15]);
	if (row[16] != NULL)  snprintf(item->snmp.priv_passphrase,
		sizeof(item->snmp.priv_passphrase), "%s", row[16]);
	if (row[17] != NULL)  snprintf(item->snmp.priv_protocol,
		sizeof(item->snmp.priv_protocol), "%s", row[17]);
	if (row[18] != NULL)  snprintf(item->snmp.context,
		sizeof(item->snmp.context), "%s", row[18]);
	if (row[19] != NULL)  snprintf(item->snmp.engine_id,
		sizeof(item->snmp.engine_id), "%s", row[19]);

	if (set.hosts.has_output_regex && row[20] != NULL)
		snprintf(item->output_regex, sizeof(item->output_regex), "%s", row[20]);

	SET_UNDEFINED(item->result);
}

static void poll_script_item(host_t *host, target_t *item,
	const poll_error_context_t *errors, double thread_start, bool spike_kill,
	bool script_server) {
	int php_process = -1;
	char *poll_result;
	/* Reject empty script commands that could cause unexpected behavior */
	if (strlen(item->arg1) == 0) {
		SPINE_LOG(("WARNING: Device[%i] HT[%i] DS[%i] empty script%s command, skipping",
			errors->host_id, errors->thread_id, item->local_data_id, script_server ? " server" : ""));
		SET_UNDEFINED(item->result);
		return;
	}
	if (script_server) {
		php_process = php_get_process();
		poll_result = php_cmd(item->arg1, php_process);
	} else {
		poll_result = exec_poll(host, item->arg1, item->local_data_id, "DS");
	}
	strncopy(item->result, poll_result, sizeof(item->result));
	enum poll_result_status status = normalize_poll_result(item->result, false);
	if (status != POLL_RESULT_VALID) {
		record_result_error(errors, host, item, item->result, false);
		if (status == POLL_RESULT_INVALID) SET_UNDEFINED(item->result);
	}
	SPINE_FREE(poll_result);
	double thread_end = get_time_as_double();
	char script[SMALL_BUFSIZE];
	php_command_script(item->arg1, script, sizeof(script));
	if (script_server) {
		SPINE_LOG_DEVICE(errors->host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DS[%i] TT[%.2f] SS[%i] SERVER: %s, output: %s", errors->host_id, errors->thread_id, item->local_data_id, (float) ((thread_end - thread_start) * 1000), php_process, script, item->result));
	} else {
		SPINE_LOG_DEVICE(errors->host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DS[%i] TT[%.2f] SCRIPT: %s, output: %s", errors->host_id, errors->thread_id, item->local_data_id, (float) ((thread_end - thread_start) * 1000), script, item->result));
	}
	/* insert a NaN in place of the actual value if the snmp agent restarts */
	if (!IS_UNDEFINED(item->result) && spike_kill && !strstr(item->result, ":")) SET_UNDEFINED(item->result);
}

typedef struct {
	char *output;
	char *boost;
	bool failed;
} poll_output_buffers_t;

static char *allocate_output_query(const char *prefix, const char *failure_message) {
	char *query = malloc(MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER);
	if (query == NULL) die("%s", failure_message);
	memset(query, 0, MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER);
	strncat(query, prefix, spine_count_to_int(strlen(prefix)));
	return query;
}

/* Attempt each destination independently. Reset only early-flush buffers;
 * a failed write must not suppress the other destination or later batches. */
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

static poll_output_buffers_t write_poll_results(MYSQL *mysql, MYSQL *mysqlr,
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
		mode   = REMOTE;
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Setting up writes to local database"));
		mysqlt = mysql;
		mode   = LOCAL;
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

typedef struct {
	int initialized;
	int version;
	int port;
	char community[50];
	char username[50];
	char password[50];
	char auth_protocol[7];
	char priv_passphrase[200];
	char priv_protocol[8];
	char context[65];
	char engine_id[30];
} snmp_item_key_t;

typedef struct {
	target_t *items;
	snmp_oids_t *oids;
	int count;
	snmp_item_key_t key;
	const poll_error_context_t *errors;
} snmp_poll_batch_t;

static void remember_snmp_item(snmp_item_key_t *key, const target_t *item) {
	key->port = item->snmp.port;
	key->version = item->snmp.version;

	STRNCOPY(key->community,       item->snmp.community);
	STRNCOPY(key->username,        item->snmp.username);
	STRNCOPY(key->password,        item->snmp.password);
	STRNCOPY(key->auth_protocol,   item->snmp.auth_protocol);
	STRNCOPY(key->priv_passphrase, item->snmp.priv_passphrase);
	STRNCOPY(key->priv_protocol,   item->snmp.priv_protocol);
	STRNCOPY(key->context,         item->snmp.context);
	STRNCOPY(key->engine_id,       item->snmp.engine_id);
}

static void *open_snmp_item(const host_t *host, target_t *item) {
	return snmp_host_init(&(snmp_connection_t){
	.host_id = host->id,
	.hostname = item->hostname,
	.snmp_version = item->snmp.version,
	.snmp_community = item->snmp.community,
	.snmp_username = item->snmp.username,
	.snmp_password = item->snmp.password,
	.snmp_auth_protocol = item->snmp.auth_protocol,
	.snmp_priv_passphrase = item->snmp.priv_passphrase,
	.snmp_priv_protocol = item->snmp.priv_protocol,
	.snmp_context = item->snmp.context,
	.snmp_engine_id = item->snmp.engine_id,
	.snmp_port = item->snmp.port,
	.snmp_timeout = item->snmp.timeout,
});
}

static bool snmp_item_changed(const snmp_item_key_t *key, const target_t *item) {
	return (key->port != item->snmp.port) ||
					(key->version != item->snmp.version) ||
					(item->snmp.version < 3 &&
					(!STRMATCH(key->community, item->snmp.community))) ||
					(item->snmp.version > 2 &&
					((!STRMATCH(key->username, item->snmp.username)) ||
					(!STRMATCH(key->password, item->snmp.password)) ||
					(!STRMATCH(key->auth_protocol, item->snmp.auth_protocol)) ||
					(!STRMATCH(key->priv_passphrase, item->snmp.priv_passphrase)) ||
					(!STRMATCH(key->priv_protocol, item->snmp.priv_protocol)) ||
					(!STRMATCH(key->context, item->snmp.context)) ||
					(!STRMATCH(key->engine_id, item->snmp.engine_id))));
}

static void flush_snmp_batch(host_t *host, snmp_poll_batch_t *batch,
	double thread_start, bool spike_kill) {
	if (batch->count <= 0) return;
	snmp_get_multi(host, batch->items, batch->oids, batch->count);
	store_snmp_results(host, batch->items, batch->oids, batch->count, batch->errors, thread_start, spike_kill);
	batch->count = 0;
	memset(batch->oids, 0, sizeof(snmp_oids_t) * host->snmp.max_oids);
}

static void poll_snmp_item(host_t *host, snmp_poll_batch_t *batch, int position,
	double thread_start, bool spike_kill) {
	target_t *item = &batch->items[position];
	if (batch->key.initialized == 0) {
		remember_snmp_item(&batch->key, item);
		host->snmp.session = open_snmp_item(host, item);
		batch->key.initialized++;
	}
	if (host->snmp.session == NULL) {
		host->ignore_host = TRUE;
		return;
	}
	if (snmp_item_changed(&batch->key, item)) {
		/* Credential-switch flushes preserve the legacy no-discard policy. */
		flush_snmp_batch(host, batch, thread_start, FALSE);
		if (host->snmp.session != NULL) {
			snmp_host_cleanup(host->snmp.session);
			host->snmp.session = NULL;
		}
		host->snmp.session = open_snmp_item(host, item);
		remember_snmp_item(&batch->key, item);
	}
	if (batch->count >= host->snmp.max_oids) flush_snmp_batch(host, batch, thread_start, spike_kill);
	snprintf(batch->oids[batch->count].oid, sizeof(batch->oids[batch->count].oid), "%s", item->arg1);
	batch->oids[batch->count].array_position = position;
	batch->count++;
}


typedef struct {
	target_t *items;
	snmp_oids_t *oids;
} poll_item_storage_t;

static MYSQL_RES *select_poll_items(MYSQL *mysql, const poller_queries_t *queries,
	const host_t *host, const poller_thread_t *work, int *num_rows) {
	const char *query = set.poller.poller_interval == 0 ? queries->items : queries->due_items;
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	*num_rows = 0;
	if (result != NULL) {
		*num_rows = spine_count_to_int(mysql_num_rows(result));
	} else {
		SPINE_LOG(("Device[%i] HT[%i] ERROR: Unable to Retrieve Rows due to Null Result!", host->id, work->host_thread));
	}
	return result;
}

static poll_item_storage_t load_poll_items(MYSQL_RES *result, host_t *host, int num_rows) {
	poll_item_storage_t storage;
	/* retrieve each hosts polling items from poller cache and load into array */
	storage.items = (target_t *) calloc(num_rows, sizeof(target_t));
	if (storage.items == NULL) die("ERROR: Fatal calloc error: poller.c poller_items");

	int i = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		load_poll_item(&storage.items[i], row);

		i++;
	}

	/* free the mysql result */
	db_free_result(result);

	/* create an array for snmp oids */
	if (host->snmp.max_oids <= 0) {
		host->snmp.max_oids = 1;
	}
	storage.oids = (snmp_oids_t *) calloc(host->snmp.max_oids, sizeof(snmp_oids_t));
	if (storage.oids == NULL) {
		die("ERROR: Fatal calloc error: poller.c snmp_oids");
	}

	return storage;
}

static int collect_poll_items(host_t *host, snmp_poll_batch_t *batch, int num_rows, bool spike_kill) {
	int i = 0;
	int rows_processed = 0;
	double thread_start = 0;
	char script[SMALL_BUFSIZE];
	while ((i < num_rows) && (!host->ignore_host)) {
		thread_start = get_time_as_double();

		switch(batch->items[i].action) {
		case POLLER_ACTION_SNMP:
			poll_snmp_item(host, batch, i, thread_start, spike_kill);
			break;
		case POLLER_ACTION_SCRIPT:
			poll_script_item(host, &batch->items[i], batch->errors, thread_start, spike_kill, FALSE);
			break;
		case POLLER_ACTION_PHP_SCRIPT_SERVER:
			poll_script_item(host, &batch->items[i], batch->errors, thread_start, spike_kill, TRUE);
			break;
		default: /* unknown action, generate error */
			php_command_script(batch->items[i].arg1, script, sizeof(script));
			SPINE_LOG(("Device[%i] HT[%i] DS[%i] ERROR: Unknown Poller Action: %s", batch->errors->host_id, batch->errors->thread_id, batch->items[i].local_data_id, script));

			break;
		}

		i++;
		rows_processed++;
	}

	/* process last multi-get request if applicable */
	if (batch->count > 0) {
		snmp_get_multi(host, batch->items, batch->oids, batch->count);

		store_snmp_results(host, batch->items, batch->oids, batch->count, batch->errors, thread_start, spike_kill);
	}

	return rows_processed;
}

static void release_poll_connections(const poller_thread_t *work,
	const pool_t *local, const pool_t *remote) {
	if (local != NULL) {
		db_release_connection(LOCAL, local->id);
	} else {
		SPINE_LOG(("WARNING: Device[%i] HT[%i] Trying to close uninitialized local connection.", work->host_id, work->host_thread));
	}
	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		if (remote != NULL) {
			db_release_connection(REMOTE, remote->id);
		} else {
			SPINE_LOG(("WARNING: Device[%i] HT[%i] Trying to close uninitialized remote connection.", work->host_id, work->host_thread));
		}
	}
}

typedef enum {
	POLL_HOST_LOADED,
	POLL_HOST_MISSING,
	POLL_HOST_FAILED
} poll_host_load_t;

/* A device deleted since selection returns quietly. A failed device query
 * fails the device: treating it as an ignored host would still advance its
 * schedule and drop the samples it never collected. */
static poll_host_load_t load_poll_host(MYSQL *mysql, const poller_queries_t *queries,
	host_t *host, ping_t *ping, const poller_thread_t *work) {
	/* host_id=0 denotes a data source without a device. */
	if (!work->host_id) {
		host->id = 0;
		host->snmp.max_oids = 1;
		host->snmp.session = NULL;
		host->ignore_host = FALSE;
		return POLL_HOST_LOADED;
	}
	MYSQL_RES *result = db_query(mysql, LOCAL, queries->host);
	if (result == NULL) {
		SPINE_LOG(("Device[%i] HT[%i] ERROR: Unable to load the device", work->host_id, work->host_thread));
		return POLL_HOST_FAILED;
	}
	if (spine_count_to_int(mysql_num_rows(result)) != 1) {
		db_free_result(result);
		return POLL_HOST_MISSING;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	if (row == NULL) {
		SPINE_LOG(("Device[%i] HT[%i] ERROR: MySQL Returned a Null Device Result", host->id, work->host_thread));
		host->ignore_host = TRUE;
		return POLL_HOST_LOADED;
	}
	load_host_metadata(mysql, row, host, work);
	db_free_result(result);
	initialize_host_snmp(host);
	bool include_system_information = refresh_host_availability(mysql, host, ping, work->host_thread);
	if (work->host_thread == 1) {
		persist_host_status(mysql, host, include_system_information && host->ignore_host != TRUE);
	}
	return POLL_HOST_LOADED;
}

/* LOCK_THDET only guards the shared completion state. The database writes
 * run after it is released: each can wait out a read timeout and a reconnect,
 * and holding the lock across them would stall every other worker. A
 * poll_failed partition skips them, since mysql may be NULL and a connection
 * that just failed would only spend another retry budget. */
static void complete_poll_host(MYSQL *mysql, poller_queries_t *queries,
	const poller_thread_t *work, const poll_error_context_t *error_context,
	bool output_failed, bool poll_failed, double poll_start) {
	extern poller_thread_t **details;
	int host_id = work->host_id;
	int host_thread = work->host_thread;
	double host_time_double = work->host_time_double;
	int errors = *error_context->errors;
	const char *error_string = error_context->buffer;
	double poll_time;
	bool last_partition;
	bool update_schedule = FALSE;
	bool write_failed = FALSE;
	/* record the polling time for the device */
	poll_time = get_time_as_double() - poll_start;
	SPINE_LOG_DEVICE(host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] Total Time: %0.2g Seconds", host_id, host_thread, poll_time));

	/* record the total time for the host */
	thread_mutex_lock(LOCK_THDET);
	poller_thread_t *device = details[work->device_counter];
	if (output_failed) {
		device->output_failed = TRUE;
		set.exit.exit_code = EXIT_FAILURE;
		SPINE_LOG(("ERROR: Device[%i] HT[%i] output write failed; partial writes remain and due items stay eligible for recollection", host_id, host_thread));
	}
	if (poll_failed) {
		device->poll_failed = TRUE;
		set.exit.exit_code = EXIT_FAILURE;
		SPINE_LOG(("ERROR: Device[%i] HT[%i] polling failed on a database error; due items stay eligible for recollection", host_id, host_thread));
	}
	device->threads_complete++;
	last_partition = device->threads_complete == device->host_threads;
	if (last_partition) {
		bool failed = device->output_failed || device->poll_failed;
		/* Keep the due-item set stable until every device partition has
		 * finished; only this last partition runs the update. */
		update_schedule = set.poller.active_profiles != 1 && !failed;
		device->complete = !failed;
	}
	thread_mutex_unlock(LOCK_THDET);

	if (poll_failed) return;

	if (update_schedule) {
		SPINE_LOG_MEDIUM(("Device[%i] HT[%i] Updating Poller Items for Next Poll", host_id, host_thread));
		/* db_insert() reports the outcome; db_query() has no result set to
		 * show for an UPDATE, so a failed write used to look like success. */
		if (!db_insert(mysql, LOCAL, queries->schedule)) write_failed = TRUE;
	}

	if (last_partition) {
		poll_time = get_time_as_double();
		queries->items[0] = '\0';
		snprintf(queries->items, BUFSIZE, "UPDATE host SET polling_time = %.3f - %.3f WHERE id = %i", poll_time, host_time_double, host_id);
		if (!db_insert(mysql, LOCAL, queries->items)) write_failed = TRUE;
	}

	if (errors > 0) {
		int error_query_len = spine_count_to_int(strlen(error_string) + BUFSIZE);
		char *error_query = (char *)malloc(error_query_len);
		if (error_query == NULL) die("ERROR: Fatal malloc error: poller.c error_query!");

		snprintf(error_query, error_query_len, "INSERT INTO host_errors (host_id, poller_id, errors, local_data_ids)"
			" VALUES(%i, %i, %i, '%s')"
			" ON DUPLICATE KEY UPDATE"
			" errors = errors + VALUES(errors),"
			" local_data_ids = CONCAT(local_data_ids, ', ', VALUES(local_data_ids))",
			host_id, set.poller.poller_id, errors, error_string);

		if (!db_insert(mysql, LOCAL, error_query)) write_failed = TRUE;

		free(error_query);
	}

	/* output_failed keeps a later partition from marking the device complete
	 * or advancing its schedule, so its items stay due for the next poll. */
	if (write_failed) {
		thread_mutex_lock(LOCK_THDET);
		device->output_failed = TRUE;
		device->complete = FALSE;
		set.exit.exit_code = EXIT_FAILURE;
		thread_mutex_unlock(LOCK_THDET);
		SPINE_LOG(("ERROR: Device[%i] HT[%i] device completion write failed; the device is not counted as polled", host_id, host_thread));
	}
}

void poll_host(const poller_thread_t *work, int *host_errors) {
	assert(work != NULL && host_errors != NULL);
	int host_id = work->host_id;
	int host_thread = work->host_thread;
	int host_data_ids = work->host_data_ids;
	const char *host_time = work->host_time;
	poller_queries_t queries;
	char *query3 = NULL;
	char *query12 = NULL;


	int  errors = 0;
	int  *buf_errors;
	int  *buf_size;
	char *error_string;

	int    num_rows;
	int    spike_kill = FALSE;
	int    rows_processed = 0;
	bool   output_failed = FALSE;
	bool   poll_failed = FALSE;
	poll_host_load_t loaded;


	double poll_time = get_time_as_double();

	/* reindex shortcuts to speed polling */


	pool_t *local_cnn = NULL;
	pool_t *remote_cnn = NULL;

	reindex_t   *reindex = NULL;
	host_t      *host = NULL;
	ping_t      *ping = NULL;
	target_t    *poller_items = NULL;
	snmp_oids_t *snmp_oids = NULL;

	if (!(error_string = malloc(DBL_BUFSIZE))) {
		die("ERROR: Fatal malloc error: poller.c error_string!");
	}
	if (!(buf_size = malloc(sizeof(int)))) {
		die("ERROR: Fatal malloc error: poller.c buf_size!");
	}
	if (!(buf_errors = malloc(sizeof(int)))) {
		die("ERROR: Fatal malloc error: poller.c buf_errors!");
	}

	if (error_string == NULL || buf_size == NULL || buf_errors == NULL) {
		die("ERROR: Fatal malloc error: poller error buffer!");
	}
	*buf_size = 0;
	*buf_errors = 0;
	const poll_error_context_t error_context = {
		error_string, buf_size, buf_errors, &errors, host_id, host_thread
	};

	MYSQL     *mysql;
	MYSQL     *mysqlr = NULL;
	MYSQL_RES *result;

	local_cnn = db_get_connection(LOCAL);
	if (local_cnn != NULL && set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		remote_cnn = db_get_connection(REMOTE);
		if (remote_cnn == NULL) {
			db_release_connection(LOCAL, local_cnn->id);
			local_cnn = NULL;
		}
	}

	if (local_cnn == NULL) {
		SPINE_LOG(("ERROR: Device[%i] HT[%i] No database connection available for polling", host_id, host_thread));
		complete_poll_host(NULL, NULL, work, &error_context, FALSE, TRUE, poll_time);
		SPINE_FREE(error_string);
		SPINE_FREE(buf_size);
		SPINE_FREE(buf_errors);
		mysql_thread_end();
		return;
	}

	mysql = &local_cnn->mysql;
	if (remote_cnn != NULL) mysqlr = &remote_cnn->mysql;

	/* allocate host and ping structures with appropriate values */
	if (!(host = (host_t *) malloc(sizeof(host_t)))) {
		die("ERROR: Fatal malloc error: poller.c host struct!");
	}

	/* set zeros */
	memset(host, 0, sizeof(host_t));

	if (!(ping = (ping_t *) malloc(sizeof(ping_t)))) {
		die("ERROR: Fatal malloc error: poller.c ping struct!");
	}

	/* set zeros */
	memset(ping, 0, sizeof(ping_t));

	if (!(reindex = (reindex_t *) malloc(sizeof(reindex_t)))) {
		die("ERROR: Fatal malloc error: poller.c reindex poll!");
	}
	memset(reindex, 0, sizeof(reindex_t));

	poller_prepare_queries(&queries, host_id, host_thread, host_data_ids);

	/* initialize the ping structure variables */
	snprintf(ping->ping_status,   50,            "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "Ping not performed due to setting.");
	snprintf(ping->snmp_status,   50,            "down");
	snprintf(ping->snmp_response, SMALL_BUFSIZE, "SNMP not performed due to setting or ping result");

	loaded = load_poll_host(mysql, &queries, host, ping, work);
	if (loaded == POLL_HOST_FAILED) {
		complete_poll_host(mysql, &queries, work, &error_context, FALSE, TRUE, poll_time);
	}
	if (loaded != POLL_HOST_LOADED) {
		release_poll_connections(work, local_cnn, remote_cnn);
		SPINE_FREE(host);
		SPINE_FREE(reindex);
		SPINE_FREE(ping);
		SPINE_FREE(error_string);
		SPINE_FREE(buf_size);
		SPINE_FREE(buf_errors);
		mysql_thread_end();

		return;
	}

	if (set.availability.ping_only) {
		if (host->snmp.session != NULL) {
			snmp_host_cleanup(host->snmp.session);
			host->snmp.session = NULL;
		}
		SPINE_FREE(host);
		SPINE_FREE(reindex);
		SPINE_FREE(ping);
		SPINE_FREE(error_string);
		SPINE_FREE(buf_size);
		SPINE_FREE(buf_errors);

		release_poll_connections(work, local_cnn, remote_cnn);

		mysql_thread_end();

		return;
	}

	const reindex_evaluation_t evaluation = {mysql, mysqlr, host, work, &errors, &spike_kill};
	poll_host_reindex(host, reindex, queries.reindex, &evaluation);

	/* calculate the number of poller items to poll this cycle */
	result = select_poll_items(mysql, &queries, host, work, &num_rows);
	poll_failed = result == NULL;

	if (num_rows > 0) {
		poll_item_storage_t storage = load_poll_items(result, host, num_rows);
		poller_items = storage.items;
		snmp_oids = storage.oids;

		/* log an informative message */
		SPINE_LOG_DEVICE(host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] NOTE: There are '%i' Polling Items for this Device", host_id, host_thread, num_rows));

		snmp_poll_batch_t batch = {.items = poller_items, .oids = snmp_oids, .errors = &error_context};
		rows_processed = collect_poll_items(host, &batch, num_rows, spike_kill);

		poll_output_buffers_t output = write_poll_results(mysql, mysqlr, &queries, poller_items, rows_processed, host_time);
		query3 = output.output;
		query12 = output.boost;
		output_failed = output.failed;

		/* cleanup memory and prepare for function exit */
		if (host->snmp.session != NULL) {
			snmp_host_cleanup(host->snmp.session);
			host->snmp.session = NULL;
		}

		SPINE_FREE(query3);
		if (query12 != NULL) {
			SPINE_FREE(query12);
		}

		SPINE_FREE(poller_items);
		SPINE_FREE(snmp_oids);
	} else {
		/* free the mysql result */
		db_free_result(result);
	}

	SPINE_FREE(host);
	SPINE_FREE(reindex);
	SPINE_FREE(ping);

	complete_poll_host(mysql, &queries, work, &error_context, output_failed, poll_failed, poll_time);

	release_poll_connections(work, local_cnn, remote_cnn);

	mysql_thread_end();

	SPINE_LOG_DEVICE(host_id, POLLER_VERBOSITY_DEBUG, ("Device[%i] HT[%i] DEBUG: HOST COMPLETE: About to Exit Device Polling Thread Function", host_id, host_thread));

	if (set.logging.spine_log_level == 1) {
		buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, 0, true);
	}

	SPINE_FREE(error_string);
	SPINE_FREE(buf_size);
	SPINE_FREE(buf_errors);

	*host_errors = errors;
}

/*! \fn void buffer_output_errors(local_data_id) {
 *  \brief buffers output errors and pushes those errors to standard
 *         output as required.
 *  \param char* buffer - pointer to the output buffer
 *  \param int device_id - the device id
 *  \param int thread id - the device thread
 *  \param int local_data_id - the local data id
 *  \param boolean flush - flush any part of buffer
 */
void buffer_output_errors(char *error_string, int *buf_size, int *buf_errors, int device_id, int thread_id, int local_data_id, bool flush) {
	int error_len;
	char tbuffer[SMALL_BUFSIZE];

	if (flush && *buf_errors > 0) {
		SPINE_LOG(("WARNING: Invalid Response(s), Errors[%i] Device[%i] Thread[%i] DS[%s]", *buf_errors, device_id, thread_id, error_string));
	} else if (!flush) {
		snprintf(tbuffer, SMALL_BUFSIZE, *buf_errors > 0 ? ", %i" : "%i", local_data_id);
		error_len = spine_count_to_int(strlen(tbuffer));
		if (*buf_size + error_len >= DBL_BUFSIZE) {
			SPINE_LOG(("WARNING: Invalid Response(s), Errors[%i] Device[%i] Thread[%i] DS[%s]", *buf_errors, device_id, thread_id, error_string));
			*buf_errors  = 1;
			*buf_size = snprintf(error_string, DBL_BUFSIZE, "%i", local_data_id);
		} else {
			(*buf_errors)++;
			snprintf(error_string + *buf_size, DBL_BUFSIZE - *buf_size, "%s", tbuffer);
			*buf_size += error_len;
		}
	}
}

/*! \fn int is_multipart_output(const char *result)
 *  \brief validates the output syntax is a valid name value pair syntax
 *  \param result the value to be checked for legality
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return TRUE if the result is valid, otherwise FALSE.
 *
 */
int is_multipart_output(const char *result) {
	if (result == NULL) return FALSE;
	if (strchr(result, ':') == NULL && strchr(result, '!') == NULL) return FALSE;
	if (strchr(result, ' ') == NULL) return TRUE;

	size_t space_cnt = 0;
	size_t delim_cnt = 0;
	for (const char *cursor = result; *cursor != '\0'; cursor++) {
		if (*cursor == ':' || *cursor == '!') delim_cnt++;
		else if (*cursor == ' ') space_cnt++;
	}
	return space_cnt + 1 == delim_cnt;
}

static void poll_system_uptime(host_t *host) {
	char *poll_result;
	// Get the legacy system uptime instance first
	SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.2.1.1.3.0');", host->id));
	poll_result = snmp_get_allow_fail(host, ".1.3.6.1.2.1.1.3.0");
	SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.2.1.1.3.0'); [complete]", host->id));

	if (poll_result && is_numeric(poll_result)) {
		host->system.snmp_sysUpTimeInstance = atoll(poll_result);
		SPINE_FREE(poll_result);

		// Attempt to get the more modern version
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.6.3.10.2.1.3.0');", host->id));
		poll_result = snmp_get_allow_fail(host, ".1.3.6.1.6.3.10.2.1.3.0");
		SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.6.3.10.2.1.3.0'); [complete]", host->id));

		if (poll_result && is_numeric(poll_result)) {
			host->system.snmp_sysUpTimeInstance = atoll(poll_result) * 100;
		}
	}
	SPINE_FREE(poll_result);
}

static void poll_system_field(host_t *host, MYSQL *mysql, char *oid, char *destination, size_t capacity) {
	SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] requesting system OID %s", host->id, oid));
	char *result = snmp_get_allow_fail(host, oid);
	if (result != NULL) db_escape(mysql, destination, (int)capacity, result);
	SPINE_FREE(result);
}

void get_system_information(host_t *host, MYSQL *mysql, int system) {
	SPINE_LOG_MEDIUM(("Device[%d] Checking for System Information Update", host->id));
	bool full = set.snmp.mibs || system;
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%d] Updating %s System Information Table", host->id, full ? "Full" : "Short"));
	if (full) {
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.1.0", host->system.snmp_sysDescr, sizeof(host->system.snmp_sysDescr));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.2.0", host->system.snmp_sysObjectID, sizeof(host->system.snmp_sysObjectID));
	}
	poll_system_uptime(host);
	if (full) {
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.4.0", host->system.snmp_sysContact, sizeof(host->system.snmp_sysContact));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.5.0", host->system.snmp_sysName, sizeof(host->system.snmp_sysName));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.6.0", host->system.snmp_sysLocation, sizeof(host->system.snmp_sysLocation));
	}
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
		} else {
			if (is_multipart_output(trim(result))) {
				return TRUE;
			} else {
				return FALSE;
			}
		}
	}

	return FALSE;
}

static int acquire_script_permit(const host_t *host) {
	if (set.php.script_timeout <= 0) return EINVAL;
	/* Preserve the existing retry budget without signed multiplication overflow. */
	uint64_t attempts = (uint64_t)set.php.script_timeout * 15;
	int error = EAGAIN;
	for (uint64_t retry = 1; retry < attempts; retry++) {
		error = spine_permits_try_acquire(&available_scripts);
		if (error == 0) return 0;
		if (error == EAGAIN || error == EWOULDBLOCK) {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEVDBG, ("Device[%i] DEBUG: Pausing as unable to obtain a script execution lock", host->id));
		} else {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEVDBG, ("Device[%i] DEBUG: Pausing as error %d whilst obtaining a script execution lock", host->id, error));
		}
		spine_sleep_usec(10000);
	}
	return error;
}

typedef struct {
	const host_t *host;
	const char *command;
	int id;
	const char *type;
} script_result_context_t;

/* Return whether the legacy popen backend may close without blocking on a
 * timed-out command; nft_popen owns and reaps its registered child instead. */
static bool read_script_result(const script_result_context_t *context, int fd, double deadline, char *result) {
	int ready = spine_wait_readable(fd, deadline);
	if (ready < 0) {
		switch (errno) {
			case EBADF:
				SPINE_LOG(("Device[%i] ERROR: One or more of the file descriptor sets specified a file descriptor that is not a valid open file descriptor.", context->host->id));
				break;
			case EINVAL:
				SPINE_LOG(("Device[%i] ERROR: Possible invalid timeout specified in select() statement.", context->host->id));
				break;
			default:
				SPINE_LOG(("Device[%i] ERROR: The script/command select() failed", context->host->id));
				break;
		}
		SET_UNDEFINED(result);
		return FALSE;
	}
	if (ready == 0) {
		SPINE_LOG_MEDIUM(("Device[%i] ERROR: The NIFTY POPEN timed out", context->host->id));
		int pid = nft_pchild(fd);
		if (pid > 1) {
			/* nft_popen() made the script a group leader; take its descendants too. */
			kill(-pid, SIGKILL);
		} else {
			SPINE_LOG(("Device[%i] ERROR: Unable to find the timed-out POPEN child", context->host->id));
		}
		SET_UNDEFINED(result);
		return FALSE;
	}
	/* Preserve the single-read response contract; later output is ignored. */
	ssize_t bytes = read(fd, result, RESULTS_BUFFER - 1);
	if (bytes > 0 && bytes < RESULTS_BUFFER) {
		result[bytes] = '\0';
	} else {
		char script[SMALL_BUFSIZE];

		php_command_script(context->command, script, sizeof(script));
		if (STRIMATCH(context->type, "DS")) {
			SPINE_LOG(("Device[%i] DS[%i] ERROR: Empty result [%s]: '%s'", context->host->id, context->id, context->host->hostname, script));
		} else {
			SPINE_LOG(("Device[%i] DQ[%i] ERROR: Empty result [%s]: '%s'", context->host->id, context->id, context->host->hostname, script));
		}
		SET_UNDEFINED(result);
	}
	return TRUE;
}

/*! \fn char *exec_poll(host_t *current_host, char *command, int id, char *type)
 *  \brief polls a host using a script
 *  \param current_host a pointer to the current host structure
 *  \param command the command to be executed
 *  \param id either the local_data_id or the data_query_id
 *
 *	This function will poll a specific host using the script pointed to by
 *  the command variable.
 *
 *  \return a pointer to a character buffer containing the result.
 *
 */
/* WARNING: command is passed to /bin/sh -c (via nft_popen) without shell escaping.
 * The caller MUST ensure command originates from a trusted source
 * (the Cacti database). Do not pass user-controlled input directly. */
char *exec_poll(host_t *current_host, char *command, int id, const char *type) {
	int cmd_fd;
	double deadline;
	char *proc_command;
	char *result_string;

	/* compensate for back slashes in arguments */
	#if defined(__CYGWIN__)
	proc_command = add_slashes(command);
	#else
	proc_command = command;
	#endif

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: poller.c exec_poll!");
	}

	/* set zeros */
	memset(result_string, 0, RESULTS_BUFFER);


	/* don't run too many scripts, operating systems do not like that. */
	int sem_err;
	int needs_cleanup = 0;

	/* used for checking executable status */
	char executable[BUFSIZE];
	char *saveptr = NULL;

	pthread_cleanup_push(child_cleanup_script, NULL);

	sem_err = acquire_script_permit(current_host);

	if (sem_err) {
		SPINE_LOG(("ERROR: Device[%i]: Failed to obtain a script execution lock (error %d)", current_host->id, sem_err));
		SET_UNDEFINED(result_string);
		#if defined(__CYGWIN__)
		SPINE_FREE(proc_command);
		#endif
	} else {
		/* Mark for cleanup */
		needs_cleanup = 1;

		/* record start time */
		deadline = spine_monotonic_time() + set.php.script_timeout;

		/* peel the executable from the command */
		saveptr = proc_command;
		spine_snprintf(executable, sizeof(executable), "%s", proc_command);
		strtok_r(executable, " ", &saveptr);

		/* cheesy little hack to add /usr/bin/ if its not included */
		if (strstr(executable, "/") == NULL) {
			saveptr = proc_command;
			spine_snprintf(executable, sizeof(executable), "/usr/bin/%s", proc_command);
			strtok_r(executable, " ", &saveptr);
		}

		/* executable is the first token; the arguments can carry credentials. */
		SPINE_LOG_DEBUG(("The executable is '%s'", executable));

		if (access(executable, X_OK | F_OK) != -1) {
			cmd_fd = nft_popen(proc_command, "r");
			SPINE_LOG_DEVICE(current_host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: The NIFTY POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));

			if (cmd_fd >= 0) {
				const script_result_context_t context = {current_host, command, id, type};
				(void)read_script_result(&context, cmd_fd, deadline, result_string);

				/* close pipe */
				nft_pclose(cmd_fd);
			} else {
				SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN [%s]: '%s'", current_host->id, current_host->hostname, executable));
				SET_UNDEFINED(result_string);
			}
		} else {
			SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN.  File '%s' does not exist or is not executable.", current_host->id, executable));
			SET_UNDEFINED(result_string);
		}

		#if defined(__CYGWIN__)
		SPINE_FREE(proc_command);
		#endif
	}

	/* reduce the active script count */
	pthread_cleanup_pop(needs_cleanup);

	return result_string;
}
