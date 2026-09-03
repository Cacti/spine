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

void child_cleanup(void *arg) {
	poller_thread_t poller_details = *(poller_thread_t*) arg;

	SPINE_LOG_DEVDBG(("Device[%i] HT[%i] DEBUG: The Device Thread has cleaned up.", poller_details.host_id, poller_details.host_thread));

	child_cleanup_thread(arg);
}

void child_cleanup_thread(void *arg) {
	UNUSED_PARAMETER(arg);
	spine_sem_post(&available_threads);

	int a_threads_value;
	spine_sem_getvalue(&available_threads, &a_threads_value);

	SPINE_LOG_DEVDBG(("DEBUG: Available Threads is %i (%i outstanding)", a_threads_value, set.threads - a_threads_value));
}

void child_cleanup_script(void *arg) {
	UNUSED_PARAMETER(arg);
	spine_sem_post(&available_scripts);

	int a_scripts_value;
	spine_sem_getvalue(&available_scripts, &a_scripts_value);

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

	int device_counter;
	int host_id;
	int host_thread;
	int host_threads;
	int host_data_ids;
	int host_errors;
	double host_time_double;
	char host_time[SMALL_BUFSIZE];

	host_errors = 0;

	poller_thread_t poller_details = *(poller_thread_t*) arg;

	device_counter   = poller_details.device_counter;
	host_id          = poller_details.host_id;
	host_thread      = poller_details.host_thread;
	host_threads     = poller_details.host_threads;
	host_data_ids    = poller_details.host_data_ids;
	host_time_double = poller_details.host_time_double;

	snprintf(host_time, SMALL_BUFSIZE, "%s", poller_details.host_time);

	thread_mutex_unlock(LOCK_HOST_TIME);

	/* Allows main thread to proceed with creation of other threads */
	spine_sem_post(poller_details.thread_init_sem);

	if (is_debug_device(host_id)) {
		SPINE_LOG(("Device[%i] HT[%i] DEBUG: In Poller, About to Start Polling", host_id, host_thread));
	} else {
		SPINE_LOG_DEBUG(("Device[%i] HT[%i] DEBUG: In Poller, About to Start Polling", host_id, host_thread));
	}

	poll_host(device_counter, host_id, host_thread, host_threads, host_data_ids, host_time, &host_errors, host_time_double);

	pthread_cleanup_pop(1);

	/* end the thread */
	pthread_exit(0);

	exit(0);
}

/*! \fn void poller_item_scope(char *out, size_t len, int poller_id)
 *  \brief The poller_item filter for the poller this process is running as.
 *
 *  The main poller reads every item that has not been deleted. A remote poller
 *  reads the items assigned to it, and ownership already excludes deleted rows.
 *  Kept in one place because poll_host() built the same pair of queries twice,
 *  once per branch, and a column added to one copy would not reach the other.
 */
void poller_item_scope(char *out, size_t len, int poller_id) {
	if (out == NULL || len == 0) {
		return;
	}

	if (poller_id == 0) {
		snprintf(out, len, " AND deleted = ''");
	} else {
		snprintf(out, len, " AND poller_id = %i", poller_id);
	}
}

/*! \fn void poller_owner_scope(char *out, size_t len, int poller_id)
 *  \brief The ownership filter applied only by a remote poller.
 *
 *  The main poller does not constrain these queries at all; a remote poller
 *  restricts them to its own rows. Returns an empty string for the main poller
 *  so the caller can interpolate it unconditionally.
 */
void poller_owner_scope(char *out, size_t len, int poller_id) {
	if (out == NULL || len == 0) {
		return;
	}

	if (poller_id == 0) {
		out[0] = '\0';
	} else {
		snprintf(out, len, " AND poller_id = %i", poller_id);
	}
}


/*! \fn void poll_host_build_queries(poll_host_queries_t *q, int host_id, const char *regex_col, const char *limits)
 *  \brief build every query poll_host() issues for one device
 *
 *  Split out of poll_host() so the construction can be reached from a test.
 *  It reads only its arguments and the settings named below, which is what
 *  makes it checkable: given the same inputs it produces the same SQL.
 *
 *  Reads set.poller_id, set.total_snmp_ports, set.dbonupdate,
 *  set.poller_interval and set.active_profiles.
 */
void poll_host_build_queries(poll_host_queries_t *q, int host_id, const char *regex_col, const char *limits) {
	char item_scope[SMALL_BUFSIZE];
	char owner_scope[SMALL_BUFSIZE];

	/* Scope every poller_item read to what this poller owns: the main poller
	   takes every undeleted row, a remote poller takes the rows assigned to it.
	   Both fragments are interpolated unconditionally, so the queries below do
	   not branch on poller_id and cannot drift apart. */
	poller_item_scope(item_scope, sizeof(item_scope), set.poller_id);
	poller_owner_scope(owner_scope, sizeof(owner_scope), set.poller_id);

	if (set.total_snmp_ports == 1) {
		snprintf(q->query1, BUFSIZE,
			"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
				"snmp_version, snmp_username, snmp_password, "
				"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
				"rrd_num, snmp_port, snmp_timeout, "
				"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
				"%s"
			" FROM poller_item"
			" WHERE host_id = %i"
			"%s %s", regex_col, host_id, item_scope, limits);
	} else {
		snprintf(q->query1, BUFSIZE,
			"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
				"snmp_version, snmp_username, snmp_password, "
				"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
				"rrd_num, snmp_port, snmp_timeout, "
				"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
				"%s"
			" FROM poller_item"
			" WHERE host_id = %i"
			"%s"
			" ORDER BY snmp_port %s", regex_col, host_id, item_scope, limits);
	}

	/* host structure for uptime checks */
	snprintf(q->query2, BIG_BUFSIZE,
		"SELECT SQL_NO_CACHE id, hostname, snmp_community, snmp_version, "
			"snmp_username, snmp_password, snmp_auth_protocol, "
			"snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id, snmp_port, snmp_timeout, max_oids, "
			"availability_method, ping_method, ping_port, ping_timeout, ping_retries, "
			"status, status_event_count, UNIX_TIMESTAMP(status_fail_date), "
			"UNIX_TIMESTAMP(status_rec_date), status_last_error, "
			"min_time, max_time, cur_time, avg_time, "
			"total_polls, failed_polls, availability, snmp_sysUpTimeInstance, snmp_sysDescr, snmp_sysObjectID, "
			"snmp_sysContact, snmp_sysName, snmp_sysLocation"
		" FROM host"
		" WHERE id = %i"
		" AND deleted = ''", host_id);

	/* data query structure for reindex detection */
	snprintf(q->query4, BUFSIZE,
		"SELECT SQL_NO_CACHE data_query_id, action, op, assert_value, arg1"
			" FROM poller_reindex"
			" WHERE host_id = %i", host_id);

	/* multiple polling interval query for items */
	if (set.active_profiles != 1) {
		if (set.total_snmp_ports == 1) {
			snprintf(q->query5, BUFSIZE,
				"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
					"snmp_version, snmp_username, snmp_password, "
					"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
					"rrd_num, snmp_port, snmp_timeout, "
					"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
					"%s"
				" FROM poller_item"
				" WHERE host_id = %i"
				" AND rrd_next_step <= 0"
				"%s %s", regex_col, host_id, owner_scope, limits);
		} else {
			snprintf(q->query5, BUFSIZE,
				"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
					"snmp_version, snmp_username, snmp_password, "
					"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
					"rrd_num, snmp_port, snmp_timeout, "
					"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
					"%s"
				" FROM poller_item"
				" WHERE host_id = %i"
				" AND rrd_next_step <= 0"
				"%s"
				" ORDER BY snmp_port %s", regex_col, host_id, owner_scope, limits);
		}
	} else {
		if (set.total_snmp_ports == 1) {
			snprintf(q->query5, BUFSIZE,
				"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
					"snmp_version, snmp_username, snmp_password, "
					"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
					"rrd_num, snmp_port, snmp_timeout, "
					"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
					"%s"
				" FROM poller_item"
				" WHERE host_id = %i"
				"%s %s", regex_col, host_id, owner_scope, limits);
		} else {
			snprintf(q->query5, BUFSIZE,
				"SELECT SQL_NO_CACHE action, hostname, snmp_community, "
					"snmp_version, snmp_username, snmp_password, "
					"rrd_name, rrd_path, arg1, arg2, arg3, local_data_id, "
					"rrd_num, snmp_port, snmp_timeout, "
					"snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id"
					"%s"
				" FROM poller_item"
				" WHERE host_id = %i"
				"%s"
				" ORDER BY snmp_port %s", regex_col, host_id, owner_scope, limits);
		}
	}

	/* query to setup the next polling interval in cacti */
	snprintf(q->query6, BUFSIZE,
		"UPDATE poller_item"
		" SET rrd_next_step = IF(rrd_step = %i, 0, IF(rrd_next_step - %i < 0, rrd_step - %i, rrd_next_step - %i))"
		" WHERE host_id = %i%s", set.poller_interval, set.poller_interval, set.poller_interval, set.poller_interval, host_id, owner_scope);

	/* query to add output records to the poller output table */
	snprintf(q->query8, BUFSIZE,
		"INSERT INTO poller_output"
		" (local_data_id, rrd_name, time, output) VALUES");

	/* query suffix to add rows to the poller output table */
	if (set.dbonupdate == 0) {
		snprintf(q->posuffix, BUFSIZE,
			" ON DUPLICATE KEY UPDATE output=VALUES(output)");
	} else {
		snprintf(q->posuffix, BUFSIZE,
			" AS rs ON DUPLICATE KEY UPDATE output=rs.output");
	}

	/* number of agent's count for single polling interval */
	snprintf(q->query9, BUFSIZE,
		"SELECT SQL_NO_CACHE snmp_port, count(snmp_port)"
		" FROM poller_item"
		" WHERE host_id = %i"
		"%s"
		" GROUP BY snmp_port %s", host_id, owner_scope, limits);

	/* number of agent's count for multiple polling intervals */
	if (set.active_profiles != 1) {
		snprintf(q->query10, BUFSIZE,
			"SELECT SQL_NO_CACHE snmp_port, count(snmp_port)"
			" FROM poller_item"
			" WHERE host_id = %i"
			" AND rrd_next_step <= 0"
			"%s"
			" GROUP BY snmp_port %s", host_id, owner_scope, limits);
	} else {
		snprintf(q->query10, BUFSIZE,
			"SELECT SQL_NO_CACHE snmp_port, count(snmp_port)"
			" FROM poller_item"
			" WHERE host_id = %i"
			"%s"
			" GROUP BY snmp_port %s", host_id, owner_scope, limits);
	}

	/* query to add output records to the poller output table */
	snprintf(q->query11, BUFSIZE,
		"INSERT INTO poller_output_boost"
		" (local_data_id, rrd_name, time, output) VALUES");

	q->query8_len   = strlen(q->query8);
	q->query11_len  = strlen(q->query11);
	q->posuffix_len = strlen(q->posuffix);
}

/*! \fn int poller_store_result(target_t *item, char *poll_result, char *error_string, int *buf_size, int *buf_errors, int host_id, int host_thread)
 *  \brief normalise one polled value and store it on the target
 *
 *  The same thirty-three lines ran after exec_poll() and after php_cmd(). They
 *  were identical, which is the only reason the two paths still agreed on what
 *  a valid result is.
 *
 *  Four outcomes, in order:
 *    - undefined, which is the poller reporting it got nothing usable
 *    - already numeric, or a multi-part "name:value" line, stored as it stands
 *    - hexadecimal, converted to decimal
 *    - anything else, stripped to its numeric part and then validated; a value
 *      that still does not validate becomes undefined
 *
 *  \return TRUE when the result was rejected, so the caller counts an error
 */
int poller_store_result(target_t *item, char *poll_result, char *error_string,
	int *buf_size, int *buf_errors, int host_id, int host_thread) {
	char temp_result[RESULTS_BUFFER];

	if (item == NULL || poll_result == NULL) {
		return FALSE;
	}

	if (IS_UNDEFINED(poll_result)) {
		SET_UNDEFINED(item->result);
		buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, item->local_data_id, false);

		if (set.spine_log_level == 2) {
			SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SCRIPT: %s, output: %s",
				host_id, host_thread, item->local_data_id,
				item->arg1, item->result));
		}

		return TRUE;
	}

	if ((is_numeric(poll_result)) || (is_multipart_output(trim(poll_result)))) {
		snprintf(item->result, RESULTS_BUFFER, "%s", poll_result);
		return FALSE;
	}

	if (is_hexadecimal(poll_result, TRUE)) {
		snprintf(item->result, RESULTS_BUFFER, "%llu", hex2dec(poll_result));
		return FALSE;
	}

	/* remove double or single quotes from string */
	snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(REGEX_NUMBER, strip_alpha(poll_result)));
	snprintf(item->result, RESULTS_BUFFER, "%s", temp_result);

	/* detect erroneous result. can be non-numeric */
	if (!validate_result(item->result)) {
		buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, item->local_data_id, false);

		if (set.spine_log_level == 2) {
			SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SCRIPT: %s, output: %s",
				host_id, host_thread, item->local_data_id,
				item->arg1, item->result));
		}

		SET_UNDEFINED(item->result);
		return TRUE;
	}

	return FALSE;
}

/*! \fn int poller_output_tuple(char *out, size_t out_len, MYSQL *mysql, const target_t *item, const char *host_time)
 *  \brief format one poller_output row for the batched INSERT
 *
 *  Escapes the two free-text columns and writes the VALUES tuple. The leading
 *  space is deliberate: the caller overwrites out[0] with a comma for every
 *  tuple after the first, which is how the list is joined without tracking a
 *  separate delimiter.
 *
 *  The escape destination is twice the source plus a terminator, because
 *  mysql_real_escape_string() can double every byte. Sizing it from the source
 *  buffer instead is what truncated results at 1022 bytes; see #583.
 *
 *  \return the length written, which the caller uses to decide whether the
 *          batch buffer has room for it
 */
int poller_output_tuple(char *out, size_t out_len, MYSQL *mysql, const target_t *item, const char *host_time) {
	char escaped_result[(RESULTS_BUFFER * 2) + 1];
	char escaped_rrd_name[DBL_BUFSIZE];

	if (out == NULL || out_len == 0 || item == NULL || host_time == NULL) {
		return 0;
	}

	db_escape(mysql, escaped_result, sizeof(escaped_result), item->result);
	db_escape(mysql, escaped_rrd_name, sizeof(escaped_rrd_name), item->rrd_name);

	snprintf(out, out_len, " (%i, '%s', FROM_UNIXTIME(%s), '%s')",
		item->local_data_id,
		escaped_rrd_name,
		host_time,
		escaped_result);

	return (int) strlen(out);
}

/*! \fn void poller_item_from_row(target_t *item, MYSQL_ROW row)
 *  \brief map one poller_item row onto a target
 *
 *  Split out of poll_host() so the mapping can be reached from a test.
 *  Every column is optional: a NULL leaves the default below in place, so
 *  a row missing snmp_port still polls on 161 rather than 0.
 *
 *  output_regex is read only when the schema has it, which is Cacti 1.3.1
 *  and later. On an older schema the column is not in the select at all.
 */
void poller_item_from_row(target_t *item, MYSQL_ROW row) {
	if (item == NULL || row == NULL) {
		return;
	}

	/* initialize monitored object */
	item->target_id                = 0;
	item->action                   = -1;
	item->hostname[0]              = '\0';
	item->snmp_community[0]        = '\0';
	item->snmp_version             = 1;
	item->snmp_username[0]         = '\0';
	item->snmp_password[0]         = '\0';
	item->snmp_auth_protocol[0]    = '\0';
	item->snmp_priv_passphrase[0]  = '\0';
	item->snmp_priv_protocol[0]    = '\0';
	item->snmp_context[0]          = '\0';
	item->snmp_engine_id[0]        = '\0';
	item->snmp_port                = 161;
	item->snmp_timeout             = 500;
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
	if (row[2] != NULL)  snprintf(item->snmp_community, sizeof(item->snmp_community), "%s", row[2]);

	if (row[3] != NULL)  item->snmp_version = atoi(row[3]);

	if (row[4] != NULL)  snprintf(item->snmp_username, sizeof(item->snmp_username), "%s", row[4]);
	if (row[5] != NULL)  snprintf(item->snmp_password, sizeof(item->snmp_password), "%s", row[5]);

	if (row[6]  != NULL) snprintf(item->rrd_name,      sizeof(item->rrd_name),      "%s", row[6]);
	if (row[7]  != NULL) snprintf(item->rrd_path,      sizeof(item->rrd_path),      "%s", row[7]);
	if (row[8]  != NULL) snprintf(item->arg1,          sizeof(item->arg1),          "%s", row[8]);
	if (row[9]  != NULL) snprintf(item->arg2,          sizeof(item->arg2),          "%s", row[9]);
	if (row[10] != NULL) snprintf(item->arg3,          sizeof(item->arg3),          "%s", row[10]);

	if (row[11] != NULL) item->local_data_id = atoi(row[11]);

	if (row[12] != NULL) item->rrd_num       = atoi(row[12]);
	if (row[13] != NULL) item->snmp_port     = atoi(row[13]);
	if (row[14] != NULL) item->snmp_timeout  = atoi(row[14]);

	if (row[15] != NULL)  snprintf(item->snmp_auth_protocol,
		sizeof(item->snmp_auth_protocol), "%s", row[15]);
	if (row[16] != NULL)  snprintf(item->snmp_priv_passphrase,
		sizeof(item->snmp_priv_passphrase), "%s", row[16]);
	if (row[17] != NULL)  snprintf(item->snmp_priv_protocol,
		sizeof(item->snmp_priv_protocol), "%s", row[17]);
	if (row[18] != NULL)  snprintf(item->snmp_context,
		sizeof(item->snmp_context), "%s", row[18]);
	if (row[19] != NULL)  snprintf(item->snmp_engine_id,
		sizeof(item->snmp_engine_id), "%s", row[19]);

	if (set.has_output_regex && row[20] != NULL)
		snprintf(item->output_regex,
			sizeof(item->output_regex), "%s", row[20]);

	SET_UNDEFINED(item->result);
}

/*! \fn int reindex_assert_failed(const char *op, const char *assert_value, const char *poll_result)
 *  \brief decide whether a data query reindex assert has been violated
 *
 *  The assert reads assert_value op poll_result, and fails when that relation
 *  does not hold. Cacti stores only three operators.
 *
 *  Two details are load-bearing and were easy to miss while this was spelled
 *  out three times inside poll_host():
 *
 *  - '=' compares as text, '<' and '>' as numbers. A device reporting "007"
 *    equals "7" numerically but not textually.
 *  - an assert_value of "0" never fails a '<' assert. That is the uptime case:
 *    a device that has not reported an uptime yet must not look like it
 *    rebooted.
 *
 *  Equality does not fail '<' or '>'; only a strict violation does.
 *
 *  \return TRUE when the assert failed and the data query should be reindexed
 */
int reindex_assert_failed(const char *op, const char *assert_value, const char *poll_result) {
	if (op == NULL || assert_value == NULL || poll_result == NULL) {
		return FALSE;
	}

	/* the host is up but gave us nothing usable, so assume the assert holds */
	if (IS_UNDEFINED(poll_result) || STRIMATCH(poll_result, "No Such Instance")) {
		return FALSE;
	}

	if (STRMATCH(op, "=")) {
		return strcmp(assert_value, poll_result) != 0;
	}

	if (STRMATCH(op, ">")) {
		return atoll(assert_value) < atoll(poll_result);
	}

	if (STRMATCH(op, "<")) {
		if (STRMATCH(assert_value, "0")) {
			return FALSE;
		}

		return atoll(assert_value) > atoll(poll_result);
	}

	return FALSE;
}

/*! \fn void poll_host_release(host_t **host, reindex_t **reindex, ping_t **ping, char **error_string, int **buf_size, int **buf_errors, pool_t *local_cnn, pool_t *remote_cnn, int host_id, int host_thread)
 *  \brief release everything poll_host() owns, on every exit path
 *
 *  poll_host() leaves through three places and each used to spell this out
 *  again. The copies were not in the same order and did not contain the same
 *  steps: the device-row-missing path never called mysql_thread_end(), which
 *  leaks the client library's thread-local state once per affected device per
 *  cycle on a thread-per-device poller. See #594.
 */
void poll_host_release_connections(pool_t *local_cnn, pool_t *remote_cnn, int host_id, int host_thread) {
	if (local_cnn != NULL) {
		db_release_connection(LOCAL, local_cnn->id);
	} else {
		SPINE_LOG(("WARNING: Device[%i] HT[%i] Trying to close uninitialized local connection.", host_id, host_thread));
	}

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		if (remote_cnn != NULL) {
			db_release_connection(REMOTE, remote_cnn->id);
		} else {
			SPINE_LOG(("WARNING: Device[%i] HT[%i] Trying to close uninitialized remote connection.", host_id, host_thread));
		}
	}
}

void poll_host_release(host_t **host, reindex_t **reindex, ping_t **ping,
	char **error_string, int **buf_size, int **buf_errors,
	pool_t *local_cnn, pool_t *remote_cnn, int host_id, int host_thread) {

	poll_host_release_connections(local_cnn, remote_cnn, host_id, host_thread);

	SPINE_FREE(*host);
	SPINE_FREE(*reindex);
	SPINE_FREE(*ping);
	SPINE_FREE(*error_string);
	SPINE_FREE(*buf_size);
	SPINE_FREE(*buf_errors);

	mysql_thread_end();
}

/*! \fn void poll_host(int device_counter, int host_id, int host_thread, int host_threads, int host_data_ids, char *host_time, int *host_errors, double host_time_double)
 *  \brief core Spine function that polls a host
 *  \param host_id integer value for the host_id from the hosts table in Cacti
 *
 *	This function is core to Spine.  It will take a host_id and then poll it.
 *
 *  Prior to the poll, the system will ping the host to verify that it is up.
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
void poll_host(int device_counter, int host_id, int host_thread, int host_threads, int host_data_ids, char *host_time, int *host_errors, double host_time_double) {
	poll_host_queries_t q;
	char *query3 = NULL;
	char *query12 = NULL;


	char sysUptime[BUFSIZE];
	char result_string[POLLER_OUTPUT_TUPLE_MAX];
	int  result_length;
	char temp_result[RESULTS_BUFFER];
	int  errors = 0;
	int  *buf_errors;
	int  *buf_size;
	char *error_string;

	int    num_rows;
	int    assert_fail = FALSE;
	int    reindex_err = FALSE;
	int    spike_kill = FALSE;
	int    rows_processed = 0;
	int    i = 0;
	int    j = 0;
	int    k = 0;
	int    num_oids = 0;
	size_t out_buffer;
	int    php_process;

	char *poll_result = NULL;
	char update_sql[BIG_BUFSIZE];
	char temp_poll_result[BUFSIZE];
	char temp_arg1[BUFSIZE];
	char limits[SMALL_BUFSIZE];

	int  last_snmp_version = 0;
	int  last_snmp_port    = 0;
	char last_snmp_community[50];
	char last_snmp_username[50];
	char last_snmp_password[50];
	char last_snmp_auth_protocol[7];
	char last_snmp_priv_passphrase[200];
	char last_snmp_priv_protocol[8];
	char last_snmp_context[65];
	char last_snmp_engine_id[30];
	double poll_time = get_time_as_double();
	double thread_start = 0;
	double thread_end = 0;

	/* reindex shortcuts to speed polling */
	int previous_assert_failure = FALSE;
	int last_data_query_id      = 0;
	int perform_assert          = TRUE;
	int new_buffer              = TRUE;
	int ignore_sysinfo          = TRUE;
	int buf_length              = 0;

	extern poller_thread_t** details;

	pool_t *local_cnn = NULL;
	pool_t *remote_cnn = NULL;

	reindex_t   *reindex = NULL;
	host_t      *host = NULL;
	ping_t      *ping = NULL;
	name_t      *name = NULL;
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

	*buf_size     = 0;
	*buf_errors   = 0;

	MYSQL     mysql;
	MYSQL     mysqlr;
	MYSQL     mysqlt;
	MYSQL_RES *result;
	MYSQL_ROW row;

	//db_connect(LOCAL, &mysql);
	local_cnn = db_get_connection(LOCAL);
	mysql = local_cnn->mysql;

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		remote_cnn = db_get_connection(REMOTE);
		mysqlr = remote_cnn->mysql;
	}

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

	/* determine the SQL limits using the poller instructions */
	if (host_data_ids > 0) {
		snprintf(limits, SMALL_BUFSIZE, "LIMIT %i, %i", host_data_ids * (host_thread - 1), host_data_ids);
	} else {
		limits[0] = '\0';
	}

	/* optional output_regex column (added in Cacti 1.3.1) */
	const char *regex_col = set.has_output_regex ? ", output_regex" : "";

	poll_host_build_queries(&q, host_id, regex_col, limits);

	/* initialize the ping structure variables */
	snprintf(ping->ping_status,   50,            "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "Ping not performed due to setting.");
	snprintf(ping->snmp_status,   50,            "down");
	snprintf(ping->snmp_response, SMALL_BUFSIZE, "SNMP not performed due to setting or ping result");

	/* if the host is a real host.  Note host_id=0 is not host based data source */
	if (host_id) {
		/* get data about this host */
		if ((result = db_query(&mysql, LOCAL, q.query2)) != 0) {
			num_rows = mysql_num_rows(result);

			if (num_rows != 1) {
				db_free_result(result);

				goto cleanup;
			}

			/* fetch the result */
			row = mysql_fetch_row(result);

			if (row) {
				/* initialize variables first */
				host->id                      = 0;                 // 0
				host->hostname[0]             = '\0';              // 1
				host->snmp_session            = NULL;              // -
				host->snmp_community[0]       = '\0';              // 2
				host->snmp_version            = 1;                 // 3
				host->snmp_username[0]        = '\0';              // 4
				host->snmp_password[0]        = '\0';              // 5
				host->snmp_auth_protocol[0]   = '\0';              // 6
				host->snmp_priv_passphrase[0] = '\0';              // 7
				host->snmp_priv_protocol[0]   = '\0';              // 8
				host->snmp_context[0]         = '\0';              // 9
				host->snmp_engine_id[0]       = '\0';              // 10
				host->snmp_port               = 161;               // 11
				host->snmp_timeout            = 500;               // 12
				host->snmp_retries            = set.snmp_retries;  // -
				host->max_oids                = 10;                // 13
				host->availability_method     = 0;                 // 14
				host->ping_method             = 0;                 // 15
				host->ping_port               = 23;                // 16
				host->ping_timeout            = 500;               // 17
				host->ping_retries            = 2;                 // 18
				host->status                  = HOST_UP;           // 19
				host->status_event_count      = 0;                 // 20
				host->status_fail_date[0]     = '\0';              // 21
				host->status_rec_date[0]      = '\0';              // 22
				host->status_last_error[0]    = '\0';              // 23
				host->min_time                = 0;                 // 24
				host->max_time                = 0;                 // 25
				host->cur_time                = 0;                 // 26
				host->avg_time                = 0;                 // 27
				host->total_polls             = 0;                 // 28
				host->failed_polls            = 0;                 // 29
				host->availability            = 100;               // 30
				host->snmp_sysUpTimeInstance  = 0;                 // 31
				host->snmp_sysDescr[0]        = '\0';              // 32
				host->snmp_sysObjectID[0]     = '\0';              // 33
				host->snmp_sysContact[0]      = '\0';              // 34
				host->snmp_sysName[0]         = '\0';              // 35
				host->snmp_sysLocation[0]     = '\0';              // 36

				/* populate host structure */
				host->ignore_host = FALSE;
				if (row[0]  != NULL) host->id = atoi(row[0]);

				if (row[1]  != NULL) {
					name = get_namebyhost(row[1], NULL);
					STRNCOPY(host->hostname, name->hostname);
					host->ping_port = name->port;
					SPINE_FREE(name);
				}

				if (row[2]  != NULL) STRNCOPY(host->snmp_community,       row[2]);

				if (row[3]  != NULL) host->snmp_version = atoi(row[3]);

				if (row[4]  != NULL) STRNCOPY(host->snmp_username,        row[4]);
				if (row[5]  != NULL) STRNCOPY(host->snmp_password,        row[5]);
				if (row[6]  != NULL) STRNCOPY(host->snmp_auth_protocol,   row[6]);
				if (row[7]  != NULL) STRNCOPY(host->snmp_priv_passphrase, row[7]);
				if (row[8]  != NULL) STRNCOPY(host->snmp_priv_protocol,   row[8]);
				if (row[9]  != NULL) STRNCOPY(host->snmp_context,         row[9]);
				if (row[10]  != NULL) STRNCOPY(host->snmp_engine_id,       row[10]);

				if (row[11] != NULL) host->snmp_port           = atoi(row[11]);
				if (row[12] != NULL) host->snmp_timeout        = atoi(row[12]);
				if (row[13] != NULL) host->max_oids            = atoi(row[13]);

				if (row[14] != NULL) host->availability_method = atoi(row[14]);
				if (row[15] != NULL) host->ping_method         = atoi(row[15]);
				if (row[16] != NULL) host->ping_port           = atoi(row[16]);
				if (row[17] != NULL) host->ping_timeout        = atoi(row[17]);
				if (row[18] != NULL) host->ping_retries        = atoi(row[18]);

				if (row[19] != NULL) host->status              = atoi(row[19]);
				if (row[20] != NULL) host->status_event_count  = atoi(row[20]);

				if (row[21] != NULL) STRNCOPY(host->status_fail_date, row[21]);
				if (row[22] != NULL) STRNCOPY(host->status_rec_date,  row[22]);

				if (row[23] != NULL) STRNCOPY(host->status_last_error, row[23]);

				if (row[24] != NULL) host->min_time     = atof(row[24]);
				if (row[25] != NULL) host->max_time     = atof(row[25]);
				if (row[26] != NULL) host->cur_time     = atof(row[26]);
				if (row[27] != NULL) host->avg_time     = atof(row[27]);
				if (row[28] != NULL) host->total_polls  = atoi(row[28]);
				if (row[29] != NULL) host->failed_polls = atoi(row[29]);
				if (row[30] != NULL) host->availability = atof(row[30]);

				if (row[31] != NULL) host->snmp_sysUpTimeInstance=atoll(row[31]);
				if (row[32] != NULL) db_escape(&mysql, host->snmp_sysDescr, sizeof(host->snmp_sysDescr), row[32]);
				if (row[33] != NULL) db_escape(&mysql, host->snmp_sysObjectID, sizeof(host->snmp_sysObjectID), row[33]);
				if (row[34] != NULL) db_escape(&mysql, host->snmp_sysContact, sizeof(host->snmp_sysContact), row[34]);
				if (row[35] != NULL) db_escape(&mysql, host->snmp_sysName, sizeof(host->snmp_sysName), row[35]);
				if (row[36] != NULL) db_escape(&mysql, host->snmp_sysLocation, sizeof(host->snmp_sysLocation), row[36]);

				/* correct max_oid bounds issues */
				if ((host->max_oids == 0) || (host->max_oids > 100)) {
					SPINE_LOG(("Device[%i] HT[%i] WARNING: Max OIDS is out of range with value of '%i'.  Resetting to default of 5", host_id, host_thread, host->max_oids));
					host->max_oids = 5;
				}

				/* free the host result */
				db_free_result(result);

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
						host->snmp_engine_id,
						host->snmp_port,
						host->snmp_timeout);
				} else {
					host->snmp_session = NULL;
				}

				/* perform a check to see if the host is alive by polling it's SysDesc
				 * if the host down from an snmp perspective, don't poll it.
				 * function sets the ignore_host bit */
				if ((host->availability_method == AVAIL_SNMP) &&
					(strlen(host->snmp_community) == 0) &&
					(host->snmp_version < 3)) {
					host->ignore_host = FALSE;
					update_host_status(HOST_UP, host, ping, host->availability_method);

					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] HT[%i] No host availability check possible for '%s'", host->id, host_thread, host->hostname));
					} else {
						SPINE_LOG_MEDIUM(("Device[%i] HT[%i] No host availability check possible for '%s'", host->id, host_thread, host->hostname));
					}
				} else if (host->availability_method == AVAIL_STREAM) {
					update_host_status(HOST_UP, host, ping, host->availability_method);
				} else {
					if (ping_host(host, ping) == HOST_UP) {
						host->ignore_host = FALSE;
						if (host_thread == 1) {
							update_host_status(HOST_UP, host, ping, host->availability_method);

							if ((host->availability_method != AVAIL_PING) && (host->availability_method != AVAIL_NONE)) {
								if (host->snmp_session != NULL && set.mibs) {
									get_system_information(host, &mysql, 1);
									ignore_sysinfo = FALSE;
								}
							}
						}
					} else {
						host->ignore_host = TRUE;
						if (host_thread == 1) {
							update_host_status(HOST_DOWN, host, ping, host->availability_method);
						}
					}
				}

				/* update host table */
				if (host_thread == 1) {
					char escaped_last_error[BUFSIZE];
					db_escape(&mysql, escaped_last_error, sizeof(escaped_last_error), host->status_last_error);

					if (!ignore_sysinfo) {
						if (host->ignore_host != TRUE) {
							snprintf(update_sql, BIG_BUFSIZE, "UPDATE host "
								"SET status='%i', status_event_count='%i', status_fail_date=FROM_UNIXTIME(%s),"
									" status_rec_date=FROM_UNIXTIME(%s), status_last_error='%s', min_time='%f',"
									" max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
									" failed_polls='%i', availability='%.4f', snmp_sysDescr='%s', "
									" snmp_sysObjectID='%s', snmp_sysUpTimeInstance='%llu', "
									" snmp_sysContact='%s', snmp_sysName='%s', snmp_sysLocation='%s' "
								"WHERE id='%i'",
								host->status,
								host->status_event_count,
								host->status_fail_date,
								host->status_rec_date,
								escaped_last_error,
								host->min_time,
								host->max_time,
								host->cur_time,
								host->avg_time,
								host->total_polls,
								host->failed_polls,
								host->availability,
								host->snmp_sysDescr,
								host->snmp_sysObjectID,
								host->snmp_sysUpTimeInstance,
								host->snmp_sysContact,
								host->snmp_sysName,
								host->snmp_sysLocation,
								host->id);
						} else {
							snprintf(update_sql, BIG_BUFSIZE, "UPDATE host "
								"SET status='%i', status_event_count='%i', status_fail_date=FROM_UNIXTIME(%s),"
									" status_rec_date=FROM_UNIXTIME(%s), status_last_error='%s', min_time='%f',"
									" max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
									" failed_polls='%i', availability='%.4f' "
								"WHERE id='%i'",
								host->status,
								host->status_event_count,
								host->status_fail_date,
								host->status_rec_date,
								escaped_last_error,
								host->min_time,
								host->max_time,
								host->cur_time,
								host->avg_time,
								host->total_polls,
								host->failed_polls,
								host->availability,
								host->id);
						}
					} else {
						snprintf(update_sql, BIG_BUFSIZE, "UPDATE host "
							"SET status='%i', status_event_count='%i', status_fail_date=FROM_UNIXTIME(%s),"
								" status_rec_date=FROM_UNIXTIME(%s), status_last_error='%s', min_time='%f',"
								" max_time='%f', cur_time='%f', avg_time='%f', total_polls='%i',"
								" failed_polls='%i', availability='%.4f' "
							"WHERE id='%i'",
							host->status,
							host->status_event_count,
							host->status_fail_date,
							host->status_rec_date,
							escaped_last_error,
							host->min_time,
							host->max_time,
							host->cur_time,
							host->avg_time,
							host->total_polls,
							host->failed_polls,
							host->availability,
							host->id);
					}

					db_insert(&mysql, LOCAL, update_sql);
				}
			} else {
				SPINE_LOG(("Device[%i] HT[%i] ERROR: MySQL Returned a Null Device Result", host->id, host_thread));
				num_rows = 0;
				host->ignore_host = TRUE;
			}
		} else {
			num_rows = 0;
			host->ignore_host = TRUE;
		}
	} else {
		host->id           = 0;
		host->max_oids     = 1;
		host->snmp_session = NULL;
		host->ignore_host  = FALSE;
	}

	if (set.ping_only) {
		goto cleanup;
	}

	/* do the reindex check for this host if not script based */
	if ((!host->ignore_host) && (host_id)) {
		if ((result = db_query(&mysql, LOCAL, q.query4)) != 0) {
			num_rows = mysql_num_rows(result);

			if (num_rows > 0) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] HT[%i] DEBUG: RECACHE: Processing %i items in the auto reindex cache for '%s'", host->id, host_thread, num_rows, host->hostname));
				} else {
					SPINE_LOG_DEBUG(("Device[%i] HT[%i] DEBUG: RECACHE: Processing %i items in the auto reindex cache for '%s'", host->id, host_thread, num_rows, host->hostname));
				}

				// Cache uptime in case we need it again
				sysUptime[0] = '\0';
				while ((row = mysql_fetch_row(result))) {
					assert_fail = FALSE;
					reindex_err = FALSE;

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

					/* shortcut assertion checks if a data query reindex has already been queued */
					if ((last_data_query_id == reindex->data_query_id) &&
						(!previous_assert_failure)) {
						perform_assert = TRUE;
					} else if (last_data_query_id != reindex->data_query_id) {
						last_data_query_id = reindex->data_query_id;
						perform_assert = TRUE;
						previous_assert_failure = FALSE;
					} else {
						perform_assert = FALSE;
					}

					poll_result = NULL;

					if (perform_assert) {
						switch(reindex->action) {
						case POLLER_ACTION_SNMP: /* snmp */
							/* if there is no snmp session, don't probe */
							if (host->snmp_session == NULL) {
								reindex_err = TRUE;
							}

							/* check to see if you are checking uptime */
							if (!reindex_err) {
								if ((strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
									strstr(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")) && strlen(sysUptime) > 0) {

									if (!(poll_result = (char *) malloc(BUFSIZE))) {
										die("ERROR: Fatal malloc error: poller.c poll_result");
									}

									poll_result[0] = '\0';

									snprintf(poll_result, BUFSIZE, "%s", sysUptime);
								} else if (strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0")) {
								     // Ensure uptime is empty to start with
								     sysUptime[0] = '\0';

									// Check the legacy poll result first
									poll_result = snmp_get(host, reindex->arg1);

									if (poll_result && is_numeric(poll_result)) {
										snprintf(sysUptime, BUFSIZE, "%s", poll_result);
									}

									if (is_debug_device(host->id)) {
										SPINE_LOG(("Device[%i] HT[%i] DQ[%i] Legacy Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, is_numeric(poll_result) ));
									} else {
										SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] Legacy Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, is_numeric(poll_result) ));
									}

									SPINE_FREE(poll_result);

									/* check the modern snmp engine uptime in seconds */
									poll_result = snmp_get_base(host, ".1.3.6.1.6.3.10.2.1.3.0", false);

									if (poll_result && is_numeric(poll_result)) {
										snprintf(sysUptime, BUFSIZE, "%lld", atoll(poll_result) * 100);
									}

									SPINE_FREE(poll_result);

									/* allocate and populate with whichever uptime was valid */
									if (!(poll_result = (char *) malloc(BUFSIZE))) {
										die("ERROR: Fatal malloc error: poller.c poll_result");
									}
									snprintf(poll_result, BUFSIZE, "%s", sysUptime);

									if (is_debug_device(host->id)) {
										SPINE_LOG(("Device[%i] HT[%i] DQ[%i] Extended Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, is_numeric(poll_result) ));
									} else {
										SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] Extended Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, is_numeric(poll_result) ));
									}
								} else {
									poll_result = snmp_get(host, reindex->arg1);
								}

								if (is_debug_device(host->id)) {
									SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE OID: %s, (assert: %s %s output: %s)", host->id, host_thread, reindex->data_query_id, reindex->arg1, reindex->assert_value, reindex->op, poll_result));
								} else {
									SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE OID: %s, (assert: %s %s output: %s)", host->id, host_thread, reindex->data_query_id, reindex->arg1, reindex->assert_value, reindex->op, poll_result));
								}
							} else {
								SPINE_LOG(("WARNING: Device[%i] HT[%i] DQ[%i] Reindex Check FAILED: No SNMP Session.  If not an SNMP host, don't use Uptime Goes Backwards!", host->id, host_thread, reindex->data_query_id));
							}

							break;
						case POLLER_ACTION_SCRIPT: /* script (popen) */
							/* Reject empty script commands that could cause unexpected behavior */
							if (strlen(reindex->arg1) == 0) {
								SPINE_LOG(("WARNING: Device[%i] HT[%i] DQ[%i] empty script command, skipping",
									host->id, host_thread, reindex->data_query_id));
								break;
							}

							poll_result = trim(exec_poll(host, reindex->arg1, reindex->data_query_id, "DQ"));

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE CMD: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE CMD: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							}

							break;
						case POLLER_ACTION_PHP_SCRIPT_SERVER: /* script (php script server) */
							php_process = php_get_process();

							poll_result = trim(php_cmd(reindex->arg1, php_process));

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE SERVER: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE SERVER: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							}

							break;
						case POLLER_ACTION_SNMP_COUNT: /* snmp; count items */
							if (!(poll_result = (char *) malloc(BUFSIZE))) {
								die("ERROR: Fatal malloc error: poller.c poll_result");
							}
							poll_result[0] = '\0';

							snprintf(poll_result, BUFSIZE, "%d", snmp_count(host, reindex->arg1));

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE OID COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE OID COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							}

							break;
						case POLLER_ACTION_SCRIPT_COUNT: /* script (popen); count items by counting line feeds */
							if (!(poll_result = (char *) malloc(BUFSIZE))) {
								die("ERROR: Fatal malloc error: poller.c poll_result");
							}
							poll_result[0] = '\0';

							{
								char *ep_result = exec_poll(host, reindex->arg1, reindex->data_query_id, "DQ");
								snprintf(poll_result, BUFSIZE, "%d", char_count(ep_result, '\n'));
								free(ep_result);
							}

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE CMD COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE CMD COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							}

							break;
						case POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT: /* script (php script server); count number of lines */
							if (!(poll_result = (char *) malloc(BUFSIZE))) {
								die("ERROR: Fatal malloc error: poller.c poll_result");
							}
							poll_result[0] = '\0';

							php_process = php_get_process();

							{
								char *php_result = php_cmd(reindex->arg1, php_process);
								snprintf(poll_result, BUFSIZE, "%d", char_count(php_result, '\n'));
								free(php_result);
							}

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE SERVER COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DQ[%i] RECACHE SERVER COUNT: %s, output: %s", host->id, host_thread, reindex->data_query_id, reindex->arg1, poll_result));
							}

							break;
						default:
							SPINE_LOG(("Device[%i] HT[%i] ERROR: Unknown Assert Action!", host->id, host_thread));
						}

						if (!reindex_err) {
							if (!(query3 = (char *)malloc(LRG_BUFSIZE))) {
								die("ERROR: Fatal malloc error: poller.c reindex insert!");
							}
							query3[0] = '\0';

							/* assume ok if host is up and result wasn't obtained */
							/* assume ok if host is up and result was not obtained */
							if (poll_result == NULL || (IS_UNDEFINED(poll_result)) || (STRIMATCH(poll_result, "No Such Instance"))) {
								if (is_debug_device(host->id) || set.spine_log_level == 2) {
									SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE ASSERT FAILED: '%s=%s'", host->id, host_thread, reindex->data_query_id, reindex->assert_value, poll_result));
								}

								assert_fail = FALSE;
							} else if (reindex_assert_failed(reindex->op, reindex->assert_value, poll_result)) {
								if (is_debug_device(host->id) || set.spine_log_level == 2) {
									SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE ASSERT FAILED: '%s%s%s'", host->id, host_thread, reindex->data_query_id, reindex->assert_value, reindex->op, poll_result));
								} else {
									if (set.spine_log_level == 1) {
										errors++;
									}

									SPINE_LOG(("Device[%i] HT[%i] DQ[%i] RECACHE ASSERT FAILED: '%s%s%s'", host->id, host_thread, reindex->data_query_id, reindex->assert_value, reindex->op, poll_result));
								}

								if (host_thread == 1) {
									snprintf(query3, LRG_BUFSIZE, "REPLACE INTO poller_command (poller_id, time, action, command) VALUES (%i, NOW(), %i, '%i:%i')", set.poller_id, POLLER_COMMAND_REINDEX, host->id, reindex->data_query_id);

									if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
										db_insert(&mysqlr, REMOTE, query3);
									} else {
										db_insert(&mysql, LOCAL, query3);
									}

									/* set zeros */
									memset(query3, 0, LRG_BUFSIZE);
								}

								assert_fail = TRUE;
								previous_assert_failure = TRUE;
							}

							/* update 'poller_reindex' with the correct information if:
							 * 1) the assert fails
							 * 2) the OP code is > or < meaning the current value could have changed without causing
							 *     the assert to fail */
							if ((assert_fail) || (!strcmp(reindex->op, ">")) || (!strcmp(reindex->op, "<"))) {
								if (host_thread == 1) {
									db_escape(&mysql, temp_poll_result, sizeof(temp_poll_result), poll_result);
									db_escape(&mysql, temp_arg1, sizeof(temp_arg1), reindex->arg1);

									snprintf(query3, LRG_BUFSIZE, "UPDATE poller_reindex SET assert_value='%s' WHERE host_id='%i' AND data_query_id='%i' AND arg1='%s'", temp_poll_result, host_id, reindex->data_query_id, temp_arg1);

									db_insert(&mysql, LOCAL, query3);

									/* set zeros */
									memset(query3, 0, LRG_BUFSIZE);
								}

								if ((assert_fail) &&
									((!strcmp(reindex->op, "<")) || (!strcmp(reindex->arg1,".1.3.6.1.2.1.1.3.0") || !strcmp(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")))) {
									spike_kill = TRUE;

									if (is_debug_device(host->id) || set.spine_log_level == 2) {
										SPINE_LOG(("Device[%i] HT[%i] NOTICE: Spike Kill in Effect for '%s'", host_id, host_thread, host->hostname));
									} else {
										if (set.spine_log_level == 1) {
											errors++;
										}

										SPINE_LOG_MEDIUM(("Device[%i] HT[%i] NOTICE: Spike Kill in Effect for '%s'", host_id, host_thread, host->hostname));
									}
								}
							}

							SPINE_FREE(query3);
							SPINE_FREE(poll_result);
						}
					}
				}
			} else {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] HT[%i] Device has no information for recache.", host->id, host_thread));
				} else {
					SPINE_LOG_HIGH(("Device[%i] HT[%i] Device has no information for recache.", host->id, host_thread));
				}
			}

			/* free the host result */
			db_free_result(result);
		} else {
			SPINE_LOG(("Device[%i] HT[%i] ERROR: RECACHE Query Returned Null Result!", host->id, host_thread));
		}

		/* close the host snmp session, we will create again momentarily */
		if (host->snmp_session != NULL) {
			snmp_host_cleanup(host->snmp_session);
			host->snmp_session = NULL;
		}
	}

	/* calculate the number of poller items to poll this cycle */
	num_rows = 0;
	if (set.poller_interval == 0) {
		/* get the poller items */
		if ((result = db_query(&mysql, LOCAL, q.query1)) != 0) {
			num_rows = mysql_num_rows(result);
		} else {
			SPINE_LOG(("Device[%i] HT[%i] ERROR: Unable to Retrieve Rows due to Null Result!", host->id, host_thread));
		}
	} else {
		/* get the poller items */
		if ((result = db_query(&mysql, LOCAL, q.query5)) != 0) {
			num_rows = mysql_num_rows(result);
		} else {
			SPINE_LOG(("Device[%i] HT[%i] ERROR: Unable to Retrieve Rows due to Null Result!", host->id, host_thread));
		}
	}

	if (num_rows > 0) {
		/* retrieve each hosts polling items from poller cache and load into array */
		if (!(poller_items = (target_t *) calloc(num_rows, sizeof(target_t)))) {
			die("ERROR: Fatal calloc error: poller.c poller_items!");
		}

		i = 0;
		while ((row = mysql_fetch_row(result))) {
			poller_item_from_row(&poller_items[i], row);
			i++;
		}

		/* free the mysql result */
		db_free_result(result);

		/* create an array for snmp oids */
		if (!(snmp_oids = (snmp_oids_t *) calloc(host->max_oids, sizeof(snmp_oids_t)))) {
			die("ERROR: Fatal calloc error: poller.c snmp_oids!");
		}

		/* initialize all the memory to insure we don't get issues */
		memset(snmp_oids, 0, sizeof(snmp_oids_t)*host->max_oids);

		/* log an informative message */
		if (is_debug_device(host_id)) {
			SPINE_LOG(("Device[%i] HT[%i] NOTE: There are '%i' Polling Items for this Device", host_id, host_thread, num_rows));
		} else {
			SPINE_LOG_MEDIUM(("Device[%i] HT[%i] NOTE: There are '%i' Polling Items for this Device", host_id, host_thread, num_rows));
		}

		i = 0; k = 0;
		while ((i < num_rows) && (!host->ignore_host)) {
			thread_start = get_time_as_double();

			switch(poller_items[i].action) {
			case POLLER_ACTION_SNMP: /* raw SNMP poll */
				/* initialize or reinitialize snmp as required */
				if (k == 0) {
					last_snmp_port = poller_items[i].snmp_port;
					last_snmp_version = poller_items[i].snmp_version;

					STRNCOPY(last_snmp_community,       poller_items[i].snmp_community);
					STRNCOPY(last_snmp_username,        poller_items[i].snmp_username);
					STRNCOPY(last_snmp_password,        poller_items[i].snmp_password);
					STRNCOPY(last_snmp_auth_protocol,   poller_items[i].snmp_auth_protocol);
					STRNCOPY(last_snmp_priv_passphrase, poller_items[i].snmp_priv_passphrase);
					STRNCOPY(last_snmp_priv_protocol,   poller_items[i].snmp_priv_protocol);
					STRNCOPY(last_snmp_context,         poller_items[i].snmp_context);
					STRNCOPY(last_snmp_engine_id,       poller_items[i].snmp_engine_id);

					host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname,
						poller_items[i].snmp_version, poller_items[i].snmp_community,
						poller_items[i].snmp_username, poller_items[i].snmp_password,
						poller_items[i].snmp_auth_protocol, poller_items[i].snmp_priv_passphrase,
						poller_items[i].snmp_priv_protocol, poller_items[i].snmp_context,
						poller_items[i].snmp_engine_id,
						poller_items[i].snmp_port, poller_items[i].snmp_timeout);

					k++;
				}

				/* catch snmp initialization issues */
				if (host->snmp_session == NULL) {
					host->ignore_host = TRUE;
					break;
				}

				/* some snmp data changed from poller item to poller item.  therefore, poll host and store data */
				if ((last_snmp_port != poller_items[i].snmp_port) ||
					(last_snmp_version != poller_items[i].snmp_version) ||
					(poller_items[i].snmp_version < 3 &&
					(!STRMATCH(last_snmp_community, poller_items[i].snmp_community))) ||
					(poller_items[i].snmp_version > 2 &&
					((!STRMATCH(last_snmp_username, poller_items[i].snmp_username)) ||
					(!STRMATCH(last_snmp_password, poller_items[i].snmp_password)) ||
					(!STRMATCH(last_snmp_auth_protocol, poller_items[i].snmp_auth_protocol)) ||
					(!STRMATCH(last_snmp_priv_passphrase, poller_items[i].snmp_priv_passphrase)) ||
					(!STRMATCH(last_snmp_priv_protocol, poller_items[i].snmp_priv_protocol)) ||
					(!STRMATCH(last_snmp_context, poller_items[i].snmp_context)) ||
					(!STRMATCH(last_snmp_engine_id, poller_items[i].snmp_engine_id))))) {

					if (num_oids > 0) {
						snmp_get_multi(host, poller_items, snmp_oids, num_oids);

						for (j = 0; j < num_oids; j++) {
							if (host->ignore_host) {
								SPINE_LOG(("Device[%i] HT[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
								SET_UNDEFINED(snmp_oids[j].result);
							} else if (IS_UNDEFINED(snmp_oids[j].result)) {
								buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
								errors++;

								if (set.spine_log_level == 2) {
									SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
										host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
										host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
										poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
								}

								/* continue */
							} else if ((is_numeric(snmp_oids[j].result)) || (is_multipart_output(snmp_oids[j].result))) {
								/* continue */
							} else if (is_hexadecimal(snmp_oids[j].result, TRUE)) {
								snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%llu", hex2dec(snmp_oids[j].result));
							} else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
								(STRIMATCH(snmp_oids[j].result, "Nan"))) {
								buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
								errors++;

								if (set.spine_log_level == 2) {
									SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
										host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
										host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
										poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
								}

								/* is valid output, continue */
							} else {
								/* remove double or single quotes from string */
								snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(REGEX_NUMBER, strip_alpha(snmp_oids[j].result)));
								snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

								/* detect erroneous non-numeric result */
								if (!validate_result(snmp_oids[j].result)) {
									buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
									errors++;

									if (set.spine_log_level == 2) {
										SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
											host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
											host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
											poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
									}

									SET_UNDEFINED(snmp_oids[j].result);
								}
							}

							snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

							thread_end = get_time_as_double();

							if (is_debug_device(host_id)) {
								SPINE_LOG(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
							}
						}

						/* reset num_snmps */
						num_oids = 0;

						/* initialize all the memory to insure we don't get issues */
						memset(snmp_oids, 0, sizeof(snmp_oids_t)*host->max_oids);
					}

					if (host->snmp_session != NULL) {
						snmp_host_cleanup(host->snmp_session);
						host->snmp_session = NULL;
					}

					host->snmp_session = snmp_host_init(host->id, poller_items[i].hostname,
						poller_items[i].snmp_version, poller_items[i].snmp_community,
						poller_items[i].snmp_username, poller_items[i].snmp_password,
						poller_items[i].snmp_auth_protocol, poller_items[i].snmp_priv_passphrase,
						poller_items[i].snmp_priv_protocol, poller_items[i].snmp_context,
						poller_items[i].snmp_engine_id,
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
					STRNCOPY(last_snmp_engine_id,       poller_items[i].snmp_engine_id);
				}

				if (num_oids >= host->max_oids) {
					snmp_get_multi(host, poller_items, snmp_oids, num_oids);

					for (j = 0; j < num_oids; j++) {
						if (host->ignore_host) {
							SPINE_LOG(("Device[%i] HT[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
							SET_UNDEFINED(snmp_oids[j].result);
						} else if (IS_UNDEFINED(snmp_oids[j].result)) {
							buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
							errors++;

							if (set.spine_log_level == 2) {
								SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
									host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
									host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
									poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
							}

							/* continue */
						} else if ((is_numeric(snmp_oids[j].result)) || (is_multipart_output(snmp_oids[j].result))) {
							/* continue */
						} else if (is_hexadecimal(snmp_oids[j].result, TRUE)) {
							snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%llu", hex2dec(snmp_oids[j].result));
						} else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
							(STRIMATCH(snmp_oids[j].result, "Nan"))) {
							buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
							errors++;

							if (set.spine_log_level == 2) {
								SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
									host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
									host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
									poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
							}

							/* is valid output, continue */
						} else {
							/* remove double or single quotes from string */
							snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(REGEX_NUMBER, strip_alpha(snmp_oids[j].result)));
							snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

							/* detect erroneous non-numeric result */
							if (!validate_result(snmp_oids[j].result)) {
								buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
								errors++;

								if (set.spine_log_level == 2) {
									SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
										host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id,
										host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
										poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
								}

								SET_UNDEFINED(snmp_oids[j].result);
							}
						}

						if (strlen(poller_items[snmp_oids[j].array_position].output_regex)) {
							snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(poller_items[snmp_oids[j].array_position].output_regex, snmp_oids[j].result));
							snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%s", temp_result);
						}

						snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

						thread_end = get_time_as_double();

						if (is_debug_device(host_id)) {
							SPINE_LOG(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
						} else {
							SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
						}

						if (!IS_UNDEFINED(poller_items[snmp_oids[j].array_position].result)) {
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
				/* Reject empty script commands that could cause unexpected behavior */
				if (strlen(poller_items[i].arg1) == 0) {
					SPINE_LOG(("WARNING: Device[%i] HT[%i] DS[%i] empty script command, skipping",
						host_id, host_thread, poller_items[i].local_data_id));
					SET_UNDEFINED(poller_items[i].result);
					break;
				}

				poll_result = exec_poll(host, poller_items[i].arg1, poller_items[i].local_data_id, "DS");

				/* process the result */
							if (poller_store_result(&poller_items[i], poll_result,
								error_string, buf_size, buf_errors, host_id, host_thread)) {
								errors++;
							}

				SPINE_FREE(poll_result);

				thread_end = get_time_as_double();

				if (is_debug_device(host_id)) {
					SPINE_LOG(("Device[%i] HT[%i] DS[%i] TT[%.2f] SCRIPT: %s, output: %s", host_id, host_thread, poller_items[i].local_data_id, (float) ((thread_end - thread_start) * 1000), poller_items[i].arg1, poller_items[i].result));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DS[%i] TT[%.2f] SCRIPT: %s, output: %s", host_id, host_thread, poller_items[i].local_data_id, (float) ((thread_end - thread_start) * 1000), poller_items[i].arg1, poller_items[i].result));
				}

				if (!IS_UNDEFINED(poller_items[i].result)) {
					/* insert a NaN in place of the actual value if the snmp agent restarts */
					if ((spike_kill) && (!strstr(poller_items[i].result,":"))) {
						SET_UNDEFINED(poller_items[i].result);
					}
				}

				break;
			case POLLER_ACTION_PHP_SCRIPT_SERVER: /* execute script server */
				/* Reject empty script commands that could cause unexpected behavior */
				if (strlen(poller_items[i].arg1) == 0) {
					SPINE_LOG(("WARNING: Device[%i] HT[%i] DS[%i] empty script server command, skipping",
						host_id, host_thread, poller_items[i].local_data_id));
					SET_UNDEFINED(poller_items[i].result);
					break;
				}

				php_process = php_get_process();

				poll_result = php_cmd(poller_items[i].arg1, php_process);

				/* process the output */
							if (poller_store_result(&poller_items[i], poll_result,
								error_string, buf_size, buf_errors, host_id, host_thread)) {
								errors++;
							}

				SPINE_FREE(poll_result);

				thread_end = get_time_as_double();

				if (is_debug_device(host_id)) {
					SPINE_LOG(("Device[%i] HT[%i] DS[%i] TT[%.2f] SS[%i] SERVER: %s, output: %s", host_id, host_thread, poller_items[i].local_data_id, (float) ((thread_end - thread_start) * 1000), php_process, poller_items[i].arg1, poller_items[i].result));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DS[%i] TT[%.2f] SS[%i] SERVER: %s, output: %s", host_id, host_thread, poller_items[i].local_data_id, (float) ((thread_end - thread_start) * 1000), php_process, poller_items[i].arg1, poller_items[i].result));
				}

				if (!IS_UNDEFINED(poller_items[i].result)) {
					/* insert a NaN in place of the actual value if the snmp agent restarts */
					if ((spike_kill) && (!strstr(poller_items[i].result,":"))) {
						SET_UNDEFINED(poller_items[i].result);
					}
				}

				break;
			default: /* unknown action, generate error */
				SPINE_LOG(("Device[%i] HT[%i] DS[%i] ERROR: Unknown Poller Action: %s", host_id, host_thread, poller_items[i].local_data_id, poller_items[i].arg1));

				break;
			}

			i++;
			rows_processed++;
		}

		/* process last multi-get request if applicable */
		if (num_oids > 0) {
			snmp_get_multi(host, poller_items, snmp_oids, num_oids);

			for (j = 0; j < num_oids; j++) {
				if (host->ignore_host) {
					SPINE_LOG(("Device[%i] HT[%i] DS[%i] WARNING: SNMP timeout detected [%i ms], ignoring host '%s'", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_timeout, host->hostname));
					SET_UNDEFINED(snmp_oids[j].result);
				} else if (IS_UNDEFINED(snmp_oids[j].result)) {
					buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
					errors++;

					if (set.spine_log_level == 2) {
						SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
							host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version,
							host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
							poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
					}

					/* continue */
				} else if ((is_numeric(snmp_oids[j].result)) || (is_multipart_output(snmp_oids[j].result))) {
					/* continue */
				} else if (is_hexadecimal(snmp_oids[j].result, TRUE)) {
					snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%llu", hex2dec(snmp_oids[j].result));
				} else if ((STRIMATCH(snmp_oids[j].result, "U")) ||
					(STRIMATCH(snmp_oids[j].result, "Nan"))) {
					buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
					errors++;

					if (set.spine_log_level == 2) {
						SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
							host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version,
							host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
							poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
					}

					/* is valid output, continue */
				} else {
					/* remove double or single quotes from string */
					snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(REGEX_NUMBER, strip_alpha(snmp_oids[j].result)));
					snprintf(snmp_oids[j].result , RESULTS_BUFFER, "%s", temp_result);

					/* detect erroneous non-numeric result */
					if (!validate_result(snmp_oids[j].result)) {
						buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, false);
						errors++;

						if (set.spine_log_level == 2) {
							SPINE_LOG(("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s",
								host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, host->snmp_version,
								host->hostname, poller_items[snmp_oids[j].array_position].rrd_name,
								poller_items[snmp_oids[j].array_position].arg1, snmp_oids[j].result));
						}

						SET_UNDEFINED(snmp_oids[j].result);
					}
				}

				if (strlen(poller_items[snmp_oids[j].array_position].output_regex)) {
					snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(poller_items[snmp_oids[j].array_position].output_regex, snmp_oids[j].result));
					snprintf(snmp_oids[j].result, RESULTS_BUFFER, "%s", temp_result);
				}

				snprintf(poller_items[snmp_oids[j].array_position].result, RESULTS_BUFFER, "%s", snmp_oids[j].result);

				thread_end = get_time_as_double();

				if (is_debug_device(host_id)) {
					SPINE_LOG(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] HT[%i] DS[%i] TT[%.2f] SNMP: v%i: %s, dsname: %s, oid: %s, value: %s", host_id, host_thread, poller_items[snmp_oids[j].array_position].local_data_id, (float) ((thread_end - thread_start) * 1000), host->snmp_version, host->hostname, poller_items[snmp_oids[j].array_position].rrd_name, poller_items[snmp_oids[j].array_position].arg1, poller_items[snmp_oids[j].array_position].result));
				}

				if (!IS_UNDEFINED(poller_items[snmp_oids[j].array_position].result)) {
					/* insert a NaN in place of the actual value if the snmp agent restarts */
					if ((spike_kill) && (!strstr(poller_items[snmp_oids[j].array_position].result,":"))) {
						SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
					}
				}
			}
		}

		buf_length = MAX_MYSQL_BUF_SIZE+RESULTS_BUFFER;

		/* insert the query results into the database */
		if (!(query3 = (char *)malloc(buf_length))) {
			die("ERROR: Fatal malloc error: poller.c query3 output buffer!");
		}

		/* set zeros */
		memset(query3, 0, buf_length);

		/* append data */
		strncat(query3, q.query8, q.query8_len);

		out_buffer = strlen(query3);

		if (set.boost_redirect && set.boost_enabled) {
			/* insert the query results into the database */
			if (!(query12 = (char *)malloc(buf_length))) {
				die("ERROR: Fatal malloc error: poller.c query12 boost output buffer!");
			}

			/* set zeros */
			memset(query12, 0, buf_length);

			/* append data */
			strncat(query12, q.query11, q.query11_len);
		}

		int mode;
		if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
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
			result_length = poller_output_tuple(result_string, sizeof(result_string),
				&mysqlt, &poller_items[i], host_time);

			/* if the next element to the buffer will overflow it, write to the database */
			if ((out_buffer + result_length) >= MAX_MYSQL_BUF_SIZE) {
				/* append the suffix */
				strncat(query3, q.posuffix, q.posuffix_len);

				/* insert the record */
				db_insert(&mysqlt, mode, query3);

				/* re-initialize the query buffer */
				memset(query3, 0, MAX_MYSQL_BUF_SIZE+RESULTS_BUFFER);

				strncat(query3, q.query8, q.query8_len);

				/* insert the record for boost */
				if (set.boost_redirect && set.boost_enabled) {
					/* append the suffix */
					strncat(query12, q.posuffix, q.posuffix_len);

					db_insert(&mysqlt, mode, query12);

					memset(query12, 0, MAX_MYSQL_BUF_SIZE+RESULTS_BUFFER);

					strncat(query12, q.query11, q.query11_len);
				}

				/* reset the output buffer length */
				out_buffer = strlen(query3);

				/* set binary, let the system know we are a new buffer */
				new_buffer = TRUE;
			}

			/* if this is our first pass, or we just outputted to the database, need to change the delimiter */
			if (new_buffer) {
				result_string[0] = ' ';
			} else {
				result_string[0] = ',';
			}

			strncat(query3, result_string, result_length);

			if (set.boost_redirect && set.boost_enabled) {
				strncat(query12, result_string, result_length);
			}

			out_buffer = out_buffer + strlen(result_string);
			new_buffer = FALSE;
			i++;
		}

		/* perform the last insert if there is data to process */
		if (out_buffer > strlen(q.query8)) {
			/* append the suffix */
			strncat(query3, q.posuffix, q.posuffix_len);

			/* insert records into database */
			db_insert(&mysqlt, mode, query3);

			/* insert the record for boost */
			if (set.boost_redirect && set.boost_enabled) {
				/* append the suffix */
				strncat(query12, q.posuffix, q.posuffix_len);

				db_insert(&mysqlt, mode, query12);
			}
		}

	} else {
		/* free the mysql result */
		db_free_result(result);
	}

	/* update poller_items table for next polling interval */
	if (host_thread == host_threads && set.active_profiles != 1) {
		SPINE_LOG_MEDIUM(("Device[%i] HT[%i] Updating Poller Items for Next Poll", host_id, host_thread));

		db_query(&mysql, LOCAL, q.query6);
	}

	/* record the polling time for the device */
	poll_time = get_time_as_double() - poll_time;
	if (is_debug_device(host_id)) {
		SPINE_LOG(("Device[%i] HT[%i] Total Time: %0.2g Seconds", host_id, host_thread, poll_time));
	} else {
		SPINE_LOG_MEDIUM(("Device[%i] HT[%i] Total Time: %0.2g Seconds", host_id, host_thread, poll_time));
	}

	/* record the total time for the host */
	thread_mutex_lock(LOCK_THDET);
	details[device_counter]->threads_complete++;
	if (details[device_counter]->threads_complete == details[device_counter]->host_threads) {
		details[device_counter]->complete = TRUE;

		poll_time = get_time_as_double();
		q.query1[0] = '\0';
		snprintf(q.query1, BUFSIZE, "UPDATE host SET polling_time = %.3f - %.3f WHERE id = %i", poll_time, host_time_double, host_id);
		db_query(&mysql, LOCAL, q.query1);

	}

	if (errors > 0) {
		int error_query_len = strlen(error_string) + BUFSIZE;
		char *error_query;
		if (!(error_query = (char *)malloc(error_query_len))) {
			die("ERROR: Fatal malloc error: poller.c error_query!");
		}

		snprintf(error_query, error_query_len, "INSERT INTO host_errors (host_id, poller_id, errors, local_data_ids)"
			" VALUES(%i, %i, %i, '%s')"
			" ON DUPLICATE KEY UPDATE"
			" errors = errors + VALUES(errors),"
			" local_data_ids = CONCAT(local_data_ids, ', ', VALUES(local_data_ids))",
			host_id, set.poller_id, errors, error_string);

		db_query(&mysql, LOCAL, error_query);

		free(error_query);
	}

	thread_mutex_unlock(LOCK_THDET);

	if (is_debug_device(host_id)) {
		SPINE_LOG(("Device[%i] HT[%i] DEBUG: HOST COMPLETE: About to Exit Device Polling Thread Function", host_id, host_thread));
	} else {
		SPINE_LOG_DEBUG(("Device[%i] HT[%i] DEBUG: HOST COMPLETE: About to Exit Device Polling Thread Function", host_id, host_thread));
	}

	/* Only the path that polled has anything buffered to report; the early
	 * exits below reached cleanup before any of it was produced. */
	if (set.spine_log_level == 1) {
		buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, 0, true);
	}

	*host_errors = errors;

cleanup:
	/* One owner for everything this function allocates, released in reverse
	 * order of acquisition.
	 *
	 * There were seventeen SPINE_FREE calls in eleven clusters, and three
	 * exits each spelling the teardown out on their own terms. They had
	 * already drifted: one omitted mysql_thread_end() (#594), and query3 is
	 * reused for two unrelated lifetimes, so any early return added between
	 * its two allocations would have leaked it. SPINE_FREE tolerates NULL and
	 * clears the pointer, so reaching here before a given allocation is made
	 * costs nothing and cannot double free. */
	if (host != NULL && host->snmp_session != NULL) {
		snmp_host_cleanup(host->snmp_session);
		host->snmp_session = NULL;
	}

	SPINE_FREE(query12);
	SPINE_FREE(query3);
	SPINE_FREE(snmp_oids);
	SPINE_FREE(poller_items);

	poll_host_release(&host, &reindex, &ping, &error_string, &buf_size, &buf_errors,
		local_cnn, remote_cnn, host_id, host_thread);
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
		error_len = strlen(tbuffer);
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
			} else {
				const int len = strlen(result);

				for (i=0; i<len; i++) {
					if ((result[i] == ':') || (result[i] == '!')) {
						delim_cnt = delim_cnt + 1;
					} else if (result[i] == ' ') {
						space_cnt = space_cnt + 1;
					}
				}

				if (space_cnt+1 == delim_cnt) {
					return TRUE;
				} else {
					return FALSE;
				}
			}
		}
	}

	return FALSE;
}

void get_system_information(host_t *host, MYSQL *mysql, int system)  {
	char *poll_result;

	SPINE_LOG_MEDIUM(("Device[%d] Checking for System Information Update", host->id));

	if (set.mibs || system) {
		if (is_debug_device(host->id)) {
			SPINE_LOG(("Device[%d] Updating Full System Information Table", host->id));
		} else {
			SPINE_LOG_MEDIUM(("Device[%d] Updating Full System Information Table", host->id));
		}

		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.1.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.1.0");
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.1.0'); [complete]", host->id));

		if (poll_result) {
			db_escape(mysql, host->snmp_sysDescr, sizeof(host->snmp_sysDescr), poll_result);
			SPINE_FREE(poll_result);
		}

		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.2.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.2.0");
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.2.0'); [complete]", host->id));

		if (poll_result) {
			db_escape(mysql, host->snmp_sysObjectID, sizeof(host->snmp_sysObjectID), poll_result);
			SPINE_FREE(poll_result);
		}

		// Get the legacy system uptime instance first
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.3.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");
		SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.3.0'); [complete]", host->id));

		if (poll_result && is_numeric(poll_result)) {
			host->snmp_sysUpTimeInstance = atoll(poll_result);
			SPINE_FREE(poll_result);

			// Attempt to get the more modern version
			SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.6.3.10.2.1.3.0');", host->id));
			poll_result = snmp_get_base(host, ".1.3.6.1.6.3.10.2.1.3.0", false);
			SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.6.3.10.2.1.3.0'); [complete]", host->id));

			if (poll_result && is_numeric(poll_result)) {
				host->snmp_sysUpTimeInstance = atoll(poll_result) * 100;
				snprintf(poll_result, BUFSIZE, "%llu", host->snmp_sysUpTimeInstance);
			}

			SPINE_FREE(poll_result);
		}

		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.4.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.4.0");
		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.4.0'); [complete]", host->id));

		if (poll_result) {
			db_escape(mysql, host->snmp_sysContact, sizeof(host->snmp_sysContact), poll_result);
			SPINE_FREE(poll_result);
		}

		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.5.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.5.0");
		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.5.0'); [complete]", host->id));

		if (poll_result) {
			db_escape(mysql, host->snmp_sysName, sizeof(host->snmp_sysName), poll_result);
			SPINE_FREE(poll_result);
		}

		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.6.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.6.0");
		SPINE_LOG_DEVDBG(("DEVDBG: Device [%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.6.0'); [complete]", host->id));

		if (poll_result) {
			db_escape(mysql, host->snmp_sysLocation, sizeof(host->snmp_sysLocation), poll_result);
			SPINE_FREE(poll_result);
		}
	} else {
		if (is_debug_device(host->id)) {
			SPINE_LOG(("Device[%d] Updating Short System Information Table", host->id));
		} else {
			SPINE_LOG_MEDIUM(("Device[%d] Updating Short System Information Table", host->id));
		}

		// Get the legacy system uptime instance first
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.3.0');", host->id));
		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");
		SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.2.1.1.3.0'); [complete]", host->id));

		if (poll_result && is_numeric(poll_result)) {
			host->snmp_sysUpTimeInstance = atoll(poll_result);
			SPINE_FREE(poll_result);

			// Attempt to get the more modern version
			SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.6.3.10.2.1.3.0');", host->id));
			poll_result = snmp_get(host, ".1.3.6.1.6.3.10.2.1.3.0");
			SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get(host, '.1.3.6.1.6.3.10.2.1.3.0'); [complete]", host->id));

			if (poll_result && is_numeric(poll_result)) {
				host->snmp_sysUpTimeInstance = atoll(poll_result) * 100;
				snprintf(poll_result, BUFSIZE, "%llu", host->snmp_sysUpTimeInstance);
			}

			SPINE_FREE(poll_result);
		}
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

/*! \fn char *exec_poll(host_t *current_host, char *command, int id, const char *type)
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
	int pid;

	#ifdef USING_TPOPEN
	FILE *fd;
	int close_fd = TRUE;
	#endif

	int bytes_read;
	fd_set fds;
	double begin_time = 0;
	double end_time = 0;
	double script_timeout;
	double remaining_usec = 0;
	struct timeval timeout;
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

	/* set script timeout as double */
	script_timeout = set.script_timeout;

	/* establish timeout of 25 seconds for pipe response */
	timeout.tv_sec = set.script_timeout;
	timeout.tv_usec = 0;

	/* don't run too many scripts, operating systems do not like that. */
	int retries = 0;
	int sem_err = 0;
	int needs_cleanup = 0;

	/* used for checking executable status */
	char executable[BUFSIZE];
	char *saveptr = NULL;

	pthread_cleanup_push(child_cleanup_script, NULL);

	// use the script server timeout value, allow for 50% leeway
	while (++retries < (set.script_timeout * 15)) {
		sem_err = spine_sem_trywait(&available_scripts);
		if (sem_err == 0) {
			break;
		} else {
			int sem_errno = errno;

			if (sem_errno == EAGAIN || sem_errno == EWOULDBLOCK) {
				if (is_debug_device(current_host->id)) {
					SPINE_LOG(("Device[%i] DEBUG: Pausing as unable to obtain a script execution lock", current_host->id));
				} else {
					SPINE_LOG_DEVDBG(("Device[%i] DEBUG: Pausing as unable to obtain a script execution lock", current_host->id));
				}
			} else {
				if (is_debug_device(current_host->id)) {
					SPINE_LOG(("Device[%i] DEBUG: Pausing as error %d whilst obtaining a script execution lock", current_host->id, sem_errno));
				} else {
					SPINE_LOG_DEVDBG(("Device[%i] DEBUG: Pausing as error %d whilst obtaining a script execution lock", current_host->id, sem_errno));
				}
			}
		}
		usleep(10000);
	}

	if (sem_err) {
		SPINE_LOG(("ERROR: Device[%i]: Failed to obtain a script execution lock within 30 seconds", current_host->id));
	} else {
		/* Mark for cleanup */
		needs_cleanup = 1;

		/* record start time */
		begin_time = get_time_as_double();

		/* peel the executable from the command */
		saveptr = proc_command;
		snprintf(executable, BUFSIZE, "%s", proc_command);
		strtok_r(executable, " ", &saveptr);

		/* cheesy little hack to add /usr/bin/ if its not included */
		if (strstr(executable, "/") == NULL) {
			saveptr = proc_command;
			snprintf(executable, BUFSIZE, "/usr/bin/%s", proc_command);
			strtok_r(executable, " ", &saveptr);
		}

		SPINE_LOG_DEBUG(("The executable is '%s' in \'%s\'", executable, proc_command));

		if (access(executable, X_OK | F_OK) != -1) {
			#ifdef USING_TPOPEN
			fd = popen((char *)proc_command, "r");
			cmd_fd = fileno(fd);
			if (is_debug_device(current_host->id)) {
				SPINE_LOG(("Device[%i] DEBUG: The POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));
			} else {
				SPINE_LOG_DEBUG(("Device[%i] DEBUG: The POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));
			}
			#else
			cmd_fd = nft_popen(proc_command, "r");
			if (is_debug_device(current_host->id)) {
				SPINE_LOG(("Device[%i] DEBUG: The NIFTY POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));
			} else {
				SPINE_LOG_DEBUG(("Device[%i] DEBUG: The NIFTY POPEN returned the following File Descriptor %i", current_host->id, cmd_fd));
			}
			#endif

			if (cmd_fd > 0) {
				retry:

				/* Initialize File Descriptors to Review for Input/Output */
				FD_ZERO(&fds);
				FD_SET(cmd_fd, &fds);

				/* wait x seconds for pipe response */
				switch (select(FD_SETSIZE, &fds, NULL, NULL, &timeout)) {
					case -1:
						switch (errno) {
							case EBADF:
								SPINE_LOG(("Device[%i] ERROR: One or more of the file descriptor sets specified a file descriptor that is not a valid open file descriptor.", current_host->id));
								SET_UNDEFINED(result_string);

								#ifdef USING_TPOPEN
								close_fd = FALSE;
								#endif

								break;
							case EINTR:
								#ifndef SOLAR_THREAD
								/* take a moment */
								usleep(2000);
								#endif

								/* record end time */
								end_time = get_time_as_double();

								/* re-establish new timeout value */
								timeout.tv_sec  = rint(floor(script_timeout-(end_time-begin_time)));
								remaining_usec  = set.script_timeout - timeout.tv_sec - (end_time - begin_time);

								if (remaining_usec > 0) {
									timeout.tv_usec = rint(remaining_usec * 1000000);
								} else {
									timeout.tv_usec = 0;
								}
								timeout.tv_sec = rint(floor(script_timeout-(end_time-begin_time)));
								timeout.tv_usec = rint((script_timeout-(end_time-begin_time)-timeout.tv_sec)*1000000);

								if (timeout.tv_sec + timeout.tv_usec > 0) {
									goto retry;
								} else {
									SPINE_LOG(("WARNING: A script timed out while processing EINTR's."));
									SET_UNDEFINED(result_string);
									#ifdef USING_TPOPEN
									close_fd = FALSE;
									#endif
								}
								break;
							case EINVAL:
								SPINE_LOG(("Device[%i] ERROR: Possible invalid timeout specified in select() statement.", current_host->id));
								SET_UNDEFINED(result_string);
								#ifdef USING_TPOPEN
								close_fd = FALSE;
								#endif
								break;
							default:
								SPINE_LOG(("Device[%i] ERROR: The script/command select() failed", current_host->id));
								SET_UNDEFINED(result_string);
								#ifdef USING_TPOPEN
								close_fd = FALSE;
								#endif
								break;
						}

						break;
				case 0:
					#ifdef USING_TPOPEN
					SPINE_LOG_MEDIUM(("Device[%i] ERROR: The POPEN timed out", current_host->id));

					close_fd = FALSE;
					#else
					SPINE_LOG_MEDIUM(("Device[%i] ERROR: The NIFTY POPEN timed out", current_host->id));

					pid = nft_pchild(cmd_fd);
					kill(pid, SIGKILL);
					#endif

					SET_UNDEFINED(result_string);
					break;
				default:
					/* get only one line of output, we will ignore the rest */
					bytes_read = read(cmd_fd, result_string, RESULTS_BUFFER-1);
					if (bytes_read > 0) {
						result_string[bytes_read] = '\0';
					} else {
						if (STRIMATCH(type,"DS")) {
							SPINE_LOG(("Device[%i] DS[%i] ERROR: Empty result [%s]: '%s'", current_host->id, id, current_host->hostname, command));
						} else {
							SPINE_LOG(("Device[%i] DQ[%i] ERROR: Empty result [%s]: '%s'", current_host->id, id, current_host->hostname, command));
						}
						SET_UNDEFINED(result_string);
					}
				}

				/* close pipe */
				#ifdef USING_TPOPEN
				/* we leave the old fd open if it timed out. It will have to exit on it's own */
				if (close_fd) {
					pclose(fd);
				}
				#else
				nft_pclose(cmd_fd);
				#endif
			} else {
				SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN [%s]: '%s'", current_host->id, current_host->hostname, command));
				SET_UNDEFINED(result_string);
			}
		} else {
			SPINE_LOG(("Device[%i] ERROR: Problem executing POPEN.  File '%s' does not exist or is not executable.", current_host->id, command));
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
