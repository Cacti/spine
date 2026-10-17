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
#include "poller/poller_internal.h"
#include <limits.h>

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
		} else if (!isdigit((unsigned char) *timep)) {
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

	return written >= 0 && (size_t) written < output_size;
}

void child_cleanup(void *arg) {
	poller_thread_t poller_details = *(poller_thread_t *) arg;

	SPINE_LOG_DEVDBG(("Device[%i] HT[%i] DEBUG: The Device Thread has cleaned up.", poller_details.host_id, poller_details.host_thread));

	free(arg);
	child_cleanup_thread(NULL);
}

void child_cleanup_thread(void *arg) {
	(void) arg;
	int a_threads_value;
	a_threads_value = spine_permits_available(&available_threads) + 1;

	SPINE_LOG_DEVDBG(("DEBUG: Available Threads is %i (%i outstanding)", a_threads_value, set.poller.threads - a_threads_value));
	/* Releasing the permit publishes completion: no shared state is used after it. */
	spine_permits_release(&available_threads);
}

void child_cleanup_script(void *arg) {
	(void) arg;
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
	poller_thread_t poller_details = *(poller_thread_t *) arg;
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
enum poll_result_status normalize_poll_result(char *result, bool snmp) {
	classified_result_t classified;
	bool unknown_marker;

	if (IS_UNDEFINED(result)) return POLL_RESULT_UNDEFINED;
	unknown_marker = snmp && (STRIMATCH(result, "U") || STRIMATCH(result, "Nan"));
	if (classify_result(result, &classified) != RESULT_UNKNOWN) {
		strncopy(result, classified.text, RESULTS_BUFFER);
		return POLL_RESULT_VALID;
	}
	/* An agent's "u" or "NaN" is still unknown; store the U RRDtool expects. */
	SET_UNDEFINED(result);
	return unknown_marker ? POLL_RESULT_UNDEFINED : POLL_RESULT_INVALID;
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

/* Publish each partition only after its bookkeeping writes finish. The last
 * partition records polling time and advances the schedule after every earlier
 * write succeeded. Database waits never hold LOCK_THDET. */
static void complete_poll_host(MYSQL *mysql, poller_queries_t *queries,
	const poller_thread_t *work, const poll_error_context_t *error_context,
	bool output_failed, bool poll_failed, double poll_start) {
	extern poller_thread_t **details;
	int host_id = work->host_id;
	int host_thread = work->host_thread;
	double host_time_double = work->host_time_double;
	int errors = *error_context->errors;
	const char *error_string = error_context->buffer;
	poller_thread_t *device = details[work->device_counter];
	double poll_time = get_time_as_double() - poll_start;
	bool last_partition;
	bool failed;
	bool write_failed = FALSE;

	SPINE_LOG_DEVICE(host_id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] Total Time: %0.2g Seconds", host_id, host_thread, poll_time));

	if (!poll_failed && errors > 0) {
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


	thread_mutex_lock(LOCK_THDET);
	if (output_failed || write_failed) device->output_failed = TRUE;
	if (poll_failed) device->poll_failed = TRUE;
	failed = device->output_failed || device->poll_failed;
	if (failed) {
		device->complete = FALSE;
		set.exit.exit_code = EXIT_FAILURE;
	}
	device->threads_complete++;
	last_partition = device->threads_complete == device->host_threads;
	thread_mutex_unlock(LOCK_THDET);

	if (output_failed || poll_failed || write_failed) {
		SPINE_LOG(("ERROR: Device[%i] HT[%i] polling or completion write failed; due items stay eligible for recollection", host_id, host_thread));
	}
	if (!last_partition) return;

	if (!poll_failed) {
		poll_time = get_time_as_double();
		snprintf(queries->items, BUFSIZE, "UPDATE host SET polling_time = %.3f - %.3f WHERE id = %i", poll_time, host_time_double, host_id);
		if (!db_insert(mysql, LOCAL, queries->items)) write_failed = TRUE;

		/* Advancing the due-item set is the final write, after every partition
		 * and the device polling-time write have reported their outcome. */
		if (!failed && !write_failed && set.poller.active_profiles != 1) {
			SPINE_LOG_MEDIUM(("Device[%i] HT[%i] Updating Poller Items for Next Poll", host_id, host_thread));
			if (!db_insert(mysql, LOCAL, queries->schedule)) write_failed = TRUE;
		}
	}

	thread_mutex_lock(LOCK_THDET);
	if (write_failed) {
		device->output_failed = TRUE;
		set.exit.exit_code = EXIT_FAILURE;
	}
	device->complete = !device->output_failed && !device->poll_failed;
	thread_mutex_unlock(LOCK_THDET);
	if (write_failed) {
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


	int errors = 0;
	int buf_errors = 0;
	int buf_size = 0;
	char error_string[DBL_BUFSIZE] = {0};

	int num_rows;
	int spike_kill = FALSE;
	int rows_processed = 0;
	bool output_failed = FALSE;
	bool poll_failed = FALSE;
	poll_host_load_t loaded;


	double poll_time = get_time_as_double();

	/* reindex shortcuts to speed polling */


	pool_t *local_cnn = NULL;
	pool_t *remote_cnn = NULL;

	reindex_t *reindex = NULL;
	host_t *host = NULL;
	ping_t *ping = NULL;
	target_t *poller_items = NULL;
	snmp_oids_t *snmp_oids = NULL;

	const poll_error_context_t error_context = {
		.buffer = error_string,
		.size = &buf_size,
		.count = &buf_errors,
		.errors = &errors,
		.host_id = host_id,
		.thread_id = host_thread};

	MYSQL *mysql;
	MYSQL *mysqlr = NULL;
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
	snprintf(ping->ping_status, 50, "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "Ping not performed due to setting.");
	snprintf(ping->snmp_status, 50, "down");
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

		release_poll_connections(work, local_cnn, remote_cnn);

		mysql_thread_end();

		return;
	}

	const reindex_evaluation_t evaluation = {mysql, mysqlr, host, work, &errors, &spike_kill};
	poll_failed = !poll_host_reindex(host, reindex, queries.reindex, &evaluation);

	/* calculate the number of poller items to poll this cycle */
	num_rows = 0;
	result = NULL;
	if (!poll_failed) {
		result = select_poll_items(mysql, &queries, host, work, &num_rows);
		poll_failed = result == NULL;
	}

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
		buffer_output_errors(error_string, &buf_size, &buf_errors, host_id, host_thread, 0, true);
	}

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
			*buf_errors = 1;
			*buf_size = snprintf(error_string, DBL_BUFSIZE, "%i", local_data_id);
		} else {
			(*buf_errors)++;
			snprintf(error_string + *buf_size, DBL_BUFSIZE - *buf_size, "%s", tbuffer);
			*buf_size += error_len;
		}
	}
}
