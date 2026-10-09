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

		if ((!IS_UNDEFINED(poller_items[snmp_oids[j].array_position].result)) && (spike_kill && (!strstr(poller_items[snmp_oids[j].array_position].result, ":")))) {
			SET_UNDEFINED(poller_items[snmp_oids[j].array_position].result);
		}
	}
}

static void load_poll_item(target_t *item, MYSQL_ROW row) {
	/* initialize monitored object */
	item->target_id = 0;
	item->action = -1;
	item->hostname[0] = '\0';
	item->snmp.community[0] = '\0';
	item->snmp.version = 1;
	item->snmp.username[0] = '\0';
	item->snmp.password[0] = '\0';
	item->snmp.auth_protocol[0] = '\0';
	item->snmp.priv_passphrase[0] = '\0';
	item->snmp.priv_protocol[0] = '\0';
	item->snmp.context[0] = '\0';
	item->snmp.engine_id[0] = '\0';
	item->snmp.port = 161;
	item->snmp.timeout = 500;
	item->rrd_name[0] = '\0';
	item->rrd_path[0] = '\0';
	item->arg1[0] = '\0';
	item->arg2[0] = '\0';
	item->arg3[0] = '\0';
	item->local_data_id = 0;
	item->rrd_num = 0;
	item->output_regex[0] = '\0';

	if (row[0] != NULL) item->action = atoi(row[0]);

	if (row[1] != NULL) snprintf(item->hostname, sizeof(item->hostname), "%s", row[1]);
	if (row[2] != NULL) snprintf(item->snmp.community, sizeof(item->snmp.community), "%s", row[2]);

	if (row[3] != NULL) item->snmp.version = atoi(row[3]);

	if (row[4] != NULL) snprintf(item->snmp.username, sizeof(item->snmp.username), "%s", row[4]);
	if (row[5] != NULL) snprintf(item->snmp.password, sizeof(item->snmp.password), "%s", row[5]);

	if (row[6] != NULL) snprintf(item->rrd_name, sizeof(item->rrd_name), "%s", row[6]);
	if (row[7] != NULL) snprintf(item->rrd_path, sizeof(item->rrd_path), "%s", row[7]);
	if (row[8] != NULL) snprintf(item->arg1, sizeof(item->arg1), "%s", row[8]);
	if (row[9] != NULL) snprintf(item->arg2, sizeof(item->arg2), "%s", row[9]);
	if (row[10] != NULL) snprintf(item->arg3, sizeof(item->arg3), "%s", row[10]);

	if (row[11] != NULL) item->local_data_id = atoi(row[11]);

	if (row[12] != NULL) item->rrd_num = atoi(row[12]);
	if (row[13] != NULL) item->snmp.port = atoi(row[13]);
	if (row[14] != NULL) item->snmp.timeout = atoi(row[14]);

	if (row[15] != NULL) snprintf(item->snmp.auth_protocol,
		sizeof(item->snmp.auth_protocol), "%s", row[15]);
	if (row[16] != NULL) snprintf(item->snmp.priv_passphrase,
		sizeof(item->snmp.priv_passphrase), "%s", row[16]);
	if (row[17] != NULL) snprintf(item->snmp.priv_protocol,
		sizeof(item->snmp.priv_protocol), "%s", row[17]);
	if (row[18] != NULL) snprintf(item->snmp.context,
		sizeof(item->snmp.context), "%s", row[18]);
	if (row[19] != NULL) snprintf(item->snmp.engine_id,
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




/* Attempt each destination independently. Reset only early-flush buffers;
 * a failed write must not suppress the other destination or later batches. */




/* The key holds a whole profile. Narrower copies truncated long communities,
 * which then never matched their own item and forced a session per OID. */




static void remember_snmp_item(snmp_item_key_t *key, const target_t *item) {
	key->profile = item->snmp;
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
	return (key->profile.port != item->snmp.port) ||
		(key->profile.version != item->snmp.version) ||
		(item->snmp.version < 3 &&
			(!STRMATCH(key->profile.community, item->snmp.community))) ||
		(item->snmp.version > 2 &&
			((!STRMATCH(key->profile.username, item->snmp.username)) ||
				(!STRMATCH(key->profile.password, item->snmp.password)) ||
				(!STRMATCH(key->profile.auth_protocol, item->snmp.auth_protocol)) ||
				(!STRMATCH(key->profile.priv_passphrase, item->snmp.priv_passphrase)) ||
				(!STRMATCH(key->profile.priv_protocol, item->snmp.priv_protocol)) ||
				(!STRMATCH(key->profile.context, item->snmp.context)) ||
				(!STRMATCH(key->profile.engine_id, item->snmp.engine_id))));
}

/* The batch-full, credential-change and final flushes all come through here,
 * so every item gets the same regex, validation and spike kill. */
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
		flush_snmp_batch(host, batch, thread_start, spike_kill);
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




poll_item_storage_t load_poll_items(MYSQL_RES *result, host_t *host, int num_rows) {
	poll_item_storage_t storage;
	/* retrieve each hosts polling items from poller cache and load into array */
	storage.items = calloc(num_rows, sizeof(*storage.items));
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
	storage.oids = calloc(host->snmp.max_oids, sizeof(*storage.oids));
	if (storage.oids == NULL) {
		die("ERROR: Fatal calloc error: poller.c snmp_oids");
	}

	return storage;
}

int collect_poll_items(host_t *host, snmp_poll_batch_t *batch, int num_rows, bool spike_kill) {
	int i = 0;
	int rows_processed = 0;
	double thread_start = 0;
	char script[SMALL_BUFSIZE];
	while ((i < num_rows) && (!host->ignore_host)) {
		thread_start = get_time_as_double();

		switch (batch->items[i].action) {
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
	flush_snmp_batch(host, batch, thread_start, spike_kill);

	return rows_processed;
}
