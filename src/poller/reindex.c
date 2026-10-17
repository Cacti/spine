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

#include "internal/common.h"
#include "app/spine.h"
#include "poller/poller_internal.h"
#include <limits.h>

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
	/* Keep the last good baseline. U compares as 0, so storing it would hide
	 * the next reboot under "<" and fire a false reindex under ">". */
	if (queued && !unavailable && (failed || STRMATCH(reindex->op, ">") || STRMATCH(reindex->op, "<"))) {
		update_reindex_value(evaluation, reindex, value);
	}
	/* A failed uptime assertion means the counters reset, so the sample is a spike. */
	if (failed && (STRMATCH(reindex->op, "<") || STRMATCH(reindex->arg1, ".1.3.6.1.2.1.1.3.0") || STRMATCH(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0"))) {
		discard_reindex_spike(evaluation);
	}
	return failed;
}

/* An uptime is a non-negative integer; anything else cannot be compared. */
bool parse_uptime(const char *text, unsigned long long *ticks) {
	unsigned long long value = 0;
	unsigned int digit;

	if (text == NULL || ticks == NULL) return FALSE;
	while (isspace((unsigned char)*text)) text++;
	if (*text < '0' || *text > '9') return FALSE;
	while (*text >= '0' && *text <= '9') {
		digit = (unsigned int)(*text++ - '0');
		if (value > (ULLONG_MAX - digit) / 10) return FALSE;
		value = value * 10 + digit;
	}
	while (isspace((unsigned char)*text)) text++;
	if (*text != '\0') return FALSE;
	*ticks = value;
	return TRUE;
}

static char *poll_reindex_snmp(host_t *host, reindex_t *reindex, int host_thread, char *sysUptime, bool *unavailable) {
	if (host->snmp.session == NULL) {
		*unavailable = TRUE;
		SPINE_LOG(("WARNING: Device[%i] HT[%i] DQ[%i] Reindex Check FAILED: No SNMP Session.  If not an SNMP host, don't use Uptime Goes Backwards!", host->id, host_thread, reindex->data_query_id));
		return NULL;
	}
	char *poll_result = NULL;
	if ((strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
			strstr(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")) &&
		strlen(sysUptime) > 0) {

		if (!(poll_result = (char *) malloc(BUFSIZE))) {
			die("ERROR: Fatal malloc error: poller.c poll_result");
		}

		poll_result[0] = '\0';

		snprintf(poll_result, BUFSIZE, "%s", sysUptime);
	} else if (strstr(reindex->arg1, ".1.3.6.1.2.1.1.3.0") ||
		strstr(reindex->arg1, ".1.3.6.1.6.3.10.2.1.3.0")) {
		unsigned long long ticks;
		bool uptime_use_engine_oid;

		// Ensure uptime is empty to start with
		sysUptime[0] = '\0';

		/* Pin the uptime-goes-backward calculation to a single OID for this poll.
		   The legacy (centisecond) and modern (second) OIDs are different counters,
		   and letting either supply the value on different rows or cycles caused
		   false "uptime went backward" detections and constant reindexing. Prefer
		   the modern engine OID and fall back to the legacy OID only when the
		   engine OID is not present with numeric data. */
		poll_result = snmp_get_base(host, ".1.3.6.1.6.3.10.2.1.3.0", false);

		uptime_use_engine_oid = parse_uptime(poll_result, &ticks) && ticks <= ULLONG_MAX / 100;

		if (uptime_use_engine_oid) {
			snprintf(sysUptime, BUFSIZE, "%llu", ticks * 100);
		}

		SPINE_FREE(poll_result);

		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Engine Uptime OID Present: %d", host->id, host_thread, reindex->data_query_id, uptime_use_engine_oid));

		if (!uptime_use_engine_oid) {
			// Engine OID unavailable, fall back to the legacy sysUpTime OID
			poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");

			if (parse_uptime(poll_result, &ticks)) {
				snprintf(sysUptime, BUFSIZE, "%llu", ticks);
			}

			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Legacy Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result != NULL ? poll_result : "U", sysUptime[0] != '\0'));

			SPINE_FREE(poll_result);
		}

		// Use the primed uptime to repopulate the poll_result
		// This ensures whichever response was valid gets used
		/* With neither OID readable there is nothing to compare. An empty
		 * value reads as 0, which looks like a reboot and queues a reindex. */
		poll_result = strdup(sysUptime[0] != '\0' ? sysUptime : "U");
		if (poll_result == NULL) {
			die("ERROR: Fatal malloc error: poller.c uptime result");
		}

		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] Extended Uptime Result: %s, Is Numeric: %d", host->id, host_thread, reindex->data_query_id, poll_result, sysUptime[0] != '\0'));
	} else {
		poll_result = snmp_get(host, reindex->arg1);
	}

	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE OID: %s, (assert: %s %s output: %s)", host->id, host_thread, reindex->data_query_id, reindex->arg1, reindex->assert_value, reindex->op, poll_result));
	return poll_result;
}

/* trim() can return a pointer past the start of the allocation. Move the
 * trimmed text to the front so the caller still frees what malloc returned. */
static char *trim_owned(char *owned) {
	char *trimmed;

	if (owned == NULL) return NULL;
	trimmed = trim(owned);
	if (trimmed != owned) memmove(owned, trimmed, strlen(trimmed) + 1);
	return owned;
}

static char *poll_reindex_action(host_t *host, reindex_t *reindex, int host_thread, char *sysUptime, bool *unavailable) {
	char *poll_result = NULL;
	int php_process;
	char script[SMALL_BUFSIZE];
	switch (reindex->action) {
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

			poll_result = trim_owned(exec_poll(host, reindex->arg1, reindex->data_query_id, "DQ"));

			php_command_script(reindex->arg1, script, sizeof(script));
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] DQ[%i] RECACHE CMD: %s, output: %s", host->id, host_thread, reindex->data_query_id, script, poll_result));

			break;
		case POLLER_ACTION_PHP_SCRIPT_SERVER: /* script (php script server) */
			php_process = php_get_process();

			poll_result = trim_owned(php_cmd(reindex->arg1, php_process));

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
	reindex->data_query_id = 0;
	reindex->action = -1;
	reindex->op[0] = '\0';
	reindex->assert_value[0] = '\0';
	reindex->arg1[0] = '\0';

	if (row[0] != NULL) reindex->data_query_id = atoi(row[0]);
	if (row[1] != NULL) reindex->action = atoi(row[1]);

	if (row[2] != NULL) snprintf(reindex->op, sizeof(reindex->op), "%s", row[2]);

	if (row[3] != NULL) snprintf(reindex->assert_value, sizeof(reindex->assert_value), "%s", row[3]);

	if (row[4] != NULL) snprintf(reindex->arg1, sizeof(reindex->arg1), "%s", row[4]);
}

bool poll_host_reindex(host_t *host, reindex_t *reindex, const char *query,
	const reindex_evaluation_t *evaluation) {
	if (host->ignore_host || evaluation->work->host_id == 0) return TRUE;
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
	return result != NULL;
}
