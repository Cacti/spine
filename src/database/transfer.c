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

typedef struct {
	const char *table;
	const char *columns;
	const char *filter_column;
	const char *order_column;
	const char *const *updates;
	size_t update_count;
	size_t field_count;
	size_t row_limit;
} poller_transfer_t;

static void transfer_queries(const poller_transfer_t *plan, char *query, size_t query_capacity, char *prefix, size_t prefix_capacity, char *suffix, size_t suffix_capacity) {
	size_t used = (size_t) spine_snprintf(query, query_capacity, "SELECT SQL_NO_CACHE %s FROM %s WHERE poller_id = %d", plan->columns, plan->table, set.poller.poller_id);
	if (set.hosts.host_id_list[0] != '\0') used += (size_t) spine_snprintf(query + used, query_capacity - used, " AND %s IN (%s)", plan->filter_column, set.hosts.host_id_list);
	spine_snprintf(query + used, query_capacity - used, " ORDER BY %s", plan->order_column);
	spine_snprintf(prefix, prefix_capacity, "INSERT INTO %s (%s) VALUES ", plan->table, plan->columns);
	/* These rows go to the main server. The cached upsert capability describes the
	 * local server, so the row-alias form could reach a MariaDB main server
	 * that rejects it. VALUES() is accepted by both (#590). */
	used = (size_t) spine_snprintf(suffix, suffix_capacity, " ON DUPLICATE KEY UPDATE ");
	for (size_t index = 0; index < plan->update_count; index++) {
		const char *column = plan->updates[index];
		used += (size_t) spine_snprintf(suffix + used, suffix_capacity - used, "%s%s=VALUES(%s)", index == 0 ? "" : ", ", column, column);
	}
}

static size_t transfer_row(MYSQL *destination, MYSQL_ROW row, size_t field_count, char *output, size_t capacity) {
	/* The selected columns are at most 300 UTF-8 characters: allow 4 bytes per
	 * character and doubling for SQL escaping. Preserve SQL NULL explicitly. */
	char escaped[DBL_BUFSIZE * 2];
	size_t used = (size_t) spine_snprintf(output, capacity, "(");
	for (size_t index = 0; index < field_count; index++) {
		if (row[index] == NULL) {
			used += (size_t) spine_snprintf(output + used, capacity - used, "%sNULL", index == 0 ? "" : ", ");
		} else {
			db_escape(destination, escaped, sizeof(escaped), row[index]);
			used += (size_t) spine_snprintf(output + used, capacity - used, "%s'%s'", index == 0 ? "" : ", ", escaped);
		}
	}
	used += (size_t) spine_snprintf(output + used, capacity - used, ")");
	return used;
}

static bool transfer_batch(MYSQL *destination, char *buffer, size_t used, const char *suffix) {
	spine_snprintf(buffer + used, HUGE_BUFSIZE - used, "%s", suffix);
	return db_insert(destination, REMOTE, buffer);
}

static bool transfer_table(MYSQL *source, MYSQL *destination, const poller_transfer_t *plan) {
	char query[MEGA_BUFSIZE];
	char prefix[BUFSIZE];
	char suffix[BUFSIZE];
	transfer_queries(plan, query, sizeof(query), prefix, sizeof(prefix), suffix, sizeof(suffix));
	MYSQL_RES *result = db_query(source, LOCAL, query);
	if (result == NULL) return FALSE;
	if (mysql_num_fields(result) != plan->field_count) {
		db_free_result(result);
		return FALSE;
	}
	/* Size one row for every column at its escaped maximum plus separators;
	 * a fixed few kilobytes could not hold a host row with wide SNMP strings. */
	size_t row_capacity = plan->field_count * (DBL_BUFSIZE * 2 + 4) + 2;
	char *row_sql = malloc(row_capacity);
	char *buffer = malloc(HUGE_BUFSIZE);
	if (buffer == NULL || row_sql == NULL) {
		free(row_sql);
		free(buffer);
		db_free_result(result);
		return FALSE;
	}
	size_t used = 0;
	size_t rows = 0;
	size_t suffix_length = strlen(suffix);
	MYSQL_ROW row;
	bool success = TRUE;
	while ((row = mysql_fetch_row(result)) != NULL) {
		size_t length = transfer_row(destination, row, plan->field_count, row_sql, row_capacity);
		if (rows > 0 && (rows == plan->row_limit || length + suffix_length + 3 > HUGE_BUFSIZE - used)) {
			if (!transfer_batch(destination, buffer, used, suffix)) {
				success = FALSE;
				break;
			}
			rows = 0;
		}
		if (rows == 0) used = (size_t) spine_snprintf(buffer, HUGE_BUFSIZE, "%s", prefix);
		else used += (size_t) spine_snprintf(buffer + used, HUGE_BUFSIZE - used, ", ");
		used += (size_t) spine_snprintf(buffer + used, HUGE_BUFSIZE - used, "%s", row_sql);
		rows++;
	}
	if (mysql_errno(source) != 0) success = FALSE;
	if (success && rows > 0) success = transfer_batch(destination, buffer, used, suffix);
	free(row_sql);
	free(buffer);
	db_free_result(result);
	return success;
}

bool poller_transfer_status(MYSQL *source, MYSQL *destination) {
	static const char *const host_updates[] = {
		"snmp_sysDescr", "snmp_sysObjectID", "snmp_sysUpTimeInstance", "snmp_sysContact", "snmp_sysName", "snmp_sysLocation",
		"status", "status_event_count", "status_fail_date", "status_rec_date", "status_last_error", "min_time", "max_time",
		"cur_time", "avg_time", "polling_time", "total_polls", "failed_polls", "availability", "last_updated"};
	static const char *const item_updates[] = {"rrd_next_step"};
	static const poller_transfer_t host_plan = {
		"host", "id, snmp_sysDescr, snmp_sysObjectID, snmp_sysUpTimeInstance, snmp_sysContact, snmp_sysName, snmp_sysLocation, status, status_event_count, status_fail_date, status_rec_date, status_last_error, min_time, max_time, cur_time, avg_time, polling_time, total_polls, failed_polls, availability, last_updated",
		"id", "id", host_updates, sizeof(host_updates) / sizeof(host_updates[0]), 21, 500};
	static const poller_transfer_t item_plan = {
		"poller_item", "local_data_id, host_id, rrd_name, rrd_step, rrd_next_step",
		"host_id", "local_data_id, rrd_name", item_updates, sizeof(item_updates) / sizeof(item_updates[0]), 5, 10000};
	SPINE_LOG_MEDIUM(("Pushing Host Status to Main Server"));
	if (!transfer_table(source, destination, &host_plan)) return FALSE;
	SPINE_LOG_MEDIUM(("Pushing Poller Item RRD Next Step to Main Server"));
	return transfer_table(source, destination, &item_plan);
}

void poller_push_data_to_main(void) {
	MYSQL source;
	MYSQL destination;
	/* A failed connect leaves an initialized handle that still has to be closed. */
	if (!db_connect(LOCAL, &source)) {
		db_disconnect(&source);
		SPINE_LOG(("ERROR: Collector synchronization skipped; the local database is unavailable. Local rows are retained for retry."));
		set.exit.exit_code = EXIT_FAILURE;
		return;
	}
	if (!db_connect(REMOTE, &destination)) {
		db_disconnect(&destination);
		db_disconnect(&source);
		SPINE_LOG(("ERROR: Collector synchronization skipped; the main server is unavailable. Local rows are retained for retry."));
		set.exit.exit_code = EXIT_FAILURE;
		return;
	}
	/* Preserve the supported zero-date and GROUP BY session policies. */
	bool configured = db_insert(&source, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))") &&
		db_insert(&source, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))") &&
		db_insert(&destination, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))") &&
		db_insert(&destination, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
	if (!configured || !poller_transfer_status(&source, &destination)) {
		SPINE_LOG(("ERROR: Collector synchronization incomplete; earlier batches may have reached the main server. Local rows are retained for retry."));
		set.exit.exit_code = EXIT_FAILURE;
	}
	db_disconnect(&source);
	db_disconnect(&destination);
}
