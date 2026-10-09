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
#include "src/poller/poller_internal.h"
#include <limits.h>

static void poller_item_query(char *buffer, size_t capacity, const char *columns, const poller_query_filter_t *filter) {
	char *cursor = buffer;
	cursor += spine_snprintf(cursor, capacity, "SELECT SQL_NO_CACHE %s FROM poller_item WHERE host_id = %i", columns, filter->host_id);
	if (set.poller.poller_id != 0) cursor += spine_snprintf(cursor, capacity - (size_t) (cursor - buffer), " AND poller_id = %i", set.poller.poller_id);
	if (filter->due_only) cursor += spine_snprintf(cursor, capacity - (size_t) (cursor - buffer), " AND rrd_next_step <= 0");
	if (filter->group_ports) {
		cursor += spine_snprintf(cursor, capacity - (size_t) (cursor - buffer), " GROUP BY snmp_port");
	} else if (set.snmp.total_snmp_ports != 1) {
		cursor += spine_snprintf(cursor, capacity - (size_t) (cursor - buffer), " ORDER BY snmp_port");
	}
	spine_snprintf(cursor, capacity - (size_t) (cursor - buffer), " %s", filter->limits);
}

void poller_prepare_queries(poller_queries_t *queries, int host_id, int host_thread, int host_data_ids) {
	char limits[SMALL_BUFSIZE] = "";
	if (host_data_ids > 0) {
		if (host_thread < 1) die("ERROR: Invalid device thread for poller item selection");
		long long offset = (long long) host_data_ids * ((long long) host_thread - 1);
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
		"snmp_sysContact, snmp_sysName, snmp_sysLocation FROM host WHERE id = %i AND deleted = ''",
		host_id);
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
