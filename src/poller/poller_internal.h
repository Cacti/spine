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

#ifndef SPINE_POLLER_INTERNAL_H
#define SPINE_POLLER_INTERNAL_H

#include "common.h"
#include "spine.h"

typedef struct poll_error_context {
	char *buffer;
	int *size;
	int *count;
	int *errors;
	int host_id;
	int thread_id;
} poll_error_context_t;

typedef struct {
	char *output;
	char *boost;
	bool failed;
} poll_output_buffers_t;

typedef struct {
	int initialized;
	snmp_profile_t profile;
} snmp_item_key_t;

typedef struct {
	target_t *items;
	snmp_oids_t *oids;
	int count;
	snmp_item_key_t key;
	const poll_error_context_t *errors;
} snmp_poll_batch_t;

typedef struct {
	target_t *items;
	snmp_oids_t *oids;
} poll_item_storage_t;

typedef struct {
	MYSQL *local;
	MYSQL *remote;
	const host_t *host;
	const poller_thread_t *work;
	int *errors;
	int *spike_kill;
} reindex_evaluation_t;

typedef struct {
	int host_id;
	const char *limits;
	bool due_only;
	bool group_ports;
} poller_query_filter_t;

typedef enum {
	POLL_HOST_LOADED,
	POLL_HOST_MISSING,
	POLL_HOST_FAILED
} poll_host_load_t;

poll_output_buffers_t write_poll_results(MYSQL *mysql, MYSQL *mysqlr,
	const poller_queries_t *queries, const target_t *poller_items,
	int rows_processed, const char *host_time);
MYSQL_RES *select_poll_items(MYSQL *mysql, const poller_queries_t *queries,
	const host_t *host, const poller_thread_t *work, int *num_rows);
poll_item_storage_t load_poll_items(MYSQL_RES *result, host_t *host, int num_rows);
int collect_poll_items(host_t *host, snmp_poll_batch_t *batch, int num_rows, bool spike_kill);
bool parse_uptime(const char *text, unsigned long long *ticks);
bool poll_host_reindex(host_t *host, reindex_t *reindex, const char *query,
	const reindex_evaluation_t *evaluation);
void persist_host_status(MYSQL *mysql, const host_t *host, bool include_system_information);
void load_host_metadata(MYSQL *mysql, MYSQL_ROW row, host_t *host, const poller_thread_t *work);
void initialize_host_snmp(host_t *host);
bool refresh_host_availability(MYSQL *mysql, host_t *host, ping_t *ping, int host_thread);
#endif
