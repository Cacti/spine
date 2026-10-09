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

#ifndef SPINE_POLLER_INTERNAL_H
#define SPINE_POLLER_INTERNAL_H

#include "internal/common.h"
#include "app/spine.h"
#include "database/persistence.h"

typedef struct poll_error_context {
	char *buffer;
	int *size;
	int *count;
	int *errors;
	int host_id;
	int thread_id;
} poll_error_context_t;


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


typedef enum {
	POLL_HOST_LOADED,
	POLL_HOST_MISSING,
	POLL_HOST_FAILED
} poll_host_load_t;

poll_item_storage_t load_poll_items(MYSQL_RES *result, host_t *host, int num_rows);
int collect_poll_items(host_t *host, snmp_poll_batch_t *batch, int num_rows, bool spike_kill);
bool parse_uptime(const char *text, unsigned long long *ticks);
bool poll_host_reindex(host_t *host, reindex_t *reindex, const char *query,
	const reindex_evaluation_t *evaluation);
void load_host_metadata(MYSQL *mysql, MYSQL_ROW row, host_t *host, const poller_thread_t *work);
void initialize_host_snmp(host_t *host);
bool refresh_host_availability(MYSQL *mysql, host_t *host, ping_t *ping, int host_thread);
#endif
