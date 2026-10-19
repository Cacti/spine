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

#ifndef SPINE_CACTI_QUERY_H
#define SPINE_CACTI_QUERY_H
#include "internal/spine_types.h"
/* Query buffers are caller-owned. Selection borrows the connection and returns
 * an owned MYSQL_RES, released with db_free_result. Runtime settings retain
 * their existing synchronization and retry behavior. */
typedef struct {
	char items[BUFSIZE];
	char host[BIG_BUFSIZE];
	char reindex[BUFSIZE];
	char due_items[BUFSIZE];
	char schedule[BUFSIZE];
	char output[BUFSIZE];
	char agents[BUFSIZE];
	char due_agents[BUFSIZE];
	char boost_output[BUFSIZE];
	char suffix[BUFSIZE];
} poller_queries_t;

extern void poller_prepare_queries(poller_queries_t *queries, int host_id, int host_thread, int host_data_ids);

typedef struct {
	int host_id;
	const char *limits;
	bool due_only;
	bool group_ports;
} poller_query_filter_t;

MYSQL_RES *select_poll_hosts(MYSQL *mysql);
MYSQL_RES *select_poll_items(MYSQL *mysql, const poller_queries_t *queries,
	const host_t *host, const poller_thread_t *work, int *num_rows);
#endif
