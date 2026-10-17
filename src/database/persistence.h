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

#ifndef SPINE_PERSISTENCE_H
#define SPINE_PERSISTENCE_H
#include "database/cacti_query.h"
/* Connections and items are borrowed. Returned output/boost buffers transfer
 * to the caller even on failed writes and must be freed by that caller.
 * Destination writes remain independent; no new locking is introduced. */
typedef struct {
	char *output;
	char *boost;
	bool failed;
} poll_output_buffers_t;

poll_output_buffers_t write_poll_results(MYSQL *mysql, MYSQL *mysqlr,
	const poller_queries_t *queries, const target_t *items,
	int rows_processed, const char *host_time);
void persist_host_status(MYSQL *mysql, const host_t *host, bool include_system_information);
/* After workers stop: synchronize remote results, mark completion, then close
 * the process-owned pools in the existing order. The app owns this call. */
void persist_poll_completion(MYSQL *mysql, MYSQL *mysqlr, int mode);
#endif
