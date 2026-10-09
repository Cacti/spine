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

#ifndef SPINE_THREAD_H
#define SPINE_THREAD_H

#include <pthread.h>
#include "internal/constants.h"
/* Process-local permits own their mutex. Initialize before sharing; destroy
 * only after users stop. Acquire/release/available serialize on that mutex.
 * Init/destroy return pthread errors; acquisition returns EAGAIN when empty
 * and release returns EOVERFLOW at the limit. Lock failures remain fatal. */
typedef struct spine_permits {
	pthread_mutex_t mutex;
	int available;
} spine_permits_t;
int spine_permits_init(spine_permits_t *permits, int count);
int spine_permits_destroy(spine_permits_t *permits);
int spine_permits_try_acquire(spine_permits_t *permits);
int spine_permits_release(spine_permits_t *permits);
int spine_permits_available(spine_permits_t *permits);
/* Raise, never lower, the platform stack default, accounting for results. */
#define SPINE_THREAD_STACK_SIZE \
	(((size_t) 2 * ((size_t) 180 * 1024 + 5 * (size_t) RESULTS_BUFFER) + 65535) & ~(size_t) 65535)
/* On failure attributes are destroyed; success transfers cleanup to caller. */
int spine_thread_attr_init(pthread_attr_t *attributes);

#endif
