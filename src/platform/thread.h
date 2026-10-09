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
