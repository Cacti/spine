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

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "platform/thread.h"
#include "config/state.h"
#include "log/log.h"

int spine_permits_init(spine_permits_t *permits, int count) {
	if (count < 0) return EINVAL;
	int status = pthread_mutex_init(&permits->mutex, NULL);
	if (status == 0) permits->available = count;
	return status;
}

int spine_permits_destroy(spine_permits_t *permits) {
	return pthread_mutex_destroy(&permits->mutex);
}

static void spine_permits_lock(spine_permits_t *permits) {
	if (pthread_mutex_lock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to lock process permits");
	}
}

static void spine_permits_unlock(spine_permits_t *permits) {
	if (pthread_mutex_unlock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to unlock process permits");
	}
}

int spine_permits_try_acquire(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EAGAIN;
	if (permits->available > 0) {
		permits->available--;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_release(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EOVERFLOW;
	if (permits->available < INT_MAX) {
		permits->available++;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_available(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int available = permits->available;
	spine_permits_unlock(permits);
	return available;
}

int spine_thread_attr_init(pthread_attr_t *attributes) {
	size_t current = 0;
	size_t wanted = SPINE_THREAD_STACK_SIZE;
	int status;

#ifdef PTHREAD_STACK_MIN
	if (wanted < (size_t) PTHREAD_STACK_MIN) wanted = (size_t) PTHREAD_STACK_MIN;
#endif

	status = pthread_attr_init(attributes);
	if (status != 0) {
		return status;
	}

	if (pthread_attr_getstacksize(attributes, &current) == 0 && current >= wanted) {
		return 0;
	}

	status = pthread_attr_setstacksize(attributes, wanted);
	if (status != 0) {
		pthread_attr_destroy(attributes);
	}

	return status;
}
