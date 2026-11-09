/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

/* common.h may have read the build configuration already */
#ifndef SPINE_BUILD_CONFIG_H_INCLUDED
#define SPINE_BUILD_CONFIG_H_INCLUDED
#include "config/config.h"
#endif
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include "platform/thread.h"
#include "platform/clock.h"
#include "config/state.h"
#include "log/log.h"

int spine_cond_init_monotonic(pthread_cond_t *cond) {
#ifdef HAVE_PTHREAD_CONDATTR_SETCLOCK
	pthread_condattr_t attributes;
	int status = pthread_condattr_init(&attributes);

	if (status != 0) return status;
	status = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
	if (status == 0) status = pthread_cond_init(cond, &attributes);
	pthread_condattr_destroy(&attributes);
	return status;
#else
	return pthread_cond_init(cond, NULL);
#endif
}

void spine_cond_wait_until(pthread_cond_t *cond, pthread_mutex_t *mutex, double deadline) {
	struct timespec until;
	double instant = deadline;

#ifndef HAVE_PTHREAD_CONDATTR_SETCLOCK
	instant = get_time_as_double() + (deadline - spine_monotonic_time());
#endif
	until.tv_sec = (time_t) instant;
	until.tv_nsec = (long) ((instant - (double) until.tv_sec) * 1000000000.0);
	if (until.tv_nsec < 0) until.tv_nsec = 0;
	if (until.tv_nsec > 999999999L) until.tv_nsec = 999999999L;
	(void) pthread_cond_timedwait(cond, mutex, &until);
}

int spine_permits_init(spine_permits_t *permits, int count) {
	if (count < 0) return EINVAL;
	int status = pthread_mutex_init(&permits->mutex, NULL);
	if (status != 0) return status;
	status = spine_cond_init_monotonic(&permits->released);
	if (status != 0) {
		pthread_mutex_destroy(&permits->mutex);
		return status;
	}
	permits->available = count;
	return 0;
}

int spine_permits_destroy(spine_permits_t *permits) {
	int status = pthread_cond_destroy(&permits->released);
	int mutex_status = pthread_mutex_destroy(&permits->mutex);
	return status != 0 ? status : mutex_status;
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

static void spine_permits_unlock_cleanup(void *permits) {
	spine_permits_unlock(permits);
}

int spine_permits_acquire_until(spine_permits_t *permits, double deadline) {
	int status = 0;

	spine_permits_lock(permits);
	pthread_cleanup_push(spine_permits_unlock_cleanup, permits);
	while (permits->available == 0) {
		if (spine_monotonic_time() >= deadline) {
			status = ETIMEDOUT;
			break;
		}
		spine_cond_wait_until(&permits->released, &permits->mutex, deadline);
	}
	if (status == 0) permits->available--;
	pthread_cleanup_pop(1);
	return status;
}

/* Broadcast, not signal: a waiter that times out as the permit arrives must
 * not absorb the only wake-up while another waiter keeps sleeping. */
int spine_permits_release(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EOVERFLOW;
	if (permits->available < INT_MAX) {
		permits->available++;
		status = 0;
		pthread_cond_broadcast(&permits->released);
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
