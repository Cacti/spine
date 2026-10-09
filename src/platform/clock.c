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
#include <time.h>
#include <sys/time.h>
#include "platform/clock.h"
#include "config/state.h"
#include "log/log.h"

void spine_sleep_usec(unsigned int microseconds) {
	struct timespec requested = {
		(time_t) (microseconds / 1000000), (long) (microseconds % 1000000) * 1000};
	while (nanosleep(&requested, &requested) != 0) {
		if (errno != EINTR) {
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Unable to wait for retry delay");
		}
	}
}

double spine_monotonic_time(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to read monotonic clock");
	}
	return (double) now.tv_sec + (double) now.tv_nsec / 1000000000;
}

double get_time_as_double(void) {
	struct timeval now;

	gettimeofday(&now, NULL);

	return (double) now.tv_sec + (double) now.tv_usec / 1000000;
}
