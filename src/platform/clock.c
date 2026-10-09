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
