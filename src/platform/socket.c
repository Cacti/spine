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

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <sys/select.h>
#include "internal/constants.h"
#include "platform/socket.h"
#include "platform/clock.h"

static int spine_wait_fd(int fd, double deadline, bool writable) {
	if (fd < 0 || fd >= FD_SETSIZE) {
		errno = EBADF;
		return -1;
	}
	if (!isfinite(deadline)) {
		errno = EINVAL;
		return -1;
	}
	for (;;) {
		double remaining = deadline - spine_monotonic_time();
		if (remaining <= 0) return 0;
		if (remaining > INT_MAX) {
			errno = EINVAL;
			return -1;
		}
		struct timeval timeout;
		timeout.tv_sec = (time_t) remaining;
		timeout.tv_usec = (suseconds_t) ((remaining - (double) timeout.tv_sec) * 1000000);
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		int status = select(fd + 1, writable ? NULL : &fds, writable ? &fds : NULL, NULL, &timeout);
		if (status < 0 && errno == EINTR) continue;
		return status;
	}
}

int spine_wait_readable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, FALSE);
}

int spine_wait_writable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, TRUE);
}
