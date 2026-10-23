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
