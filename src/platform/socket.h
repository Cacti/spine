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

#ifndef SPINE_SOCKET_H
#define SPINE_SOCKET_H

/* Borrow fd; never close it. Deadlines use spine_monotonic_time().
 * Return positive on readiness, 0 on expiry, -1 with errno on error.
 * EINTR recomputes remaining time. Caller owns descriptor lifetime. */
int spine_wait_readable(int fd, double deadline);
int spine_wait_writable(int fd, double deadline);

#endif
