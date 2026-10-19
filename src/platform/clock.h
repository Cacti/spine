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

#ifndef SPINE_CLOCK_H
#define SPINE_CLOCK_H

/* No shared mutable state. Clock/sleep errors retain fatal behavior.
 * Monotonic time is for deadlines; wall time is for reporting only. */
void spine_sleep_usec(unsigned int microseconds);
double spine_monotonic_time(void);
double get_time_as_double(void);

#endif
