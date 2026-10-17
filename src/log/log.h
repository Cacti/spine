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

#ifndef SPINE_LOG_H
#define SPINE_LOG_H

#include <stdbool.h>
#include "log/sanitize.h"
/* Logging borrows format arguments and uses per-thread formatting buffers.
 * Destination writes use existing locks. die reports a fatal error and exits;
 * it is not a signal-handler interface. Logging configuration is app-owned. */
int spine_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
_Noreturn void die(const char *format, ...) __attribute__((format(printf, 1, 2)));
bool spine_should_log_device(int host_id, int verbosity);
void set_date_format(void);
char *get_date_format(void);

#endif
