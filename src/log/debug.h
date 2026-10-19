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

#ifndef SPINE_DEBUG_H
#define SPINE_DEBUG_H

#include <stddef.h>
/* The app owns the debug-device list: initialize before workers, release
 * after they stop. Queries borrow it; no synchronization is added here.
 * Parsing mutates device_list and fills caller-owned devices with a sentinel. */
int is_debug_device(int device_id);
void parse_debug_devices(char *device_list, int *devices, size_t capacity);

#endif
