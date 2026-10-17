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

#ifndef SPINE_CONFIG_STATE_H
#define SPINE_CONFIG_STATE_H

#include "config/model.h"
/* Process-wide storage is owned by app/runtime.c. Callers retain the existing
 * initialization and subsystem locking contracts; access adds no implicit
 * synchronization. Shutdown wipes credentials after worker cleanup. */
extern config_t set;

#endif
