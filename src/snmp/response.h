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

#ifndef SPINE_SNMP_RESPONSE_H
#define SPINE_SNMP_RESPONSE_H
#include "internal/spine_types.h"
/* Borrow host/OID/varbind inputs; output is caller-owned RESULTS_BUFFER storage.
 * Return the existing STAT_SUCCESS/STAT_ERROR result, with U for unavailable
 * values. Caller retains session synchronization and varbind ownership. */
int snmp_get_variable(const host_t *host, const char *text_oid,
	const struct variable_list *variable, char *output);
int snmp_format_scalar(char *output, const struct variable_list *variable, bool ascii);
#endif
