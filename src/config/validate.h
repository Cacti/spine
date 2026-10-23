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

#ifndef SPINE_CONFIG_VALIDATE_H
#define SPINE_CONFIG_VALIDATE_H
/* Borrow terminated input; no allocation or shared state. Preserve legacy
 * lexical validation, including its address-character grammar. These are
 * compatibility predicates, not complete IP parsers. */
int all_digits(const char *string);
int is_ipaddress(const char *string);
#endif
