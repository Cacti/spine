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

#ifndef SPINE_KEYWORDS_H
#define SPINE_KEYWORDS_H
extern const char *printable_log_level(int token);
extern int parse_log_level(const char *word, int dflt);

extern const char *printable_logdest(int token);
extern int parse_logdest(const char *word, int dflt);

extern const char *printable_action(int token);
extern int parse_action(const char *word, int dflt);

#endif /* SPINE_KEYWORDS_H */
