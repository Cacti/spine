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

#ifndef SPINE_TEXT_H
#define SPINE_TEXT_H

/* Mutable helpers borrow and modify caller storage. Returned pointers may
 * point inside that storage and must not be freed separately. No globals or
 * internal locks; callers synchronize shared buffers. */
char *strip_alpha(char *string);
char *trim(char *string);
char *rtrim(char *string);
char *ltrim(char *string);
char *reverse(char *string);
int strpos(const char *haystack, const char *needle);
int char_count(const char *string, int character);

#endif
