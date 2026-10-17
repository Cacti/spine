/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_BUFFER_H
#define SPINE_BUFFER_H

#include <stddef.h>
/* Caller owns every buffer. Functions have no internal mutable state.
 * strncopy intentionally truncates and terminates when capacity is nonzero.
 * snprintf/count conversion fail through die on overflow; appendf returns 0
 * on invalid arguments, formatting error or truncation and keeps termination.
 * Callers must synchronize concurrent access to their own storage. */
char *strncopy(char *dst, const char *src, size_t capacity);
int spine_snprintf(char *output, size_t capacity, const char *format, ...)
	__attribute__((format(printf, 3, 4)));
int spine_count_to_int(unsigned long long count);
int spine_appendf(char **cursor, size_t *remaining, const char *format, ...)
	__attribute__((format(printf, 3, 4)));
void spine_clear_sensitive(void *buffer, size_t length);
#define STRNCOPY(dst, src) strncopy((dst), (src), sizeof(dst))
#define USTRNCOPY(dst, src) ustrncopy((dst), (src), sizeof(dst))
#define STRDUP_OR_DIE(dst, src, reason) \
	if ((dst = strdup(src)) == NULL) { \
		die("FATAL: malloc() failed during strdup() for %s", reason); \
	}

#endif
