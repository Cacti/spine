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

#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "app/buffer.h"
#include "config/state.h"
#include "log/log.h"

int spine_snprintf(char *output, size_t capacity, const char *format, ...) {
	va_list args;
	int length;

	va_start(args, format);
	length = vsnprintf(output, capacity, format, args);
	va_end(args);
	if (length < 0 || (size_t) length >= capacity) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Formatted output exceeds its destination buffer");
	}
	return length;
}

int spine_count_to_int(unsigned long long count) {
	if (count > INT_MAX) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Result count exceeds supported integer range");
	}
	return (int) count;
}

void spine_clear_sensitive(void *buffer, size_t length) {
	volatile unsigned char *bytes = buffer;
	while (length > 0) {
		*bytes++ = 0;
		length--;
	}
}

char *strncopy(char *dst, const char *src, size_t obuf) {
	assert(dst != NULL);
	assert(src != NULL);

	size_t len;

	if (obuf == 0) return dst;
	/* Bound the scan by the usable capacity; src may be large or unterminated. */
	len = strnlen(src, obuf - 1);
	if (len) {
		memcpy(dst, src, len);
	}

	dst[len] = '\0';
	return dst;
}

int spine_appendf(char **cursor, size_t *remaining, const char *fmt, ...) {
	va_list args;
	int written;

	if (cursor == NULL || *cursor == NULL || remaining == NULL || *remaining == 0) {
		return FALSE;
	}

	va_start(args, fmt);
	written = vsnprintf(*cursor, *remaining, fmt, args);
	va_end(args);

	if (written < 0) {
		/* the buffer is untouched on an encoding error, but vsnprintf may have
		   written a partial result, so re-terminate where the cursor stands */
		**cursor = '\0';
		return FALSE;
	}

	if ((size_t) written >= *remaining) {
		/* Truncated. Leave the cursor on the terminator vsnprintf wrote, so
		   the buffer stays a valid string and every later append fails here
		   rather than running past the end. */
		*cursor += *remaining - 1;
		*remaining = 1;
		return FALSE;
	}

	*cursor += written;
	*remaining -= (size_t) written;

	return TRUE;
}
