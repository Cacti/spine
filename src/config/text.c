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

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include "config/text.h"

char *strip_alpha(char *string) {
	size_t end = strlen(string);
	while (end > 0 && !isdigit((unsigned char) string[end - 1])) string[--end] = '\0';
	size_t start = 0;
	while (start < end && !isdigit((unsigned char) string[start]) && string[start] != '-') start++;
	return string + start;
}

char *trim(char *str) {
	return ltrim(rtrim(str));
}

char *rtrim(char *str) {
	char *end;
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	end = str + strlen(str);

	while (end > str) {
		--end;
		if (!strchr(trim_chars, *end)) return str;

		*end = 0;
	}

	return str;
}

char *ltrim(char *str) {
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	while (*str) {
		if (!strchr(trim_chars, *str)) return str;

		++str;
	}

	return str;
}

char *reverse(char *str) {
	size_t start = 0;
	size_t end = strlen(str);
	while (start < end) {
		end--;
		if (start >= end) break;
		char byte = str[start];
		str[start++] = str[end];
		str[end] = byte;
	}
	return str;
}

int strpos(const char *haystack, const char *needle) {
	const char *p = strstr(haystack, needle);

	if (p) {
		return p - haystack <= INT_MAX ? (int) (p - haystack) : -1;
	}

	return -1;
}

int char_count(const char *str, int chr) {
	const unsigned char *my_str = (const unsigned char *) str;
	const unsigned char my_chr = (unsigned char) chr;
	int count = 0;

	if (!my_chr) return 1;

	while (*my_str) {
		if (*my_str++ == my_chr) {
			count++;
		}
	}
	return count;
}
