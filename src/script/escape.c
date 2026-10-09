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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config/state.h"
#include "log/log.h"
#include "script/escape.h"

char *add_slashes(const char *string) {
	size_t length = strlen(string);
	if (length > (SIZE_MAX - 1) / 2) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Escaped command exceeds addressable memory");
	}
	char *result = malloc(length * 2 + 1);
	if (result == NULL) die("ERROR: Fatal malloc error: util.c add_slashes!");
	size_t used = 0;
	for (size_t i = 0; i < length; i++) {
		if (string[i] == '\\') result[used++] = '\\';
		result[used++] = string[i];
	}
	result[used] = '\0';
	return result;
}
