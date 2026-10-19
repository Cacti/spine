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
