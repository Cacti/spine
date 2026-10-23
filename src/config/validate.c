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

#include <ctype.h>
#include "internal/constants.h"
#include "config/validate.h"

int all_digits(const char *string) {
	/* empty string is not all digits */
	if (*string == '\0') return FALSE;

	while (isdigit((unsigned char) *string))
		string++;

	return *string == '\0';
}

int is_ipaddress(const char *string) {
	while (*string) {
		if ((isdigit((unsigned char) *string)) ||
			(*string == '.') ||
			(*string == ':')) {
			string++;

			continue;
		}

		return FALSE;
	}

	return TRUE;
}
