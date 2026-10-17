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

#include "log/sanitize.h"

void spine_sanitize_log_message(char *message) {
	for (unsigned char *p = (unsigned char *) message; *p != 0; p++) {
		if (*p < 0x20 || *p == 0x7f) {
			*p = ' ';
		} else if (p[0] == 0xc2 && p[1] == 0x85) {
			p[0] = ' ';
			p[1] = ' ';
		} else if (p[0] == 0xe2 && p[1] == 0x80 && (p[2] == 0xa8 || p[2] == 0xa9)) {
			p[0] = ' ';
			p[1] = ' ';
			p[2] = ' ';
		}
	}
}
