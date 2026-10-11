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

#include "internal/common.h"
#include "app/spine.h"

bool db_upsert_suffix(MYSQL *destination, char *buffer, size_t capacity,
	const char *const *columns, size_t count) {
	const char *server;
	bool row_alias;
	char *cursor = buffer;
	size_t remaining = capacity;
	size_t index;

	if (buffer == NULL || capacity == 0 || columns == NULL || count == 0) return FALSE;
	buffer[0] = '\0';
	server = destination == NULL ? NULL : mysql_get_server_info(destination);
	/* MariaDB may expose a MySQL compatibility prefix. Identify the vendor
	 * before checking the version; unknown metadata uses the legacy fallback. */
	row_alias = server != NULL && strstr(server, "MariaDB") == NULL &&
		mysql_get_server_version(destination) >= 80019;
	if (!spine_appendf(&cursor, &remaining, "%s ON DUPLICATE KEY UPDATE ", row_alias ? " AS spine_row" : "")) return FALSE;
	for (index = 0; index < count; index++) {
		if (columns[index] == NULL || columns[index][0] == '\0') return FALSE;
		if (!spine_appendf(&cursor, &remaining, row_alias ? "%s%s=spine_row.%s" : "%s%s=VALUES(%s)",
				index == 0 ? "" : ", ", columns[index], columns[index])) return FALSE;
	}
	return TRUE;
}
