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

#include <stdlib.h>
#include <string.h>
#include "internal/constants.h"
#include "log/debug.h"

int is_debug_device(int device_id) {
	extern int *debug_devices;
	int i = 0;

	/* main() releases the list during shutdown; later logging must not read it. */
	if (debug_devices == NULL) return FALSE;

	while (i < MAX_DEBUG_DEVICES) {
		if (debug_devices[i] == '\0') break;
		if (debug_devices[i] == device_id) {
			return TRUE;
		}

		i++;
	}

	return FALSE;
}

void parse_debug_devices(char *device_list, int *devices, size_t capacity) {
	if (capacity == 0) return;
	devices[0] = 0;
	char *saveptr = NULL;
	const char *token = strtok_r(device_list, ",", &saveptr);
	for (size_t i = 0; token != NULL && i < capacity - 1; i++, token = strtok_r(NULL, ",", &saveptr)) {
		devices[i] = atoi(token);
		devices[i + 1] = 0;
	}
}
