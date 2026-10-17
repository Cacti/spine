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
