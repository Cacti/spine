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

#include "internal/common.h"
#include "app/spine.h"
#include "poller/poller_internal.h"
#include <limits.h>

static void poll_system_uptime(host_t *host) {
	char *poll_result;
	unsigned long long ticks;
	// Get the legacy system uptime instance first
	SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.2.1.1.3.0');", host->id));
	poll_result = snmp_get_allow_fail(host, ".1.3.6.1.2.1.1.3.0");
	SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.2.1.1.3.0'); [complete]", host->id));

	if (parse_uptime(poll_result, &ticks)) {
		host->system.snmp_sysUpTimeInstance = ticks;
		SPINE_FREE(poll_result);

		// Attempt to get the more modern version
		SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.6.3.10.2.1.3.0');", host->id));
		poll_result = snmp_get_allow_fail(host, ".1.3.6.1.6.3.10.2.1.3.0");
		SPINE_LOG_DEVDBG(("DEVDGB: Device[%d] poll_result = snmp_get_allow_fail(host, '.1.3.6.1.6.3.10.2.1.3.0'); [complete]", host->id));

		if (parse_uptime(poll_result, &ticks)) {
			host->system.snmp_sysUpTimeInstance = ticks * 100;
		}
	}
	SPINE_FREE(poll_result);
}

static void poll_system_field(host_t *host, MYSQL *mysql, char *oid, char *destination, size_t capacity) {
	SPINE_LOG_DEVDBG(("DEVDBG: Device[%d] requesting system OID %s", host->id, oid));
	char *result = snmp_get_allow_fail(host, oid);
	if (result != NULL) db_escape(mysql, destination, (int) capacity, result);
	SPINE_FREE(result);
}

void get_system_information(host_t *host, MYSQL *mysql, int system) {
	SPINE_LOG_MEDIUM(("Device[%d] Checking for System Information Update", host->id));
	bool full = set.snmp.mibs || system;
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%d] Updating %s System Information Table", host->id, full ? "Full" : "Short"));
	if (full) {
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.1.0", host->system.snmp_sysDescr, sizeof(host->system.snmp_sysDescr));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.2.0", host->system.snmp_sysObjectID, sizeof(host->system.snmp_sysObjectID));
	}
	poll_system_uptime(host);
	if (full) {
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.4.0", host->system.snmp_sysContact, sizeof(host->system.snmp_sysContact));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.5.0", host->system.snmp_sysName, sizeof(host->system.snmp_sysName));
		poll_system_field(host, mysql, ".1.3.6.1.2.1.1.6.0", host->system.snmp_sysLocation, sizeof(host->system.snmp_sysLocation));
	}
}
