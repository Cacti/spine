/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
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

#ifndef _SPINE_H_
#define _SPINE_H_

#include "internal/spine_types.h"

/* Include all Standard Spine Headers */
#include "poller/poller.h"
#include "platform/locks.h"
#include "config/keywords.h"
#include "snmp/snmp.h"
#include "script/server.h"
#include "ping/ping.h"
#include "database/sql.h"
#include "internal/util.h"
#include "process/nft_popen.h"
#include "app/signals.h"

/* Globals */
extern int spine_snmpv3_protocol_is_set(const char *value);
extern int spine_snmpv3_passphrase_is_set(const char *value);
extern int spine_snmpv3_security_level(const char *auth_protocol, const char *auth_password,
	const char *priv_protocol, const char *priv_passphrase);

extern config_t set;
extern php_t *php_processes;
extern char start_datetime[20];
extern char config_paths[CONFIG_PATHS][BUFSIZE];
extern spine_permits_t available_threads;
extern spine_permits_t available_scripts;
extern pool_t *db_pool_remote;
extern pool_t *db_pool_local;

#endif /* not _SPINE_H_ */
