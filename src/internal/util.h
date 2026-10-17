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

#ifndef SPINE_UTIL_H
#define SPINE_UTIL_H

#include "app/buffer.h"
#include "platform/clock.h"
#include "platform/socket.h"
#include "platform/thread.h"
#include "platform/descriptor.h"
#include "config/text.h"
#include "config/validate.h"
#include "log/log.h"
#include "log/debug.h"
#include "script/escape.h"
#include "poller/result.h"
/* Transitional forwarding interface for legacy callers. New modules include
 * the focused headers above directly; no implementation remains in util.c. */
void read_config_options(void);
int read_spine_config(const char *file);
void config_defaults(void);
void set_option(const char *setting, const char *value);
bool poller_transfer_status(MYSQL *source, MYSQL *destination);
void poller_push_data_to_main(void);
#define MAX_MATCHES 5
#define REGEX_NUMBER "([-+]*)([0-9]*)([.][0-9]+)"
#define CAPABILITY_PROTOCOL_LIST_MAX 480
char *regex_replace(const char *expression, char *value);
int format_spine_capabilities(char *output, size_t size,
	const char *auth_protocols, const char *priv_protocols);
void drop_privileges(void);
int privileges_dropped(uid_t uid, gid_t gid);
int hasCaps(void);
void checkAsRoot(void);
int db_row_alias_upsert_supported(const char *version, unsigned long version_number);
extern double start_time;
int get_cacti_version(MYSQL *mysql, int mode);

#endif
