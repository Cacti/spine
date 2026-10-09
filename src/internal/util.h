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
