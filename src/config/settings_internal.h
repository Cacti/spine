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

#ifndef SPINE_SETTINGS_INTERNAL_H
#define SPINE_SETTINGS_INTERNAL_H

#include "internal/common.h"
#include "app/spine.h"
void settings_cache_free(void);
void settings_cache_load(MYSQL *mysql, int mode);
char *getsetting(MYSQL *mysql, int mode, const char *setting);
char *getpsetting(MYSQL *mysql, int mode, const char *setting);
int getboolsetting(MYSQL *mysql, int mode, const char *setting, int fallback);
char *getglobalvariable(MYSQL *mysql, int mode, const char *setting);
MYSQL_RES *config_query(MYSQL *mysql, int mode, const char *query);
int putsetting(MYSQL *mysql, int mode, const char *setting, const char *value);
#endif
