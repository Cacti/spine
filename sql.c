/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "util.h"
#include "sql.h"

int db_insert(MYSQL *mysql, char *query) {
	char logmessage[LOGSIZE];

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: SQLCMD: %s\n", query);
		cacti_log(logmessage);
	}

	thread_mutex_lock(LOCK_MYSQL);
	if (mysql_query(mysql, query)) {
		snprintf(logmessage, LOGSIZE, "ERROR: Problem with MySQL: %s\n", mysql_error(mysql));
		cacti_log(logmessage);
  		thread_mutex_unlock(LOCK_MYSQL);
		return (FALSE);
	}else{
		thread_mutex_unlock(LOCK_MYSQL);
		return (TRUE);
	}
}

MYSQL_RES *db_query(MYSQL *mysql, char *query) {
	MYSQL_RES *mysql_res;

	thread_mutex_lock(LOCK_MYSQL);
 	mysql_query(mysql, query);
	mysql_res = mysql_store_result(mysql);
	thread_mutex_unlock(LOCK_MYSQL);

	return mysql_res;
}

int db_connect(char *database, MYSQL *mysql) {
	char logmessage[LOGSIZE];
	int retries;

	if (set.verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "MYSQL: Connecting to MySQL database '%s' on '%s'...\n", database, set.dbhost);
		cacti_log(logmessage);
	}

	retries = 1;
	mysql_init(mysql);
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, "5");
		
	while (1) {
		thread_mutex_lock(LOCK_MYSQL);

		if (!mysql_real_connect(mysql, set.dbhost, set.dbuser, set.dbpass, database, set.dbport, NULL, 0)) {
			if (retries > 10) {
				snprintf(logmessage, LOGSIZE, "MYSQL: Connection failed after 10 attempts : %s\n", mysql_error(mysql));
				cacti_log(logmessage);
				thread_mutex_unlock(LOCK_MYSQL);
				exit(-1);
			} else {
				retries++;
				usleep(100000);
			}
		}else {
			thread_mutex_unlock(LOCK_MYSQL);
			return (0);
		}
	}
}

void db_disconnect(MYSQL *mysql) {
	mysql_close(mysql);
}


