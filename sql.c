/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2003 Ian Berry                                            |
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
#include "sql.h"

int db_insert(char *query, MYSQL *mysql) {
	if (set.verbose >= HIGH) {
		printf("SQL: %s\n", query);
	}
	
	if (mysql_query(mysql, query)) {
		if (set.verbose >= LOW) {
			fprintf(stderr, "** MySQL Error: %s\n", mysql_error(mysql));
		}
		
		return (FALSE);
	}else{
		return (TRUE);
	}
}

MYSQL_RES *db_query(MYSQL *mysql, char *query) {
	MYSQL_RES *mysql_res;
	
	mysql_query(mysql, query);
	mysql_res = mysql_store_result(mysql);
	
	return mysql_res;
}


int db_connect(char *database, MYSQL *mysql) {
	if (set.verbose >= LOW) {
		printf("Connecting to MySQL database '%s' on '%s'...\n", database, set.dbhost);
	}
	
	mutex_lock(LOCK_MYSQL);
	mysql_init(mysql);
	mutex_unlock(LOCK_MYSQL);
    	
	if (!mysql_real_connect(mysql, set.dbhost, set.dbuser, set.dbpass, database, 0, NULL, 0)) {
		fprintf(stderr, "** Failed: %s\n", mysql_error(mysql));
		exit(0);
	}else{
		return (0);
	}
}


void db_disconnect(MYSQL *mysql) {
	mysql_close(mysql);
}
