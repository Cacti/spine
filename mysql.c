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
 |    - Rivo Nurges (rrd support, mysql poller cache, misc functions)      |
 |    - RTG (core poller code, pthreads, snmp, autoconf examples)          |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "cactid.h"


int db_insert(char *query, MYSQL * mysql)
{
    if (set.verbose >= HIGH)
	printf("SQL: %s\n", query);
    if (mysql_query(mysql, query)) {
	if (set.verbose >= LOW)
	    fprintf(stderr, "** MySQL Error: %s\n", mysql_error(mysql));
	return (FALSE);
    } else
	return (TRUE);
}


int rtg_dbconnect(char *database, MYSQL * mysql)
{
    if (set.verbose >= LOW)
	printf("Connecting to MySQL database '%s' on '%s'...", database, set.dbhost);
    mysql_init(mysql);
    if (!mysql_real_connect
     (mysql, set.dbhost, set.dbuser, set.dbpass, database, 0, NULL, 0)) {
	fprintf(stderr, "** Failed: %s\n", mysql_error(mysql));
	return (-1);
    } else
	return (0);
}


void rtg_dbdisconnect(MYSQL * mysql)
{
    mysql_close(mysql);
}
