/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2021 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

extern int db_insert(MYSQL *mysql, int type, const char *query);
extern MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query);
extern void db_connect(int type, MYSQL *mysql);
extern void db_disconnect(MYSQL *mysql);
extern void db_escape(MYSQL *mysql, char *output, int max_size, const char *input);
extern void db_free_result(MYSQL_RES *result);
extern void db_create_connection_pool(int type);
extern void db_close_connection_pool(int type);
extern pool_t *db_get_connection(int type);
extern void db_release_connection(int type, int id);
extern int  db_reconnect(MYSQL *mysql, int error, char *location);

extern int append_hostrange(char *obuf, const char *colname);

#define MYSQL_SET_OPTION(opt, value, desc)	\
	options_error = mysql_options(mysql, opt, value); \
	if (options_error < 0) {\
	        die("FATAL: MySQL options unable to set %s option", desc);\
	}\

