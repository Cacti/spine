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

extern int db_insert(MYSQL *mysql, int type, const char *query)
	SPINE_ATTR_NONNULL(1, 3);
extern MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query)
	SPINE_ATTR_NONNULL(1, 3)
	SPINE_ATTR_WARN_UNUSED;
extern void db_connect(int type, MYSQL *mysql)
	SPINE_ATTR_NONNULL(2);
extern void db_disconnect(MYSQL *mysql)
	SPINE_ATTR_NONNULL(1);
extern void db_escape(MYSQL *mysql, char *output, int max_size, const char *input)
	SPINE_ATTR_NONNULL(1, 2, 4);
extern void db_free_result(MYSQL_RES *result);
extern void db_create_connection_pool(int type);
extern void db_close_connection_pool(int type);
extern pool_t *db_get_connection(int type)
	SPINE_ATTR_WARN_UNUSED;
extern void db_release_connection(int type, int id);
extern int  db_reconnect(MYSQL *mysql, int type, int error, const char *location)
	SPINE_ATTR_NONNULL(1);
extern int db_column_exists(MYSQL *mysql, int type, const char *table, const char *column)
	SPINE_ATTR_NONNULL(1, 3, 4);

typedef struct {
	char   *buffer;
	size_t  capacity;
	size_t  length;
} sql_buffer_t;

/* Conservative fail-safe for MariaDB/MySQL max_allowed_packet constraints */
#define SQL_MAX_BUFFER_CAPACITY (8 * 1024 * 1024)

extern int  sql_buffer_init(sql_buffer_t *sb, size_t initial_capacity)
	SPINE_ATTR_NONNULL(1) SPINE_ATTR_WARN_UNUSED;
extern int  sql_buffer_append(sql_buffer_t *sb, const char *format, ...)
	SPINE_ATTR_NONNULL(1, 2) SPINE_ATTR_WARN_UNUSED;
extern void sql_buffer_reset(sql_buffer_t *sb)
	SPINE_ATTR_NONNULL(1);
extern void sql_buffer_truncate(sql_buffer_t *sb, size_t length)
	SPINE_ATTR_NONNULL(1);
extern void sql_buffer_free(sql_buffer_t *sb);

extern char *db_fetch_cell_dup(MYSQL_RES *result, int col_index)
	SPINE_ATTR_WARN_UNUSED;

extern int append_hostrange(char *obuf, const char *colname)
	SPINE_ATTR_NONNULL(1, 2);

#define MYSQL_SET_OPTION(opt, value, desc)	\
{\
	options_error = mysql_options(mysql, opt, value); \
	if (options_error < 0) {\
	        die("FATAL: MySQL options unable to set %s option", desc);\
	}\
}\
