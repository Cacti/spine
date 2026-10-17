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

#ifndef SPINE_SQL_H
#define SPINE_SQL_H
typedef struct db_address {
	char *storage;
	char *hostname;
	char *socket;
} db_address_t;
extern void db_address_init(db_address_t *address, const char *value, bool parse_socket);
extern void db_address_release(db_address_t *address);

extern int db_insert(MYSQL *mysql, int type, const char *query);
extern MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query);
extern int db_connect(int type, MYSQL *mysql);
extern void db_disconnect(MYSQL *mysql);
extern void db_escape(MYSQL *mysql, char *output, int max_size, const char *input);
extern void db_free_result(MYSQL_RES *result);
extern void db_create_connection_pool(int type);
extern void db_close_connection_pool(int type);
extern pool_t *db_get_connection(int type);
extern void db_release_connection(int type, int id);
extern int db_set_session_mode(MYSQL *mysql);
extern int db_reconnect(MYSQL *mysql, int type, int error, const char *location);
extern int db_column_exists(MYSQL *mysql, int type, const char *table, const char *column);

extern int append_hostrange(char *obuf, size_t capacity, const char *colname);

extern void db_set_option(MYSQL *mysql, enum mysql_option option, const void *value, const char *description);

#endif /* SPINE_SQL_H */
