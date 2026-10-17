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

#include "internal/common.h"
#include "app/spine.h"

/*! \fn int db_insert(MYSQL *mysql, int type, const char *query)
 *  \brief inserts a row or rows in a database table.
 *  \param mysql the database connection object
 *  \param type  the database to connect to local or remote
 *  \param query the database query to execute
 *
 *	Unless the SQL_readonly boolean is set to TRUE, the function will execute
 *	the SQL statement specified in the query variable.
 *
 *  \return TRUE if successful, or FALSE if not.
 *
 */
/* Returns FALSE when the statement should not be retried. A failed reconnect
 * ends the attempt at once: db_connect() has already spent its own tries, and
 * repeating it here only multiplies the wait while a worker holds its device. */
static bool retry_disconnected_query(MYSQL *mysql, int type, int error, const char *function, int *error_count) {
	/* Every attempt counts. A signal that interrupted the call gets a few
	 * in-place retries, but the client library does not reset errno, so a
	 * stale EINTR used to skip both the reconnect and the count forever. */
	if (++*error_count > 30) {
		SPINE_LOG(("ERROR: Too many Reconnect Attempts in Function %s", function));
		return FALSE;
	}
	if (errno == EINTR && *error_count <= 3) {
		spine_sleep_usec(50000);
		return TRUE;
	}
	return db_reconnect(mysql, type, error, function) >= 0;
}

int db_insert(MYSQL *mysql, int type, const char *query) {
	int error_count = 0;
	char query_frag[LRG_BUFSIZE];
	snprintf(query_frag, sizeof(query_frag), "%s", query);
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));
	if (set.poller.SQL_readonly != FALSE) return TRUE;
	while (mysql_query(mysql, query) != 0) {
		int error = mysql_errno(mysql);
		if (error == 2013 || error == 2006) {
			if (retry_disconnected_query(mysql, type, error, "db_insert", &error_count)) continue;
			SPINE_LOG(("ERROR: SQL Failed! Connection lost, SQL Fragment:'%s'", query_frag));
			return FALSE;
		}
		if (error == 1213 || error == 1205) {
			spine_sleep_usec(50000);
			if (++error_count > 30) {
				SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
				return FALSE;
			}
			continue;
		}
		SPINE_LOG(("ERROR: SQL Failed! Error:'%i', Message:'%s', SQL Fragment:'%s'", error, mysql_error(mysql), query_frag));
		return FALSE;
	}
	return TRUE;
}

/*! \fn int db_set_session_mode(MYSQL *mysql)
 *  \brief relaxes the session sql_mode to what Cacti's schema needs.
 *
 *  Uses mysql_query() directly so a failure here never recurses into the
 *  reconnect path. Every new session needs it, including one opened by a
 *  reconnect, since the server starts each session at its default mode.
 *  SQL_readonly does not skip it: it changes no data.
 *
 *  \return TRUE when every statement succeeded
 */
int db_set_session_mode(MYSQL *mysql) {
	static const char *const modes[] = {
		"NO_ZERO_DATE", "NO_ZERO_IN_DATE", "ONLY_FULL_GROUP_BY", "NO_AUTO_VALUE_ON_ZERO",
		"TRADITIONAL", "STRICT_ALL_TABLES", "STRICT_TRANS_TABLES"};
	char query[BUFSIZE];
	size_t i;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		snprintf(query, sizeof(query), "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'%s', ''))", modes[i]);
		if (mysql_query(mysql, query) != 0) {
			SPINE_LOG(("ERROR: Unable to set the session sql_mode: %s", mysql_error(mysql)));
			return FALSE;
		}
	}

	return TRUE;
}

/* Returns TRUE after a reconnect, FALSE when the session was still alive, and
 * -1 when the server could not be reached. After -1 the handle is initialized
 * but unconnected, so the next attempt closes and reconnects it again. */
int db_reconnect(MYSQL *mysql, int type, int error, const char *function) {
	const unsigned long mysql_thread = mysql_thread_id(mysql);
	char query[100];
	int ping_status;

	ping_status = mysql_ping(mysql);

	if (mysql_thread_id(mysql) != mysql_thread) {
		SPINE_LOG(("WARNING: Connection Broken in Function %s with Error %i.  Reconnect via mysql_ping() successful.", function, error));
		snprintf(query, sizeof(query), "KILL %lu;", mysql_thread);
		mysql_query(mysql, query);

		if (!db_set_session_mode(mysql)) return -1;

		sleep(1);

		return TRUE;
	}

	/* A live session on the same thread has nothing to reconnect. */
	if (ping_status == 0) {
		return FALSE;
	}

	/* mysql_ping() did not reconnect; do it explicitly */
	SPINE_LOG(("WARNING: Connection Broken in Function %s with Error %i.  Attempting explicit reconnect.", function, error));

	mysql_close(mysql);

	if (db_connect(type, mysql) && mysql_thread_id(mysql) > 0 && db_set_session_mode(mysql)) {
		SPINE_LOG(("WARNING: Explicit reconnect successful in Function %s.", function));
		return TRUE;
	}

	SPINE_LOG(("WARNING: Connection Broken with Error %i.  Reconnect failed.", error));
	return -1;
}

/*! \fn MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query)
 *  \brief executes a query and returns a pointer to the result set.
 *  \param mysql the database connection object
 *  \param query the database query to execute
 *
 *	This function will execute the SQL statement specified in the query variable.
 *
 *  \return MYSQL_RES a MySQL result structure, or NULL when the statement
 *          failed or produced no result set; the caller decides whether a
 *          failure ends a device, a startup step or the process
 *
 */
MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query) {
	int error_count = 0;
	char query_frag[LRG_BUFSIZE];
	snprintf(query_frag, sizeof(query_frag), "%s", query);
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));
	while (mysql_query(mysql, query) != 0) {
		int error = mysql_errno(mysql);
		if (error == 2013 || error == 2006) {
			if (retry_disconnected_query(mysql, type, error, "db_query", &error_count)) continue;
			SPINE_LOG(("ERROR: Database connection lost, SQL Fragment:'%s'", query_frag));
			return NULL;
		}
		if (error == 1213 || error == 1205) {
			spine_sleep_usec(50000);
			if (++error_count > 30) {
				SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
				return NULL;
			}
			continue;
		}
		SPINE_LOG(("ERROR: Database Error:'%i', Message:'%s'", error, mysql_error(mysql)));
		SPINE_LOG(("ERROR: The Query Was:'%s'", query));
		return NULL;
	}
	return mysql_store_result(mysql);
}

/*! \fn int append_hostrange(char *obuf, const char *colname, const config_t *set)
 *  \brief appends a host range to a sql select statement
 *  \param obuf the sql select statement to have the host range appended
 *  \param colname the sql column name that will have the host range checked
 *  \param set global runtime settings
 *
 *	Several places in the code need to limit the range of hosts to
 *	those with a certain ID range, but only if those range values
 *	are actually nonzero.
 *
 *	This appends the SQL clause if necessary, returning the # of
 *	characters added to the buffer. Else return 0.
 *
 *  \return the number of characters added to the end of the character buffer
 *
 */
int append_hostrange(char *obuf, size_t capacity, const char *colname) {
	if (HOSTID_DEFINED(set.hosts.start_host_id) && HOSTID_DEFINED(set.hosts.end_host_id)) {
		return spine_snprintf(obuf, capacity, " AND %s BETWEEN %d AND %d",
			colname,
			set.hosts.start_host_id,
			set.hosts.end_host_id);
	} else {
		return 0;
	}
}

/*! \fn void db_escape(MYSQL *mysql, char *output, int max_size, const char *input)
 *  \brief Escapes a text string to make it safe for mysql insert/updates
 *  \param mysql the connection object
 *  \param output a pointer to the output string
 *  \param a pointer to the input string
 *
 *	A simple implementation of the mysql_real_escape_string that one
 *  day should be portable.
 *
 *  \return void
 *
 */
void db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	size_t input_len;
	size_t max_input;

	if (input == NULL || output == NULL) return;

	if (max_size <= 1) {
		if (max_size == 1) {
			*output = '\0';
		}
		return;
	}

	/* Escaping can double every byte and adds a NUL terminator. Derive the
	 * input limit from the caller's destination rather than a fixed staging
	 * buffer, so full RESULTS_BUFFER values survive in a 2N+1 destination. */
	max_input = ((size_t) max_size - 1) / 2;
	input_len = strlen(input);
	if (input_len > max_input) {
		input_len = max_input;
	}

	mysql_real_escape_string(mysql, output, input, (unsigned long) input_len);
}

void db_free_result(MYSQL_RES *result) {
	mysql_free_result(result);
}

/* TRUE or FALSE, or -1 when the probe itself failed. */
int db_column_exists(MYSQL *mysql, int type, const char *table, const char *column) {
	char query_frag[BUFSIZE] = {0};
	MYSQL_RES *result;
	int exists;

	/* save a fragment just in case */
	snprintf(query_frag, sizeof(query_frag), "SHOW COLUMNS FROM `%s` LIKE '%s'", table, column);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: db_column_exists('%s','%s'): %s", table, column, query_frag));

	result = db_query(mysql, type, query_frag);
	if (result == NULL) return -1;
	if (mysql_num_rows(result)) {
		exists = TRUE;
	} else {
		exists = FALSE;
	}

	db_free_result(result);
	return exists;
}
