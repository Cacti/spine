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

#include "common.h"
#include "spine.h"

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
static void retry_disconnected_query(MYSQL *mysql, int type, int error, const char *function, int *error_count) {
	if (errno == EINTR) {
		spine_sleep_usec(50000);
		return;
	}
	db_reconnect(mysql, type, error, function);
	if (++*error_count > 30) die("FATAL: Too many Reconnect Attempts!");
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
			retry_disconnected_query(mysql, type, error, "db_insert", &error_count);
			continue;
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

int db_reconnect(MYSQL *mysql, int type, int error, const char *function) {
	unsigned long  mysql_thread = 0;
	char   query[100];
	int    ping_status;

	mysql_thread = mysql_thread_id(mysql);
	ping_status  = mysql_ping(mysql);

	if (mysql_thread_id(mysql) != mysql_thread) {
		SPINE_LOG(("WARNING: Connection Broken in Function %s with Error %i.  Reconnect via mysql_ping() successful.", function, error));
		snprintf(query, 100, "KILL %lu;", mysql_thread);
		mysql_query(mysql, query);
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_IN_DATE', ''))");
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_AUTO_VALUE_ON_ZERO', ''))");
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'TRADITIONAL', ''))");
		mysql_query(mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_ALL_TABLES', ''))");

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
	db_connect(type, mysql);

	if (mysql_thread_id(mysql) > 0) {
		SPINE_LOG(("WARNING: Explicit reconnect successful in Function %s.", function));
		return TRUE;
	}

	SPINE_LOG(("WARNING: Connection Broken with Error %i.  Reconnect failed.", error));
	return FALSE;
}

/*! \fn MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query)
 *  \brief executes a query and returns a pointer to the result set.
 *  \param mysql the database connection object
 *  \param query the database query to execute
 *
 *	This function will execute the SQL statement specified in the query variable.
 *
 *  \return MYSQL_RES a MySQL result structure
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
			retry_disconnected_query(mysql, type, error, "db_query", &error_count);
			continue;
		}
		if (error == 1213 || error == 1205) {
			spine_sleep_usec(50000);
			if (++error_count > 30) {
				SPINE_LOG(("FATAL: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
				exit(1);
			}
			continue;
		}
		SPINE_LOG(("FATAL: Database Error:'%i', Message:'%s'", error, mysql_error(mysql)));
		SPINE_LOG(("ERROR: The Query Was:'%s'", query));
		exit(1);
	}
	return mysql_store_result(mysql);
}

/*! \fn void db_connect(char *database, MYSQL *mysql)
 *  \brief opens a connection to a MySQL database.
 *  \param database a string pointer to the database name
 *  \param mysql a pointer to a mysql database connection object
 *
 *	This function will attempt to open a connection to a MySQL database and then
 *	return the connection object to the calling function.  If the database connection
 *  fails more than 20 times, the function will fail and Spine will terminate.
 *
 */
void db_address_init(db_address_t *address, const char *value, bool parse_socket) {
	address->storage = strdup(value);
	if (address->storage == NULL) die("ERROR: Fatal malloc error: database address!");
	address->hostname = address->storage;
	address->socket = NULL;
	if (!parse_socket) return;
	struct stat socket_stat;
	if (stat(address->storage, &socket_stat) == 0) {
		if (S_ISSOCK(socket_stat.st_mode)) {
			address->socket = address->storage;
			address->hostname = NULL;
		}
		return;
	}
	address->socket = strchr(address->storage, ':');
	if (address->socket != NULL) *address->socket++ = '\0';
}

void db_address_release(db_address_t *address) {
	free(address->storage);
	address->storage = NULL;
	address->hostname = NULL;
	address->socket = NULL;
}

void db_set_option(MYSQL *mysql, enum mysql_option option, const void *value, const char *description) {
	if (mysql_options(mysql, option, value) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("FATAL: MySQL options unable to set %s option", description);
	}
}

#ifdef HAS_MYSQL_OPT_SSL_KEY
static void db_set_ssl_options(MYSQL *mysql, int type) {
	#ifdef HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	int ssl_enabled = type == LOCAL ? set.database.ssl : set.remote_database.ssl;
	if (ssl_enabled == 0) {
		bool ssl_enforce = false;
		db_set_option(mysql, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_enforce, "ssl disable");
	}
	#endif
	const char *key = type == REMOTE ? set.remote_database.ssl_key : set.database.ssl_key;
	const char *ca = type == REMOTE ? set.remote_database.ssl_ca : set.database.ssl_ca;
	const char *cert = type == REMOTE ? set.remote_database.ssl_cert : set.database.ssl_cert;
	if (key[0] != '\0') db_set_option(mysql, MYSQL_OPT_SSL_KEY, key, "ssl key");
	if (ca[0] != '\0') db_set_option(mysql, MYSQL_OPT_SSL_CA, ca, "ssl ca");
	if (cert[0] != '\0') db_set_option(mysql, MYSQL_OPT_SSL_CERT, cert, "ssl cert");
}
#endif

void db_connect(int type, MYSQL *mysql) {
	int     tries;
	int     attempts;
	int     timeout;
	int     rtimeout;
	int     wtimeout;
	int     success;
	int     error = 0;
	const MYSQL *connect_error;
	db_address_t address;
	static int connections = 0;

	bool local_address = set.poller.poller_id <= 1 || type == LOCAL;
	db_address_init(&address, local_address ? set.database.host : set.remote_database.host, local_address);

	/* initialalize variables */
	tries     = 2;
	success   = FALSE;
	timeout   = 5;
	rtimeout  = 30;
	wtimeout  = 30;
	attempts  = 1;

	if (mysql_init(mysql) == NULL) {
		db_address_release(&address);
		printf("FATAL: Database unable to allocate memory and therefore can not connect\n");
		exit(1);
	}

	db_set_option(mysql, MYSQL_OPT_READ_TIMEOUT, &rtimeout, "read timeout");
	db_set_option(mysql, MYSQL_OPT_WRITE_TIMEOUT, &wtimeout, "write timeout");
	db_set_option(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout, "general timeout");

	#ifdef HAS_MYSQL_OPT_RETRY_COUNT
	db_set_option(mysql, MYSQL_OPT_RETRY_COUNT, &tries, "retry count");
	#endif

	#ifdef HAS_MYSQL_OPT_SSL_KEY
	db_set_ssl_options(mysql, type);
	#endif

	while (tries > 0) {
		tries--;

		if (set.poller.poller_id > 1) {
			if (type == LOCAL) {
				connect_error = mysql_real_connect(mysql, address.hostname, set.database.user, set.database.password, set.database.database, set.database.port, address.socket, 0);
			} else {
				connect_error = mysql_real_connect(mysql, address.hostname, set.remote_database.user, set.remote_database.password, set.remote_database.database, set.remote_database.port, address.socket, 0);
			}
		} else {
			connect_error = mysql_real_connect(mysql, address.hostname, set.database.user, set.database.password, set.database.database, set.database.port, address.socket, 0);
		}

		if (!connect_error) {
			error = mysql_errno(mysql);

			if ((error == 2002 || error == 2003 || error == 2006 || error == 2013) && errno == EINTR) {
				spine_sleep_usec(5000);
				tries++;
				success = FALSE;
			} else if (error == 2002) {
				printf("Database: Connection Failed: Attempt:'%d', Error:'%u', Message:'%s'\n", attempts, mysql_errno(mysql), mysql_error(mysql));
				sleep(1);
				success = FALSE;
			} else if (error != 1049 && error != 2005 && error != 1045) {
				printf("Database: Connection Failed: Error:'%d', Message:'%s'\n", error, mysql_error(mysql));
				success = FALSE;
				spine_sleep_usec(50000);
			} else {
				tries   = 0;
				success = FALSE;
			}
		} else {
			success = TRUE;
			break;
		}

		attempts++;
	}

	db_address_release(&address);



	if (!success){
		printf("FATAL: Connection Failed, Error:'%i', Message:'%s'\n", error, mysql_error(mysql));
		exit(1);
	}

	SPINE_LOG_DEBUG(("DEBUG: Total Connections made %i", connections));

	connections++;
}

/*! \fn void db_disconnect(MYSQL *mysql)
 *  \brief closes connection to MySQL database
 *  \param mysql the database connection object
 *
 */
void db_disconnect(MYSQL *mysql) {
	if (mysql != NULL) {
		mysql_close(mysql);
	}

}

/*! \fn void db_create_connection_pool(int type)
 *  \brief Creates a connection pool for spine
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
void db_create_connection_pool(int type) {
	int id;

	if (type == LOCAL) {
		SPINE_LOG_DEBUG(("DEBUG: Creating Local Connection Pool of %i threads.", set.poller.threads));

		for(id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Creating Local Connection %i.", id));

			db_connect(type, &db_pool_local[id].mysql);

			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_IN_DATE', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_AUTO_VALUE_ON_ZERO', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'TRADITIONAL', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_ALL_TABLES', ''))");
			db_insert(&db_pool_local[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_TRANS_TABLES', ''))");

			db_pool_local[id].free = TRUE;
			db_pool_local[id].id   = id;
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection Pool of %i threads.", set.poller.threads));

		for(id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection %i.", id));

			db_connect(type, &db_pool_remote[id].mysql);

			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_IN_DATE', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_AUTO_VALUE_ON_ZERO', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'TRADITIONAL', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_ALL_TABLES', ''))");
			db_insert(&db_pool_remote[id].mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'STRICT_TRANS_TABLES', ''))");

			db_pool_remote[id].free = TRUE;
			db_pool_remote[id].id   = id;
		}
	}
}

/*! \fn void db_close_connection_pool(int type)
 *  \brief Closes a connection pool for spine
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
void db_close_connection_pool(int type) {
	int id;

	if (type == LOCAL) {
		for(id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Local Connection Pool ID %i", id));
			db_disconnect(&db_pool_local[id].mysql);
		}

		free(db_pool_local);
	} else {
		for(id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Remote Connection Pool ID %i", id));
			db_disconnect(&db_pool_remote[id].mysql);
		}

		free(db_pool_remote);
	}
}

/*! \fn pool_t db_get_connection(int type)
 *  \brief returns a free mysql connection from the pool
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
pool_t *db_get_connection(int type) {
	int id;

	thread_mutex_lock(LOCK_POOL);

	if (type == LOCAL) {
		SPINE_LOG_DEBUG(("DEBUG: Traversing Local Connection Pool for free connection."));
		for (id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Checking Local Pool ID %i.", id));
			if (db_pool_local[id].free == TRUE) {
				SPINE_LOG_DEBUG(("DEBUG: Allocating Local Pool ID %i.", id));
				db_pool_local[id].free = FALSE;
				thread_mutex_unlock(LOCK_POOL);
				return &db_pool_local[id];
			}
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Traversing Remote Connection Pool for free connection."));
		for (id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Checking Remote Pool ID %i.", id));
			if (db_pool_remote[id].free == TRUE) {
				SPINE_LOG_DEBUG(("DEBUG: Allocating Remote Pool ID %i.", id));
				db_pool_remote[id].free = FALSE;
				thread_mutex_unlock(LOCK_POOL);
				return &db_pool_remote[id];
			}
		}
	}

	SPINE_LOG(("FATAL: Connection Pool Fatal Error."));

	thread_mutex_unlock(LOCK_POOL);

	return NULL;
}

/*! \fn voi db_release_connection(int id)
 *  \brief marks a database connection as free
 *  \param id the connection id
 *
 */
void db_release_connection(int type, int id) {
	thread_mutex_lock(LOCK_POOL);

	if (type == LOCAL) {
		SPINE_LOG_DEBUG(("DEBUG: Freeing Local Pool ID %i", id));
		db_pool_local[id].free = TRUE;
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Freeing Remote Pool ID %i", id));
		db_pool_remote[id].free = TRUE;
	}

	thread_mutex_unlock(LOCK_POOL);
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

int db_column_exists(MYSQL *mysql, int type, const char *table, const char *column) {
	char       query_frag[BUFSIZE];
   MYSQL_RES *result;
	int        exists;

	/* save a fragment just in case */
	memset(query_frag, 0, BUFSIZE);
	snprintf(query_frag, BUFSIZE, "SHOW COLUMNS FROM `%s` LIKE '%s'", table, column);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: db_column_exists('%s','%s'): %s", table, column, query_frag));

	result = db_query(mysql, type, query_frag);
	if (mysql_num_rows(result)) {
		exists = TRUE;
	} else {
		exists = FALSE;
	}

	db_free_result(result);
	return exists;
}
