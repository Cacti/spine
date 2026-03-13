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
int db_insert(MYSQL *mysql, int type, const char *query) {
	int    error;
	int    error_count = 0;
	char   query_frag[LRG_BUFSIZE];

	/* save a fragment just in case */
	memset(query_frag, 0, LRG_BUFSIZE);
	snprintf(query_frag, LRG_BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));

	while(1) {
		if (set.SQL_readonly == FALSE) {
			if (mysql_query(mysql, query)) {
				error = mysql_errno(mysql);

				if (error == 2013 || error == 2006) {
					if (errno != EINTR) {
						db_reconnect(mysql, type, error, "db_insert");

						error_count++;

						if (error_count > 30) {
							die("FATAL: Too many Reconnect Attempts!");
						}

						continue;
					} else {
						usleep(50000);
						continue;
					}
				}

				if ((error == 1213) || (error == 1205)) {
					usleep(50000);
					error_count++;

					if (error_count > 30) {
						SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
						return FALSE;
					}

					continue;
				} else {
					SPINE_LOG(("ERROR: SQL Failed! Error:'%i', Message:'%s', SQL Fragment:'%s'", error, mysql_error(mysql), query_frag));
					return FALSE;
				}
			} else {
				return TRUE;
			}
		} else {
			return TRUE;
		}
	}
}

int db_reconnect(MYSQL *mysql, int type, int error, char *function) {
	unsigned long  mysql_thread = 0;
	char   query[100];

	mysql_thread = mysql_thread_id(mysql);
	mysql_ping(mysql);

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
	MYSQL_RES  *mysql_res = 0;

	int    error       = 0;
	int    error_count = 0;

	char   query_frag[LRG_BUFSIZE];

	/* save a fragment just in case */
	memset(query_frag, 0, LRG_BUFSIZE);
	snprintf(query_frag, LRG_BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));

	while (1) {
		if (mysql_query(mysql, query)) {
			error = mysql_errno(mysql);

			if (error == 2013 || error == 2006) {
				if (errno != EINTR) {
					db_reconnect(mysql, type, error, "db_query");

					error_count++;

					if (error_count > 30) {
						die("FATAL: Too many Reconnect Attempts!");
					}

					continue;
				} else {
					usleep(50000);
					continue;
				}
			}

			if (error == 1213 || error == 1205) {
				usleep(50000);
				error_count++;

				if (error_count > 30) {
					SPINE_LOG(("FATAL: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
					exit(1);
				}

				continue;
			} else {
				SPINE_LOG(("FATAL: Database Error:'%i', Message:'%s'", error, mysql_error(mysql)));
				SPINE_LOG(("ERROR: The Query Was:'%s'", query));
				exit(1);
			}
		} else {
			mysql_res = mysql_store_result(mysql);

			break;
		}
	}

	return mysql_res;
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
void db_connect(int type, MYSQL *mysql) {
	int     tries;
	int     attempts;
	int     timeout;
	int     rtimeout;
	int     wtimeout;
	int     options_error;
	int     success;
	int     error = 0;
	MYSQL   *connect_error;
	char    *hostname = NULL;
	char    *socket = NULL;
	struct  stat socket_stat;
	static int connections = 0;
	#ifdef HAS_MYSQL_OPT_SSL_KEY
	char    *ssl_key  = NULL;
	char    *ssl_ca   = NULL;
	char    *ssl_cert = NULL;
	#endif

	/* see if the hostname variable is a file reference.  If so,
	 * and if it is a socket file, setup mysql to use it.
	 */
	if (set.poller_id > 1) {
		if (type == LOCAL) {
			STRDUP_OR_DIE(hostname, set.db_host, "db_host")

			if (stat(hostname, &socket_stat) == 0) {
				if (socket_stat.st_mode & S_IFSOCK) {
					socket = strdup (set.db_host);
					hostname = NULL;
				}
			} else if ((socket = strstr(hostname,":"))) {
				*socket++ = 0x0;
			}
		} else {
			STRDUP_OR_DIE(hostname, set.rdb_host, "rdb_host")
		}
	} else {
		STRDUP_OR_DIE(hostname, set.db_host, "db_host")

		if (stat(hostname, &socket_stat) == 0) {
			if (socket_stat.st_mode & S_IFSOCK) {
				socket = strdup (set.db_host);
				hostname = NULL;
			}
		} else if ((socket = strstr(hostname,":"))) {
			*socket++ = 0x0;
		}
	}

	/* initialalize variables */
	tries     = 2;
	success   = FALSE;
	timeout   = 5;
	rtimeout  = 30;
	wtimeout  = 30;
	attempts  = 1;

	if (mysql_init(mysql) == NULL) {
		printf("FATAL: Database unable to allocate memory and therefore can not connect\n");
		exit(1);
	}

	MYSQL_SET_OPTION(MYSQL_OPT_READ_TIMEOUT, (int *)&rtimeout, "read timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_WRITE_TIMEOUT, (int *)&wtimeout, "write timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_CONNECT_TIMEOUT, (int *)&timeout, "general timeout");

	#ifdef HAS_MYSQL_OPT_RETRY_COUNT
	MYSQL_SET_OPTION(MYSQL_OPT_RETRY_COUNT, &tries, "retry count");
	#endif

	/* set SSL options if available */
	#ifdef HAS_MYSQL_OPT_SSL_KEY
	/* if the users has explicitly said to disable SSL, do that now */
	#ifdef HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	if (type == LOCAL) {
		if (set.db_ssl == 0) {
			bool ssl_enforce = 0;
			MYSQL_SET_OPTION(MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_enforce, "ssl disable");
		}
	} else {
		if (set.rdb_ssl == 0) {
			bool ssl_enforce = 0;
			MYSQL_SET_OPTION(MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_enforce, "ssl disable");
		}
	}
	#endif

	if (type == REMOTE) {
		STRDUP_OR_DIE(ssl_key, set.rdb_ssl_key, "rdb_ssl_key");
		STRDUP_OR_DIE(ssl_ca, set.rdb_ssl_ca, "rdb_ssl_ca");
		STRDUP_OR_DIE(ssl_cert, set.rdb_ssl_cert, "rdb_ssl_cert");
	} else {
		STRDUP_OR_DIE(ssl_key, set.db_ssl_key, "db_ssl_key");
		STRDUP_OR_DIE(ssl_ca, set.db_ssl_ca, "db_ssl_ca");
		STRDUP_OR_DIE(ssl_cert, set.db_ssl_cert, "db_ssl_cert");
	}

	if (strlen(ssl_key)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_KEY, ssl_key,  "ssl key");
	if (strlen(ssl_ca)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_CA, ssl_ca,   "ssl ca");
	if (strlen(ssl_cert)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_CERT, ssl_cert, "ssl cert");

	#endif

	while (tries > 0) {
		tries--;

		if (set.poller_id > 1) {
			if (type == LOCAL) {
				connect_error = mysql_real_connect(mysql, hostname, set.db_user, set.db_pass, set.db_db, set.db_port, socket, 0);
			} else {
				connect_error = mysql_real_connect(mysql, hostname, set.rdb_user, set.rdb_pass, set.rdb_db, set.rdb_port, socket, 0);
			}
		} else {
			connect_error = mysql_real_connect(mysql, hostname, set.db_user, set.db_pass, set.db_db, set.db_port, socket, 0);
		}

		if (!connect_error) {
			error = mysql_errno(mysql);

			if ((error == 2002 || error == 2003 || error == 2006 || error == 2013) && errno == EINTR) {
				usleep(5000);
				tries++;
				success = FALSE;
			} else if (error == 2002) {
				printf("Database: Connection Failed: Attempt:'%d', Error:'%u', Message:'%s'\n", attempts, mysql_errno(mysql), mysql_error(mysql));
				sleep(1);
				success = FALSE;
			} else if (error != 1049 && error != 2005 && error != 1045) {
				printf("Database: Connection Failed: Error:'%d', Message:'%s'\n", error, mysql_error(mysql));
				success = FALSE;
				usleep(50000);
			} else {
				tries   = 0;
				success = FALSE;
			}
		} else {
			tries   = 0;
			success = TRUE;
			break;
		}

		attempts++;
	}

	if (hostname != NULL) {
		free(hostname);
	}

    #ifdef HAS_MYSQL_OPT_SSL_KEY
	if (ssl_key != NULL) {
		free(ssl_key);
	}

	if (ssl_ca != NULL) {
		free(ssl_ca);
	}

	if (ssl_cert != NULL) {
		free(ssl_cert);
	}
    #endif

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
		SPINE_LOG_DEBUG(("DEBUG: Creating Local Connection Pool of %i threads.", set.threads));

		for(id = 0; id < set.threads; id++) {
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
		SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection Pool of %i threads.", set.threads));

		for(id = 0; id < set.threads; id++) {
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
		for(id = 0; id < set.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Local Connection Pool ID %i", id));
			db_disconnect(&db_pool_local[id].mysql);
		}

		free(db_pool_local);
	} else {
		for(id = 0; id < set.threads; id++) {
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
		for (id = 0; id < set.threads; id++) {
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
		for (id = 0; id < set.threads; id++) {
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
int append_hostrange(char *obuf, const char *colname) {
	if (HOSTID_DEFINED(set.start_host_id) && HOSTID_DEFINED(set.end_host_id)) {
		return sprintf(obuf, " AND %s BETWEEN %d AND %d",
			colname,
			set.start_host_id,
			set.end_host_id);
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
	char input_trimmed[DBL_BUFSIZE];
	int  max_escaped_input_size;
	int  trim_limit;

	if (output == NULL) return;

	/* ensure the output buffer is initialized to an empty string if input is NULL
	 * to avoid using stale data from previous calls in bulk query buffers */
	if (input == NULL) {
		output[0] = '\0';
		return;
	}

	max_escaped_input_size = (strlen(input) * 2) + 1;
	trim_limit = (max_size < DBL_BUFSIZE) ? max_size : DBL_BUFSIZE;

	if (max_escaped_input_size > max_size) {
		snprintf(input_trimmed, (trim_limit / 2) - 1, "%s", input);
	} else {
		snprintf(input_trimmed, trim_limit, "%s", input);
	}

	mysql_real_escape_string(mysql, output, input_trimmed, strlen(input_trimmed));
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

	result = db_query(mysql, LOCAL, query_frag);
	if (mysql_num_rows(result)) {
		exists = TRUE;
	} else {
		exists = FALSE;
	}

	db_free_result(result);
	return exists;
}

/**
 * sql_buffer_init - Initializes a sql_buffer_t structure.
 * @sb:     The sql_buffer_t structure to initialize.
 * @initial_capacity: Initial allocation size.
 */
int sql_buffer_init(sql_buffer_t *sb, size_t initial_capacity) {
	if (sb == NULL || initial_capacity == 0 || initial_capacity > SQL_MAX_BUFFER_CAPACITY) {
		SPINE_LOG(("ERROR: sql_buffer_init invalid capacity request '%zu' (max '%d')",
			initial_capacity, SQL_MAX_BUFFER_CAPACITY));
		return -1;
	}

	sb->buffer = (char *)malloc(initial_capacity);
	if (sb->buffer == NULL) {
		SPINE_LOG(("ERROR: sql_buffer_init failed to allocate '%zu' bytes", initial_capacity));
		sb->capacity = 0;
		sb->length   = 0;
		return -1;
	}

	sb->capacity  = initial_capacity;
	sb->length    = 0;
	sb->buffer[0] = '\0';

	return 0;
}

/**
 * sql_buffer_append - Appends a formatted string to the SQL buffer.
 * @sb:     The sql_buffer_t structure.
 * @format: The printf-style format string.
 * @...:    Arguments for the format string.
 *
 * Returns 0 on success, -1 on failure.
 */
int sql_buffer_append(sql_buffer_t *sb, const char *format, ...) {
	va_list args;
	va_list args_copy;
	size_t  available;
	size_t  required_capacity;
	size_t  new_capacity;
	char    *new_buffer;
	int     written;

	/* safety: ensure the buffer is actually initialized before attempting to append */
	if (sb == NULL || sb->buffer == NULL || format == NULL) {
		SPINE_LOG(("ERROR: sql_buffer_append called with invalid arguments"));
		return -1;
	}

	if (sb->length >= sb->capacity) {
		SPINE_LOG(("ERROR: sql_buffer_append detected invalid state (length '%zu' >= capacity '%zu')",
			sb->length, sb->capacity));
		return -1;
	}

	available = sb->capacity - sb->length;

	va_start(args, format);
	va_copy(args_copy, args);

	/* Fast path: attempt to write into existing capacity first. */
	written = vsnprintf(sb->buffer + sb->length, available, format, args);
	va_end(args);

	if (written < 0) {
		sb->buffer[sb->length] = '\0';
		SPINE_LOG(("ERROR: sql_buffer_append failed during format operation"));
		va_end(args_copy);
		return -1;
	}

	if ((size_t)written >= available) {
		required_capacity = sb->length + (size_t)written + 1;

		if (required_capacity > SQL_MAX_BUFFER_CAPACITY) {
			sb->buffer[sb->length] = '\0';
			SPINE_LOG(("ERROR: sql_buffer_append exceeded SQL_MAX_BUFFER_CAPACITY '%d' (required '%zu')",
				SQL_MAX_BUFFER_CAPACITY, required_capacity));
			va_end(args_copy);
			return -1;
		}

		new_capacity = sb->capacity;
		while (new_capacity < required_capacity) {
			if (new_capacity >= SQL_MAX_BUFFER_CAPACITY / 2) {
				new_capacity = SQL_MAX_BUFFER_CAPACITY;
				break;
			}

			new_capacity *= 2;
		}

		if (new_capacity < required_capacity) {
			sb->buffer[sb->length] = '\0';
			SPINE_LOG(("ERROR: sql_buffer_append could not reach required capacity '%zu' (max '%d')",
				required_capacity, SQL_MAX_BUFFER_CAPACITY));
			va_end(args_copy);
			return -1;
		}

		new_buffer = (char *)realloc(sb->buffer, new_capacity);
		if (new_buffer == NULL) {
			sb->buffer[sb->length] = '\0';
			SPINE_LOG(("ERROR: sql_buffer_append failed to reallocate buffer to '%zu' bytes", new_capacity));
			va_end(args_copy);
			return -1;
		}

		sb->buffer   = new_buffer;
		sb->capacity = new_capacity;

		/* Slow path: retry formatting once capacity is guaranteed. */
		written = vsnprintf(sb->buffer + sb->length, sb->capacity - sb->length, format, args_copy);
		if (written < 0 || (size_t)written >= (sb->capacity - sb->length)) {
			sb->buffer[sb->length] = '\0';
			SPINE_LOG(("ERROR: sql_buffer_append failed after reallocation"));
			va_end(args_copy);
			return -1;
		}
	}
	va_end(args_copy);

	sb->length += (size_t)written;

	return 0;
}

/**
 * sql_buffer_reset - Resets the SQL buffer pointer to the beginning.
 * @sb: The sql_buffer_t structure.
 */
void sql_buffer_reset(sql_buffer_t *sb) {
	if (sb == NULL || sb->buffer == NULL) {
		return;
	}

	sb->length = 0;
	if (sb->capacity > 0) {
		sb->buffer[0] = '\0';
	}
}

/**
 * sql_buffer_truncate - Truncates the SQL buffer to a previous length.
 * @sb: The sql_buffer_t structure.
 * @length: Target length.
 */
void sql_buffer_truncate(sql_buffer_t *sb, size_t length) {
	if (sb == NULL || sb->buffer == NULL || length > sb->length) {
		return;
	}

	sb->length = length;
	sb->buffer[length] = '\0';
}

/**
 * sql_buffer_free - Releases SQL buffer memory.
 * @sb: The sql_buffer_t structure.
 */
void sql_buffer_free(sql_buffer_t *sb) {
	if (sb == NULL) {
		return;
	}

	if (sb->buffer != NULL) {
		free(sb->buffer);
	}

	sb->buffer   = NULL;
	sb->capacity = 0;
	sb->length   = 0;
}

/**
 * db_fetch_cell_dup - fetches the first row's specified column and duplicates it.
 * @result:       The MYSQL_RES result set to process.
 * @col_index:    The 0-based column index to fetch.
 *
 * This function handles all NULL checks and ensures the result set is freed.
 * It always returns a valid strdup'd string (or empty string) that the caller must free.
 */
char *db_fetch_cell_dup(MYSQL_RES *result, int col_index) {
	char *retval = NULL;
	MYSQL_ROW mysql_row;

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);

			if (mysql_row != NULL && mysql_row[col_index] != NULL) {
				STRDUP_OR_DIE(retval, mysql_row[col_index], "sql.c db_fetch_cell_dup");
			}
		}
		db_free_result(result);
	}

	if (retval == NULL) {
		STRDUP_OR_DIE(retval, "", "sql.c db_fetch_cell_dup fallback");
	}

	return retval;
}

