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
#include "db_session.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netdb.h>
#endif

static int spine_hostname_is_numeric(const char *hostname) {
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int rc;

	if (hostname == NULL || *hostname == '\0') {
		return FALSE;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;

	rc = getaddrinfo(hostname, NULL, &hints, &res);
	if (rc == 0) {
		freeaddrinfo(res);
		return TRUE;
	}
	return FALSE;
}

static int spine_resolve_connect_host(const char *hostname, char *resolved, size_t resolved_len) {
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	int rc;

	if (hostname == NULL || resolved == NULL || resolved_len == 0) {
		return -1;
	}

	if (*hostname == '\0' || strcmp(hostname, "localhost") == 0 || spine_hostname_is_numeric(hostname)) {
		snprintf(resolved, resolved_len, "%s", hostname);
		return 0;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	rc = getaddrinfo(hostname, NULL, &hints, &res);
	if (rc != 0 || res == NULL) {
		if (res != NULL) {
			freeaddrinfo(res);
		}
		return -1;
	}

	rc = getnameinfo(res->ai_addr, (socklen_t)res->ai_addrlen,
		resolved, (socklen_t)resolved_len,
		NULL, 0, NI_NUMERICHOST);
	freeaddrinfo(res);
	if (rc != 0) {
		return -1;
	}

	return 0;
}

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

	/* --dry-run short-circuits every write so operators can validate config
	 * and connectivity without touching poller_output or settings. A single
	 * INFO line per query keeps the log readable while still proving the
	 * would-be SQL was generated correctly. SQL_readonly is the legacy
	 * developer-testing flag and retains its existing semantics. */
	if (set.dry_run) {
		SPINE_LOG(("DRY-RUN: would SQL: %s", query_frag));
		return TRUE;
	}

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
						spine_platform_sleep_us(50000);
						continue;
					}
				}

				if ((error == 1213) || (error == 1205)) {
					spine_platform_sleep_us(50000);
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

int db_reconnect(MYSQL *mysql, int type, int error, const char *function) {
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

		spine_platform_sleep_s(1);

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
					spine_platform_sleep_us(50000);
					continue;
				}
			}

			if (error == 1213 || error == 1205) {
				spine_platform_sleep_us(50000);
				error_count++;

				if (error_count > 30) {
					SPINE_LOG(("FATAL: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
					SPINE_LOG(("INFO: Daemon exit triggered by non-retryable SQL error; consider filing issue"));
					exit(1);
				}

				continue;
			} else {
				SPINE_LOG(("FATAL: Database Error:'%i', Message:'%s'", error, mysql_error(mysql)));
				SPINE_LOG(("ERROR: The Query Was:'%s'", query));
				SPINE_LOG(("INFO: Daemon exit triggered by non-retryable SQL error; consider filing issue"));
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
	const char *connect_host = NULL;
	char    *hostname = NULL;
	char    resolved_hostname[BUFSIZE];
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
					free(hostname);
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
				free(hostname);
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
	connect_host = hostname;
	resolved_hostname[0] = '\0';

	if (hostname != NULL && socket == NULL) {
		if (spine_resolve_connect_host(hostname, resolved_hostname, sizeof(resolved_hostname)) == 0) {
			connect_host = resolved_hostname;
		}
	}

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

	/* MYSQL_OPT_SSL_VERIFY_SERVER_CERT expects a pointer to the connector's
	 * boolean type. MariaDB's C connector and MySQL <8.0 typedef my_bool to
	 * char; MySQL 8.0+ removed my_bool and uses plain bool. Pick the matching
	 * type so we do not pass a 4-byte int into an API that reads 1 byte. */
	#if defined(MARIADB_BASE_VERSION) || defined(MARIADB_VERSION_ID)
	#  define SPINE_SSL_VERIFY_T my_bool
	#elif defined(MYSQL_VERSION_ID) && MYSQL_VERSION_ID >= 80000
	#  define SPINE_SSL_VERIFY_T bool
	#else
	#  define SPINE_SSL_VERIFY_T my_bool
	#endif

	/* set SSL options if available */
	#ifdef HAS_MYSQL_OPT_SSL_KEY
	/* if the users has explicitly said to disable SSL, do that now */
	#ifdef HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	if (type == LOCAL) {
		if (set.db_ssl == 0) {
			SPINE_SSL_VERIFY_T ssl_enforce = 0;
			MYSQL_SET_OPTION(MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_enforce, "ssl disable");
		}
	} else {
		if (set.rdb_ssl == 0) {
			SPINE_SSL_VERIFY_T ssl_enforce = 0;
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

	/* When the operator opts into SSL, require the server identity to verify.
	 * MYSQL_OPT_SSL_MODE=SSL_MODE_VERIFY_IDENTITY is the modern path; older
	 * connectors only expose MYSQL_OPT_SSL_VERIFY_SERVER_CERT which is the
	 * closest equivalent. */
	if ((type == LOCAL && set.db_ssl) || (type == REMOTE && set.rdb_ssl)) {
		#ifdef MYSQL_OPT_SSL_MODE
		unsigned int ssl_mode = SSL_MODE_VERIFY_IDENTITY;
		MYSQL_SET_OPTION(MYSQL_OPT_SSL_MODE, &ssl_mode, "ssl mode");
		#endif
		#ifdef HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
		{
			SPINE_SSL_VERIFY_T ssl_verify = 1;
			MYSQL_SET_OPTION(MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_verify, "ssl verify");
		}
		#endif
	}

	#endif

	while (tries > 0) {
		tries--;

		if (set.poller_id > 1) {
			if (type == LOCAL) {
				connect_error = mysql_real_connect(mysql, connect_host, set.db_user, set.db_pass, set.db_db, set.db_port, socket, 0);
			} else {
				connect_error = mysql_real_connect(mysql, connect_host, set.rdb_user, set.rdb_pass, set.rdb_db, set.rdb_port, socket, 0);
			}
		} else {
			connect_error = mysql_real_connect(mysql, connect_host, set.db_user, set.db_pass, set.db_db, set.db_port, socket, 0);
		}

		if (!connect_error) {
			error = mysql_errno(mysql);

			if ((error == 2002 || error == 2003 || error == 2006 || error == 2013) && errno == EINTR) {
				spine_platform_sleep_us(5000);
				tries++;
				success = FALSE;
			} else if (error == 2002) {
				printf("Database: Connection Failed: Attempt:'%d', Error:'%u', Message:'%s'\n", attempts, mysql_errno(mysql), mysql_error(mysql));
				spine_platform_sleep_s(1);
				success = FALSE;
			} else if (error != 1049 && error != 2005 && error != 1045) {
				printf("Database: Connection Failed: Error:'%d', Message:'%s'\n", error, mysql_error(mysql));
				success = FALSE;
				spine_platform_sleep_us(50000);
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

			spine_db_session_apply_sql_mode(&db_pool_local[id].mysql, LOCAL);

			db_pool_local[id].free = TRUE;
			db_pool_local[id].id   = id;
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection Pool of %i threads.", set.threads));

		for(id = 0; id < set.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection %i.", id));

			db_connect(type, &db_pool_remote[id].mysql);

			spine_db_session_apply_sql_mode(&db_pool_remote[id].mysql, LOCAL);

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
 *  \brief returns a free mysql connection from the pool, or NULL on exhaustion
 *  \param type the connection type, LOCAL or REMOTE
 *
 *  Contract: may return NULL when the pool is exhausted (all entries marked
 *  busy). Callers MUST check the return value and clean up any previously
 *  acquired connections before returning. The pool is sized to set.threads,
 *  so exhaustion is a bug (more acquirers than threads) and the NULL return
 *  is the signal to bail out of the current poll cycle rather than die.
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
		return snprintf(obuf, BUFSIZE, " AND %s BETWEEN %d AND %d",
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
	size_t in_len;
	int    trim_limit;

	if (input == NULL) return;

	/* Zero before snprintf so that a partial write or an undersized trim_limit
	 * still leaves a NUL-terminated buffer for strlen() and mysql_real_escape_string. */
	memset(input_trimmed, 0, sizeof(input_trimmed));

	in_len     = strlen(input);
	/* Clamp to the actual buffer size so gcc -Wformat-truncation can prove
	 * the snprintf destination cannot overflow regardless of max_size. */
	trim_limit = (max_size < (int)(sizeof(input_trimmed) - 1))
	             ? max_size
	             : (int)(sizeof(input_trimmed) - 1);

	/* Guard against snprintf size values that cannot preserve any input byte.
	 * The (trim_limit / 2) - 1 path writes only a NUL for trim_limit in {4,5};
	 * require >= 6 so at least one input byte plus NUL survives truncation. */
	if (trim_limit < 6) {
		output[0] = '\0';
		return;
	}

	/* Compare against max_size in size_t space: the old (strlen * 2) + 1 math
	 * overflowed int for inputs near INT_MAX/2. Checking in_len against
	 * (max_size / 2) - 1 is equivalent and overflow-free. */
	if (max_size > 0 && in_len > (size_t)((max_size / 2) - 1)) {
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

	result = db_query(mysql, type, query_frag);
	if (mysql_num_rows(result)) {
		exists = TRUE;
	} else {
		exists = FALSE;
	}

	db_free_result(result);
	return exists;
}
