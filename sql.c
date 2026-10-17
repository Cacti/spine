/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2024 The Cacti Group                                 |
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

#include "common.h"
#include "spine.h"

static const char *sql_skip_space(const char *cursor) {
	while (*cursor != '\0' && isspace((unsigned char) *cursor)) {
		cursor++;
	}

	return cursor;
}

static int sql_word_is(const char *cursor, const char *word) {
	size_t length = strlen(word);

	return strncasecmp(cursor, word, length) == 0 &&
		!(isalnum((unsigned char) cursor[length]) || cursor[length] == '_');
}

/* Names the table a statement targets: the identifier after INTO, UPDATE,
 * DELETE FROM or the first FROM outside quotes. Only identifier characters
 * are ever returned, never literals. */
static const char *sql_target_table(const char *cursor) {
	const char *begin = cursor;
	char quote = '\0';

	if (sql_word_is(cursor, "INSERT") || sql_word_is(cursor, "REPLACE")) {
		cursor = sql_skip_space(cursor + (sql_word_is(cursor, "INSERT") ? 6 : 7));
		if (sql_word_is(cursor, "IGNORE")) {
			cursor = sql_skip_space(cursor + 6);
		}
		return sql_word_is(cursor, "INTO") ? sql_skip_space(cursor + 4) : NULL;
	}

	if (sql_word_is(cursor, "UPDATE")) {
		cursor = sql_skip_space(cursor + 6);
		if (sql_word_is(cursor, "LOW_PRIORITY")) {
			cursor = sql_skip_space(cursor + 12);
		}
		if (sql_word_is(cursor, "IGNORE")) {
			cursor = sql_skip_space(cursor + 6);
		}
		return cursor;
	}

	for (; *cursor != '\0'; cursor++) {
		if (quote != '\0') {
			if (*cursor == quote) {
				quote = '\0';
			}
		} else if (*cursor == '\'' || *cursor == '"') {
			quote = *cursor;
		} else if (cursor != begin && isspace((unsigned char) cursor[-1]) && sql_word_is(cursor, "FROM")) {
			return sql_skip_space(cursor + 4);
		}
	}

	return NULL;
}

/* A fixed description of a statement for the log: its verb and target table.
 * SQL text and the server's message can carry credentials, including INSERTs
 * that cannot be safely redacted by looking for assignment keys, so neither is
 * ever logged. */
static void sql_statement_label(const char *query, char *label, size_t capacity) {
	static const char *const verbs[] = {"SELECT", "INSERT", "REPLACE", "UPDATE", "DELETE",
		"SET", "KILL", "SHOW", "CREATE", "DROP", "ALTER", "TRUNCATE"};
	const char *cursor = sql_skip_space(query);
	const char *table;
	size_t index;
	size_t used;

	snprintf(label, capacity, "SQL");

	for (index = 0; index < sizeof(verbs) / sizeof(verbs[0]); index++) {
		if (sql_word_is(cursor, verbs[index])) {
			break;
		}
	}

	if (index == sizeof(verbs) / sizeof(verbs[0])) {
		return;
	}

	snprintf(label, capacity, "%s", verbs[index]);
	table = sql_target_table(cursor);

	if (table == NULL) {
		return;
	}

	used = strlen(label);
	if (used + 2 < capacity) {
		label[used++] = ' ';
	}

	while (used + 1 < capacity && (isalnum((unsigned char) *table) || *table == '_' || *table == '$' || *table == '`' || *table == '.')) {
		label[used++] = *table++;
	}

	label[used] = '\0';
}

static void log_sql_statement(const char *query) {
	char label[SMALL_BUFSIZE];

	sql_statement_label(query, label, sizeof(label));
	SPINE_LOG_DEVDBG(("DEVDBG: SQL statement %s (%zu bytes)", label, strlen(query)));
}

/* MariaDB can advertise a MySQL compatibility prefix. Test the vendor first. */
bool db_row_alias(MYSQL *destination) {
	const char *server = mysql_get_server_info(destination);
	return server != NULL && strstr(server, "MariaDB") == NULL &&
		mysql_get_server_version(destination) >= 80019;
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

	/* show the sql query */
	log_sql_statement(query);

	while(1) {
		if (set.SQL_readonly == FALSE) {
			if (mysql_query(mysql, query)) {
				error = mysql_errno(mysql);

				if (error == 2013 || error == 2006) {
					if (++error_count > 30) {
						die("FATAL: Too many Reconnect Attempts!");
					}
					if (errno != EINTR) {
						db_reconnect(mysql, type, error, "db_insert");


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
						SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!"));
						return FALSE;
					}

					continue;
				} else {
					{
						char label[SMALL_BUFSIZE];

						sql_statement_label(query, label, sizeof(label));
						SPINE_LOG(("ERROR: SQL Failed! Error:'%i', State:'%s', Statement:'%s'", error, mysql_sqlstate(mysql), label));
					}
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

/* The legacy SSL flag must not silently fall back to plaintext. A Unix socket
 * never leaves the host and the client library does not negotiate TLS on it,
 * so requiring TLS there would fail every connection. */
static int db_tls_required(int type, const char *hostname) {
	if (!(type == REMOTE ? set.rdb_ssl : set.db_ssl)) return FALSE;
	return !(hostname == NULL || strcmp(hostname, "localhost") == 0);
}

/* Whether a connection of this type is expected to be encrypted: TLS was
 * requested and the host is neither a Unix socket file nor localhost. */
static int db_tls_expected(int type) {
	const char *host = (set.poller_id > 1 && type == REMOTE) ? set.rdb_host : set.db_host;
	char name[BUFSIZE];
	char *colon;
	struct stat socket_stat;

	if (stat(host, &socket_stat) == 0 && (socket_stat.st_mode & S_IFSOCK)) {
		return FALSE;
	}

	snprintf(name, sizeof(name), "%s", host);
	colon = strchr(name, ':');
	if (colon != NULL) {
		*colon = '\0';
	}

	return db_tls_required(type, name);
}

int db_reconnect(MYSQL *mysql, int type, int error, char *function) {
	unsigned long  mysql_thread = 0;
	char   query[100];

	mysql_thread = mysql_thread_id(mysql);
	mysql_ping(mysql);

	if (mysql_thread_id(mysql) != mysql_thread) {
		/* The client library reconnects with the handle's stored options; make
		 * sure the required encryption survived that. */
		if (db_tls_expected(type) && mysql_get_ssl_cipher(mysql) == NULL) {
			mysql_close(mysql);
			die("ERROR: Database reconnect completed without the required TLS");
		}

		SPINE_LOG(("WARNING: Connection Broken in Function %s with Error %i.  Reconnect successful.", function, error));
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
	} else {
		SPINE_LOG(("WARNING: Connection Broken with Error %i.  Reconnect failed.", error));
		return FALSE;
	}
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


	/* show the sql query */
	log_sql_statement(query);

	while (1) {
		if (mysql_query(mysql, query)) {
			error = mysql_errno(mysql);

			if (error == 2013 || error == 2006) {
				if (++error_count > 30) {
					die("FATAL: Too many Reconnect Attempts!");
				}
				if (errno != EINTR) {
					db_reconnect(mysql, type, error, "db_query");

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
					SPINE_LOG(("FATAL: Too many Lock/Deadlock errors occurred!"));
					exit(1);
				}

				continue;
			} else {
				{
					char label[SMALL_BUFSIZE];

					sql_statement_label(query, label, sizeof(label));
					SPINE_LOG(("FATAL: Database Error:'%i', State:'%s', Statement:'%s'", error, mysql_sqlstate(mysql), label));
				}
				log_sql_statement(query);
				exit(1);
			}
		} else {
			mysql_res = mysql_store_result(mysql);

			break;
		}
	}

	return mysql_res;
}

/* REQUIRED encrypts the session but does not authenticate the server. When a
 * CA is configured the MySQL client can also verify the certificate chain. */
static void db_require_tls(MYSQL *mysql, int type, const char *hostname, const char *ssl_ca) {
	if (!db_tls_required(type, hostname)) return;
#ifdef HAS_MYSQL_OPT_SSL_MODE
	enum mysql_ssl_mode policy = (ssl_ca != NULL && ssl_ca[0] != '\0') ? SSL_MODE_VERIFY_CA : SSL_MODE_REQUIRED;
	if (mysql_options(mysql, MYSQL_OPT_SSL_MODE, &policy) != 0) {
		die("ERROR: Unable to require database TLS");
	}
#elif defined(HAS_MYSQL_OPT_SSL_ENFORCE)
	unsigned char required = 1;
	(void)ssl_ca;
	if (mysql_options(mysql, MYSQL_OPT_SSL_ENFORCE, &required) != 0) {
		die("ERROR: Unable to require database TLS");
	}
#else
	(void)mysql;
	(void)ssl_ca;
	die("ERROR: Database client cannot enforce required TLS");
#endif
}

/* A failed handshake can leave the handle's options consumed, so every
 * attempt starts from a freshly initialized handle with the complete policy. */
static void db_prepare_handle(MYSQL *mysql, int type, const char *hostname,
	const char *ssl_key, const char *ssl_ca, const char *ssl_cert) {
	int  options_error;
	int  tries     = 2;
	int  timeout   = 5;
	int  rtimeout  = 30;
	int  wtimeout  = 30;
	bool reconnect = TRUE;

	mysql_init(mysql);

	MYSQL_SET_OPTION(MYSQL_OPT_READ_TIMEOUT, (int *)&rtimeout, "read timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_WRITE_TIMEOUT, (int *)&wtimeout, "write timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_CONNECT_TIMEOUT, (int *)&timeout, "general timeout");

	#if defined(MARIADB_BASE_VERSION) || (MYSQL_VERSION_ID < 80034 && MYSQL_VERSION_ID >= 50013)
		MYSQL_SET_OPTION(MYSQL_OPT_RECONNECT, &reconnect, "reconnect");
	#endif

	#ifdef HAS_MYSQL_OPT_RETRY_COUNT
	MYSQL_SET_OPTION(MYSQL_OPT_RETRY_COUNT, &tries, "retry count");
	#endif

	db_require_tls(mysql, type, hostname, ssl_ca);

	/* set SSL options if available */
	#ifdef HAS_MYSQL_OPT_SSL_KEY

	/* if the users has explicitly said to disable SSL, do that now */
	#ifdef HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	if ((type == LOCAL ? set.db_ssl : set.rdb_ssl) == 0) {
		bool ssl_enforce = 0;
		MYSQL_SET_OPTION(MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_enforce, "ssl disable");
	}
	#endif

	if (strlen(ssl_key)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_KEY, ssl_key,  "ssl key");
	if (strlen(ssl_ca)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_CA, ssl_ca,   "ssl ca");
	if (strlen(ssl_cert)) 	MYSQL_SET_OPTION(MYSQL_OPT_SSL_CERT, ssl_cert, "ssl cert");

	#else
	(void)ssl_key;
	(void)ssl_ca;
	(void)ssl_cert;
	#endif

	(void)tries;
	(void)reconnect;
}

/*! \fn void db_connect(char *database, MYSQL *mysql)
 *  \brief opens a connection to a MySQL databse.
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
	int     success;
	int     error = 0;
	MYSQL   *connect_error;
	char    *hostname = NULL;
	char    *socket = NULL;
	char    *ssl_key  = NULL;
	char    *ssl_ca   = NULL;
	char    *ssl_cert = NULL;
	char    last_error[BUFSIZE];
	struct  stat socket_stat;
	static int connections = 0;

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
	attempts  = 1;
	last_error[0] = '\0';

	if (type == REMOTE) {
		STRDUP_OR_DIE(ssl_key, set.rdb_ssl_key, "rdb_ssl_key");
		STRDUP_OR_DIE(ssl_ca, set.rdb_ssl_ca, "rdb_ssl_ca");
		STRDUP_OR_DIE(ssl_cert, set.rdb_ssl_cert, "rdb_ssl_cert");
	} else {
		STRDUP_OR_DIE(ssl_key, set.db_ssl_key, "db_ssl_key");
		STRDUP_OR_DIE(ssl_ca, set.db_ssl_ca, "db_ssl_ca");
		STRDUP_OR_DIE(ssl_cert, set.db_ssl_cert, "db_ssl_cert");
	}

	while (tries > 0) {
		tries--;

		db_prepare_handle(mysql, type, hostname, ssl_key, ssl_ca, ssl_cert);

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
			snprintf(last_error, sizeof(last_error), "%s", mysql_error(mysql));

			if ((error == 2002 || error == 2003 || error == 2006 || error == 2013) && errno == EINTR) {
				usleep(5000);
				tries++;
				success = FALSE;
			} else if (error == 2002) {
				printf("Database: Connection Failed: Attempt:'%u', Error:'%u', Message:'%s'\n", attempts, error, last_error);
				sleep(1);
				success = FALSE;
			} else if (error == 2026) {
				/* The TLS handshake failed; another attempt cannot succeed
				 * and must not be allowed to fall back to a plain session. */
				printf("Database: Connection Failed: Error:'%u', Message:'%s'\n", error, last_error);
				tries   = 0;
				success = FALSE;
			} else if (error != 1049 && error != 2005 && error != 1045) {
				printf("Database: Connection Failed: Error:'%u', Message:'%s'\n", error, last_error);
				success = FALSE;
				usleep(50000);
			} else {
				tries   = 0;
				success = FALSE;
			}

			/* Another attempt starts from a freshly initialized handle. */
			if (tries > 0) {
				mysql_close(mysql);
			}
		} else {
			tries   = 0;
			if (db_tls_required(type, hostname) && mysql_get_ssl_cipher(mysql) == NULL) {
				mysql_close(mysql);
				die("ERROR: Required database TLS was not negotiated");
			}
			success = TRUE;
			break;
		}

		attempts++;
	}

	if (hostname != NULL) {
		free(hostname);
	}

	free(ssl_key);
	free(ssl_ca);
	free(ssl_cert);

	if (!success){
		printf("FATAL: Connection Failed, Error:'%i', Message:'%s'\n", error, last_error);
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

	mysql = NULL;
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
 *  \param obuf the sql select statment to have the host range appended
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
 *  \brief Escapse a text string to make it safe for mysql insert/updates
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
	if (input == NULL) return;

	char input_trimmed[DBL_BUFSIZE];
	int  max_escaped_input_size = (strlen(input) * 2) + 1;

	if (max_escaped_input_size > max_size) {
		snprintf(input_trimmed, (max_size / 2) - 1, "%s", input);
	} else {
		snprintf(input_trimmed, max_size, "%s", input);
	}

	mysql_real_escape_string(mysql, output, input_trimmed, strlen(input_trimmed));
}

void db_free_result(MYSQL_RES *result) {
	mysql_free_result(result);
}
