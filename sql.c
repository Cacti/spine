/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2019 The Cacti Group                                 |
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
	snprintf(query_frag, LRG_BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));

	while(1) {
		if (set.SQL_readonly == FALSE) {
			if (mysql_query(mysql, query)) {
				error = mysql_errno(mysql);

				if (error == 2013 && errno == EINTR) {
					usleep(50000);
					continue;
				}

				if ((error == 1213) || (error == 1205)) {
					usleep(50000);
					error_count++;

					if (error_count > 30) {
						SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'", query_frag));
						return FALSE;
					}

					continue;
				} else if (error == 2006 && errno == EINTR) {
					db_disconnect(mysql);
					usleep(50000);
					db_connect(type, mysql);
					error_count++;

					if (error_count > 30) {
						die("FATAL: Too many Reconnect Attempts!\n");
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

/*! \fn MYSQL_RES *db_query(MYSQL *mysql, const char *query)
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
	snprintf(query_frag, LRG_BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:%s", query_frag));

	while (1) {
		if (mysql_query(mysql, query)) {
			error = mysql_errno(mysql);

			if (error == 2013 && errno == EINTR) {
				usleep(50000);
				continue;
			}

			if ((error == 1213) || (error == 1205)) {
				#ifndef SOLAR_THREAD
				usleep(50000);
				#endif
				error_count++;

				if (error_count > 30) {
					die("FATAL: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'\n", query_frag);
				}

				continue;
			} else if (error == 2006 && errno == EINTR) {
				db_disconnect(mysql);
				usleep(50000);
				db_connect(type, mysql);
				error_count++;

				if (error_count > 30) {
					die("FATAL: Too many Reconnect Attempts!\n");
				}

				continue;
			} else {
				die("FATAL: MySQL Error:'%i', Message:'%s'", error, mysql_error(mysql));
			}
		} else {
			mysql_res = mysql_store_result(mysql);

			break;
		}
	}

	return mysql_res;
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
	int    tries;
	int    timeout;
	int    rtimeout;
	int    wtimeout;
	int    options_error;
	int    success;
	int    error;
	MYSQL  *connect_error;
	char   *hostname;
	char   *socket = NULL;
	struct stat socket_stat;

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
	tries   = 10;
	success = FALSE;
	timeout = 5;
	rtimeout = 10;
	wtimeout = 20;
	my_bool reconnect = 1;

	mysql_init(mysql);

	if (mysql == NULL) {
		die("FATAL: MySQL unable to allocate memory and therefore can not connect");
	}

	MYSQL_SET_OPTION(MYSQL_OPT_READ_TIMEOUT, (char *)&rtimeout, "read timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_WRITE_TIMEOUT, (char *)&wtimeout, "write timeout");
	MYSQL_SET_OPTION(MYSQL_OPT_CONNECT_TIMEOUT, (char *)&timeout, "general timeout");

	#ifdef MYSQL_OPT_RECONNECT
	MYSQL_SET_OPTION(MYSQL_OPT_RECONNECT, &reconnect, "reconnect");
	#endif

	#ifdef MYSQL_OPT_RETRY_COUNT
	MYSQL_SET_OPTION(MYSQL_OPT_RETRY_COUNT, &tries, "retry count");
	#endif

	/* set SSL options if available */
	#ifdef MYSQL_OPT_SSL_KEY
	char *ssl_key;
	char *ssl_ca;
	char *ssl_cert;

	if (set.poller_id > 1 && type == REMOTE) {
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
			db_disconnect(mysql);

			if (error == 2013 && errno == EINTR) {
				usleep(50000);
				tries++;
				success = FALSE;
				continue;
			}

			if (error != 1049 && error != 2005 && error != 1045) {
				printf("MYSQL: Connection Failed: Error:'%u', Message:'%s'\n", mysql_errno(mysql), mysql_error(mysql));

				success = FALSE;

				#ifndef SOLAR_THREAD
				usleep(2000);
				#endif
			} else {
				tries   = 0;
				success = FALSE;
			}
		} else {
			tries   = 0;
			success = TRUE;
		}
	}

	free(hostname);

	if (!success){
		die("FATAL: Connection Failed, Error:'%i', Message:'%s'", mysql_errno(mysql), mysql_error(mysql));
	}
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

	char input_trimmed[BUFSIZE];
	int  input_size;

	input_size = strlen(input);

	if (input_size > max_size) {
		strncpy(input_trimmed, input, max_size - 10);
		input_trimmed[max_size-10] = 0;
	} else {
		strncpy(input_trimmed, input, input_size);
		input_trimmed[input_size] = 0;
	}

	mysql_real_escape_string(mysql, output, input_trimmed, strlen(input_trimmed));
}

void db_free_result(MYSQL_RES *result) {
	mysql_free_result(result);
}
