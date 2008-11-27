/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2008 The Cacti Group                                 |
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

/*! \fn int db_insert(MYSQL *mysql, const char *query)
 *  \brief inserts a row or rows in a database table.
 *  \param mysql the database connection object
 *  \param query the database query to execute
 *
 *	Unless the SQL_readonly boolean is set to TRUE, the function will execute
 *	the SQL statement specified in the query variable.
 *
 *  \return TRUE if successful, or FALSE if not.
 *
 */
int db_insert(MYSQL *mysql, const char *query) {
	int    error;
	int    error_count = 0;
	char   query_frag[BUFSIZE];

	/* save a fragment just in case */
	snprintf(query_frag, BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:'%s'", query_frag));

	while(1) {
		if (set.SQL_readonly == FALSE) {
			if (mysql_query(mysql, query)) {
				error = mysql_errno(mysql);

				if ((error == 1213) || (error == 1205)) {
					usleep(50000);
					error_count++;

					if (error_count > 30) {
						SPINE_LOG(("ERROR: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'\n", query_frag));
						return FALSE;
					}

					continue;
				}else{
					SPINE_LOG(("ERROR: SQL Failed! Error:'%i', Message:'%s', SQL Fragment:'%s'\n", error, mysql_error(mysql), query_frag));
					return FALSE;
				}
			}else{
				return TRUE;
			}
		}else{
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
MYSQL_RES *db_query(MYSQL *mysql, const char *query) {
	MYSQL_RES  *mysql_res = 0;

	int    error       = 0;
	int    error_count = 0;

	char   query_frag[BUFSIZE];

	/* save a fragment just in case */
	snprintf(query_frag, BUFSIZE, "%s", query);

	/* show the sql query */
	SPINE_LOG_DEVDBG(("DEVDBG: SQL:'%s'", query_frag));

	while (1) {
		if (mysql_query(mysql, query)) {
			error = mysql_errno(mysql);

			if ((error == 1213) || (error == 1205)) {
				#ifndef SOLAR_THREAD
				usleep(50000);
				#endif
				error_count++;

				if (error_count > 30) {
					die("FATAL: Too many Lock/Deadlock errors occurred!, SQL Fragment:'%s'\n", query_frag);
				}

				continue;
			}else{
				die("FATAL: MySQL Error:'%i', Message:'%s'", error, mysql_error(mysql));
			}
		}else{
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
void db_connect(const char *database, MYSQL *mysql) {
	int    tries;
	int    timeout;
	int    options_error;
	int    success;
	char   *hostname;
	char   *socket = NULL;
	struct stat socket_stat;

	if ((hostname = strdup(set.dbhost)) == NULL) {
		die("FATAL: malloc(): strdup() failed");
	}

	/* see if the hostname variable is a file reference.  If so,
	 * and if it is a socket file, setup mysql to use it.
	 */
	if (stat(hostname, &socket_stat) == 0) {
		if (socket_stat.st_mode & S_IFSOCK) {
			socket = strdup (set.dbhost);
			hostname = NULL;
		}
	}else if ((socket = strstr(hostname,":"))) {
		*socket++ = 0x0;
	}

	/* initialalize variables */
	tries   = 5;
	success = FALSE;
	timeout = 5;

	mysql_init(mysql);
	if (mysql == NULL) {
		die("FATAL: MySQL unable to allocate memory and therefore can not connect");
	}

	options_error = mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (char *)&timeout);
	if (options_error < 0) {
		die("FATAL: MySQL options unable to set timeout value");
	}

	while (tries > 0) {
		tries--;

		if (!mysql_real_connect(mysql, hostname, set.dbuser, set.dbpass, database, set.dbport, socket, 0)) {
			if ((mysql_errno(mysql) != 1049) && (mysql_errno(mysql) != 2005) && (mysql_errno(mysql) != 1045)) {
				printf("MYSQL: Connection Failed: Error:'%u', Message:'%s'\n", mysql_errno(mysql), mysql_error(mysql));

				success = FALSE;

				#ifndef SOLAR_THREAD
				usleep(2000);
				#endif
			}else{
				tries   = 0;
				success = FALSE;
			}
		}else{
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
	mysql_close(mysql);
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
	}else{
		return 0;
	}
}
