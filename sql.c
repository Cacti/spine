/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2006 The Cacti Group                                 |
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
 | cactid: a backend data gatherer for cacti                               |
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
#include "cactid.h"

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
	static int queryid = 0;

	if (set.SQL_readonly) { return TRUE; }
	
	CACTID_LOG_DEBUG(("DEBUG: MySQL Insert ID '%i': '%s'\n", queryid, query));

	thread_mutex_lock(LOCK_MYSQL);
	if (mysql_query(mysql, query)) {
		CACTID_LOG(("ERROR: Problem with MySQL: '%s'\n", mysql_error(mysql)));

		queryid++;
		thread_mutex_unlock(LOCK_MYSQL);
		return FALSE;
	}else{
		CACTID_LOG_DEBUG(("DEBUG: MySQL Insert ID '%i': OK\n", queryid));

		queryid++;
		thread_mutex_unlock(LOCK_MYSQL);
		return TRUE;
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
	MYSQL_RES *mysql_res = 0;
	int return_code;
	int retries;
	int error;
	static int queryid = 0;
	
	CACTID_LOG_DEBUG(("DEBUG: MySQL Query ID '%i': '%s'\n", queryid, query));

	thread_mutex_lock(LOCK_MYSQL);
	retries = 0;
	error = FALSE;
	while (retries < 3) {
	 	return_code = mysql_query(mysql, query);
		if (return_code) {
			CACTID_LOG(("WARNING: MySQL Query Error, retrying query '%s'\n", query));
			error = TRUE;
		}else{
			CACTID_LOG_DEBUG(("DEBUG: MySQL Query ID '%i': OK\n", queryid));

			mysql_res = mysql_store_result(mysql);
			error = FALSE;
			break;
		}
		#ifndef SOLAR_THREAD
		usleep(1000);
		#endif
		retries++;
	}

	queryid++;
	thread_mutex_unlock(LOCK_MYSQL);

	if (error) {
		die("ERROR: Fatal MySQL Query Error, exiting!");
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
 *  fails more than 20 times, the function will fail and Cactid will terminate.
 *
 */
void db_connect(const char *database, MYSQL *mysql) {
	MYSQL *db;
	int tries;
	int options_error;
	int success;
	int timeout;
	char *hostname;
	char *socket;

	if ((hostname = strdup(set.dbhost)) == NULL) {
		die("ERROR: malloc(): strdup() failed");
	}

	if ((socket = strstr(hostname,":"))) {
		*socket++ = 0x0;
	}

	/* initialalize my variables */
	tries = 5;
	success = FALSE;
	timeout = 5;

	CACTID_LOG_DEBUG(("MYSQL: Connecting to MySQL database '%s' on '%s'...\n", database, set.dbhost));

	thread_mutex_lock(LOCK_MYSQL);
	db = mysql_init(mysql);
	if (db == NULL) {
		die("ERROR: MySQL unable to allocate memory and therefore can not connect");
	timeout = 5;
	}

	while (tries > 0){
		tries--;
		if (!mysql_real_connect(mysql, hostname, set.dbuser, set.dbpass, database, set.dbport, socket, 0)) {
			CACTID_LOG_DEBUG(("MYSQL: Connection Failed: %s\n", mysql_error(mysql)));

			success = FALSE;
		}else{
			CACTID_LOG_DEBUG(("MYSQL: Connected to MySQL database '%s' on '%s'...\n", database, set.dbhost));

			tries = 0;
			success = TRUE;
		}
		#ifndef SOLAR_THREAD
		usleep(2000);
		#endif
	}

	free(hostname);

	thread_mutex_unlock(LOCK_MYSQL);

	if (!success){
		die("MYSQL: Connection Failed: %s", mysql_error(mysql));
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
