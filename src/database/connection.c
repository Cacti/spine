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

/* Reports failure instead of exiting: worker threads reconnect through here,
 * and a lost database must fail a device rather than the poller. Startup
 * callers turn FALSE into a process exit. */
int db_connect(int type, MYSQL *mysql) {
	int tries;
	int attempts;
	int timeout;
	int rtimeout;
	int wtimeout;
	int success;
	int error = 0;
	const MYSQL *connect_error;
	db_address_t address;
	static int connections = 0;

	bool local_address = set.poller.poller_id <= 1 || type == LOCAL;
	db_address_init(&address, local_address ? set.database.host : set.remote_database.host, local_address);

	/* initialalize variables */
	tries = 2;
	success = FALSE;
	timeout = 5;
	rtimeout = 30;
	wtimeout = 30;
	attempts = 1;

	if (mysql_init(mysql) == NULL) {
		db_address_release(&address);
		printf("ERROR: Database unable to allocate memory and therefore can not connect\n");
		return FALSE;
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

			/* A stale EINTR in errno used to refund the attempt here and made
			 * the loop unbounded; every failed connect now spends a try. */
			if (error == 2002) {
				printf("Database: Connection Failed: Attempt:'%d', Error:'%u', Message:'%s'\n", attempts, mysql_errno(mysql), mysql_error(mysql));
				sleep(1);
				success = FALSE;
			} else if (error != 1049 && error != 2005 && error != 1045) {
				printf("Database: Connection Failed: Error:'%d', Message:'%s'\n", error, mysql_error(mysql));
				success = FALSE;
				spine_sleep_usec(50000);
			} else {
				tries = 0;
				success = FALSE;
			}
		} else {
			success = TRUE;
			break;
		}

		attempts++;
	}

	db_address_release(&address);



	if (!success) {
		printf("ERROR: Connection Failed, Error:'%i', Message:'%s'\n", error, mysql_error(mysql));
		return FALSE;
	}

	SPINE_LOG_DEBUG(("DEBUG: Total Connections made %i", connections));

	connections++;

	return TRUE;
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
