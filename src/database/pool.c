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

/*! \fn void db_create_connection_pool(int type)
 *  \brief Creates a connection pool for spine
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
void db_create_connection_pool(int type) {
	int id;

	if (type == LOCAL) {
		SPINE_LOG_DEBUG(("DEBUG: Creating Local Connection Pool of %i threads.", set.poller.threads));

		for (id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Creating Local Connection %i.", id));

			if (!db_connect(type, &db_pool_local[id].mysql)) die("FATAL: Unable to create the local connection pool");

			if (!db_set_session_mode(&db_pool_local[id].mysql)) die("FATAL: Unable to configure the local connection pool");

			db_pool_local[id].free = TRUE;
			db_pool_local[id].id = id;
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection Pool of %i threads.", set.poller.threads));

		for (id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Creating Remote Connection %i.", id));

			if (!db_connect(type, &db_pool_remote[id].mysql)) die("FATAL: Unable to create the remote connection pool");

			if (!db_set_session_mode(&db_pool_remote[id].mysql)) die("FATAL: Unable to configure the remote connection pool");

			db_pool_remote[id].free = TRUE;
			db_pool_remote[id].id = id;
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
		for (id = 0; id < set.poller.threads; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Local Connection Pool ID %i", id));
			db_disconnect(&db_pool_local[id].mysql);
		}

		free(db_pool_local);
	} else {
		for (id = 0; id < set.poller.threads; id++) {
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
