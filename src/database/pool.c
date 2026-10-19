/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"

/*! \fn void db_create_connection_pool(int type)
 *  \brief Creates a connection pool for spine
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
void db_create_connection_pool(int type) {
	int id;
	pool_t *slots = type == LOCAL ? db_pool_local : type == REMOTE ? db_pool_remote
																   : NULL;
	if (db_pool_ownership_init(slots, (size_t) set.poller.threads) != 0) {
		die("FATAL: Unable to initialize database pool ownership");
	}

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
	pool_t *slots = type == LOCAL ? db_pool_local : type == REMOTE ? db_pool_remote
																   : NULL;
	size_t count = db_pool_owned_size(slots);
	if (db_pool_ownership_destroy(slots) != 0) {
		die("FATAL: Cannot close a database pool while leases remain");
	}

	if (type == LOCAL) {
		for (id = 0; (size_t) id < count; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Local Connection Pool ID %i", id));
			db_disconnect(&db_pool_local[id].mysql);
		}

		free(db_pool_local);
		db_pool_local = NULL;
	} else {
		for (id = 0; (size_t) id < count; id++) {
			SPINE_LOG_DEBUG(("DEBUG: Closing Remote Connection Pool ID %i", id));
			db_disconnect(&db_pool_remote[id].mysql);
		}

		free(db_pool_remote);
		db_pool_remote = NULL;
	}
}

/*! \fn pool_t db_get_connection(int type)
 *  \brief returns a free mysql connection from the pool
 *  \param type the connection type, LOCAL or REMOTE
 *
 */
bool db_acquire_lease(int type, db_lease_t *lease) {
	pool_t *slots = type == LOCAL ? db_pool_local : type == REMOTE ? db_pool_remote
																   : NULL;
	if (lease == NULL || db_pool_take_owned(slots, lease) == NULL) return FALSE;
	lease->type = type;
	return TRUE;
}

/*! \fn voi db_release_connection(int id)
 *  \brief marks a database connection as free
 *  \param id the connection id
 *
 */
bool db_release_lease(db_lease_t *lease) {
	pool_t *slots;
	if (lease == NULL) return FALSE;
	slots = lease->type == LOCAL ? db_pool_local : lease->type == REMOTE ? db_pool_remote
																		 : NULL;
	if (db_pool_return_owned(slots, lease) == 0) return TRUE;
	SPINE_LOG(("ERROR: Database lease release rejected; ownership does not match"));
	thread_mutex_lock(LOCK_THDET);
	set.exit.exit_code = EXIT_FAILURE;
	thread_mutex_unlock(LOCK_THDET);
	return FALSE;
}
