/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
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
 *
 * COMMAND-LINE PARAMETERS
 *
 * -h | --help
 * -v | --version
 *
 *	Show a brief help listing, then exit.
 *
 * -C | --conf=F
 *
 *	Provide the name of the Spine configuration file, which contains
 *	the parameters for connecting to the database. In the absence of
 *	this, it searches in order: the current directory, /etc/,
 *	/etc/cacti/, and ../etc/ for a file named spine.conf.
 *
 * -f | --first=ID
 *
 *	Start polling with device <ID> (else starts at the beginning)
 *
 * -l | --last=ID
 *
 *	Stop polling after device <ID> (else ends with the last one)
 *
 * -m | --mibs
 *
 *	Collect all system mibs this pass
 *
 * -N | --mode=online|offline|recovery
 *
 *	For remote pollers, the polling mode.  The default is 'online'
 *
 * -H | --hostlist="hostid1,hostid2,hostid3,...,hostidn"
 *
 *	Override the expected first host, last host behavior with a list of hostids.
 *
 * -O | --option=setting:value
 *
 *	Override a DB-provided value from the settings table in the DB.
 *
 * -C | -conf=FILE
 *
 *	Specify the location of the Spine configuration file.
 *
 * -R | --readonly
 *
 *	This processing is readonly with respect to the database: it's
 *	meant only for developer testing.
 *
 * -S | --stdout
 *
 *	All logging goes to the standard output
 *
 * -V | --verbosity=V
 *
 * Set the debug logging verbosity to <V>. Can be 1..5 or
 *	NONE/LOW/MEDIUM/HIGH/DEBUG (case insensitive).
 *
 * The First/Last device IDs are all relative to the "hosts" table in the
 * Cacti database, and this mechanism allows us to split up the polling
 * duties across multiple "spine" instances: each one gets a subset of
 * the polling range.
 *
 * For compatibility with poller.php, we also accept the first and last
 * device IDs as standalone parameters on the command line.
*/

#include "internal/common.h"
#include "app/spine.h"
#include "app/startup_internal.h"
#include <limits.h>

/*! \fn main(int argc, char *argv[])
 *  \brief The Spine program entry point
 *  \param argc The number of arguments passed to the function plus one (+1)
 *  \param argv An array of the command line arguments
 *
 *  The Spine entry point.  This function performs the following tasks.
 *  1) Processes command line input parameters
 *  2) Processes the Spine configuration file to obtain database access information
 *  3) Process runtime parameters from the settings table
 *  4) Initialize the runtime threads and mutexes for the threaded environment
 *  5) Initialize Net-SNMP, MySQL, and the PHP Script Server (if required)
 *  6) Spawns X threads in order to process hosts
 *  7) Loop until either all hosts have been processed or until the poller runtime
 *     has been exceeded
 *  8) Close database and free variables
 *  9) Log poller process statistics if required
 *  10) Exit
 *
 *  Note: Command line runtime parameters override any database settings.
 *
 *  \return 0 if SUCCESS, or -1 if FAILED
 *
 */
static bool wait_for_worker_permit(spine_permits_t *permit, int host_id, int host_thread, const char *label) {
	int retries = 0;
	for (;;) {
		int error = spine_permits_try_acquire(permit);
		if (error == 0) return TRUE;
		if (error == EDEADLK) {
			SPINE_LOG_DEVDBG(("WARNING: Device[%i] HT[%i] would have deadlocked acquiring %s", host_id, host_thread, label));
		} else if (error != EINTR && error != EAGAIN) {
			SPINE_LOG_DEVDBG(("WARNING: Device[%i] HT[%i] errored with %d while acquiring %s", host_id, host_thread, error, label));
		}
		if (++retries == 10) {
			if (get_time_as_double() - start_time + 1 > set.poller.poller_interval) {
				SPINE_LOG(("ERROR: Device[%i] HT[%i] polling timed out while acquiring %s", host_id, host_thread, label));
				return FALSE;
			}
			retries = 0;
		}
		spine_sleep_usec(10000);
		total_time = get_time_as_double();
		if (total_time - start_time > set.poller.poller_interval) {
			SPINE_LOG(("ERROR: Device[%i] HT[%i] Spine Timed Out While Processing Devices (%s)", host_id, host_thread, label));
			return FALSE;
		}
	}
}

static bool acquire_worker_permits(spine_permits_t *startup, int host_id, int host_thread) {
	if (!wait_for_worker_permit(&available_threads, host_id, host_thread, "Available Thread Lock")) return FALSE;
	if (wait_for_worker_permit(startup, host_id, host_thread, "Thread Initialization Lock")) return TRUE;
	spine_permits_release(&available_threads);
	return FALSE;
}

typedef struct {
	int threads;
	int items;
	char *timestamp;
	double time;
} poller_partition_t;

static int count_partition_items(MYSQL *mysql, int host_id, int divisor, bool due_only) {
	char query[BIG_BUFSIZE];
	const char *due = due_only ? " AND rrd_next_step <=0" : "";
	if (divisor > 1) {
		snprintf(query, sizeof(query), "SELECT SQL_NO_CACHE CEIL(COUNT(local_data_id)/%i) FROM poller_item WHERE host_id=%i%s", divisor, host_id, due);
	} else {
		snprintf(query, sizeof(query), "SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item WHERE host_id=%i%s", host_id, due);
	}
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	if (result == NULL) die("ERROR: Unable to count polling items");
	MYSQL_ROW row = mysql_fetch_row(result);
	if (row == NULL || row[0] == NULL) {
		db_free_result(result);
		die("ERROR: Missing polling item count");
	}
	int count = atoi(row[0]);
	db_free_result(result);
	return count;
}

static void update_partition_time(poller_partition_t *partition) {
	spine_snprintf(partition->timestamp, SMALL_BUFSIZE, "%lu", (unsigned long) time(NULL));
	partition->time = get_time_as_double();
}

static void prepare_device_partition(MYSQL *mysql, int host_id, int current_thread, poller_partition_t *partition) {
	if (set.availability.ping_only) {
		partition->threads = 1;
	} else {
		int total_items = count_partition_items(mysql, host_id, 1, set.poller.active_profiles != 1);
		if (total_items && total_items < partition->threads) partition->threads = total_items;
	}
	if (partition->threads > 1) {
		if (current_thread == 1) {
			partition->items = count_partition_items(mysql, host_id, partition->threads, set.poller.active_profiles != 1);
			update_partition_time(partition);
		} else if (partition->time == 0 || partition->timestamp == NULL) {
			update_partition_time(partition);
		}
	} else {
		partition->items = count_partition_items(mysql, host_id, 1, TRUE);
		update_partition_time(partition);
	}
}

static bool start_poll_worker(const poller_thread_t *device, int current_thread, spine_permits_t *startup,
	const pthread_attr_t *attributes, pthread_t *thread) {
	if (!acquire_worker_permits(startup, device->host_id, current_thread)) {
		thread_mutex_lock(LOCK_THDET);
		set.exit.exit_code = EXIT_FAILURE;
		thread_mutex_unlock(LOCK_THDET);
		return FALSE;
	}
	poller_thread_t *worker = malloc(sizeof(*worker));
	if (worker == NULL) die("ERROR: Fatal malloc error: polling worker instructions");
	thread_mutex_lock(LOCK_THDET);
	*worker = *device;
	thread_mutex_unlock(LOCK_THDET);
	worker->host_thread = current_thread;
	int status;
	do {
		status = pthread_create(thread, attributes, child, worker);
		if (status == EAGAIN) spine_sleep_usec(10000);
	} while (status == EAGAIN && get_time_as_double() - start_time < set.poller.poller_interval);
	if (status == 0) {
		SPINE_LOG_DEBUG(("Device[%i] DEBUG: Valid Thread to be Created (%ld)", device->host_id, (unsigned long int) *thread));
		return TRUE;
	}
	SPINE_LOG(("ERROR: Device[%i] HT[%i] unable to create polling thread (error %d)", device->host_id, current_thread, status));
	free(worker);
	spine_permits_release(startup);
	spine_permits_release(&available_threads);
	thread_mutex_lock(LOCK_THDET);
	set.exit.exit_code = EXIT_FAILURE;
	thread_mutex_unlock(LOCK_THDET);
	return FALSE;
}

static void report_worker_launch(const poller_thread_t *device, int device_counter) {
	int available = spine_permits_available(&available_threads);
	SPINE_LOG_HIGH(("Device[%i] DEBUG: Available Threads is %i (%i outstanding)", device->host_id, available, set.poller.threads - available));
	thread_mutex_lock(LOCK_THDET);
	SPINE_LOG_DEVDBG(("DEBUG: DTS: device = %d, host_id = %d, host_thread = %d,"
					  " host_threads = %d, host_data_ids = %d, complete = %d",
		device_counter - 1, device->host_id, device->host_thread, device->host_threads,
		device->host_data_ids, device->complete));
	thread_mutex_unlock(LOCK_THDET);
}

int wait_for_workers(double begin_time) {
	int a_threads_value;
	double cur_time;
	a_threads_value = spine_permits_available(&available_threads);

	/* wait for all threads to 'complete'
	 * using the mutex here as the semaphore will
     * show zero before the children are done */
	while (a_threads_value < set.poller.threads) {
		cur_time = get_time_as_double();

		if (cur_time - begin_time > set.poller.poller_interval) {
			SPINE_LOG(("ERROR: Polling timed out while waiting for %d Threads to End", set.poller.threads - a_threads_value));
			/* Active workers still own pool entries and completion state. Exit the
			 * process before normal cleanup can invalidate those borrowed objects. */
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Polling deadline expired with active workers; polling is incomplete");
		}

		SPINE_LOG_HIGH(("NOTE: Polling sleeping while waiting for %d Threads to End", set.poller.threads - a_threads_value));
		spine_sleep_usec(500000);
		a_threads_value = spine_permits_available(&available_threads);
	}

	return a_threads_value;
}

void report_worker_completion(int num_rows) {
	int threads_missing = -1;
	if (set.availability.ping_only) return;
	thread_mutex_lock(LOCK_THDET);

	for (int threads_count = 0; threads_count < num_rows; threads_count++) {
		const poller_thread_t *det = details[threads_count];

		if (threads_missing == -1 && det == NULL) {
			threads_missing = threads_count;
		}

		if (det != NULL) {
			if (det->output_failed) {
				SPINE_LOG(("ERROR: Device[%i] output persistence failed; due items remain scheduled for retry", det->host_id));
			}
			if (det->poll_failed) {
				SPINE_LOG(("ERROR: Device[%i] polling failed on a database error; due items remain scheduled for retry", det->host_id));
			}
			SPINE_LOG_HIGH(("INFO: Device[%i] Thread %scomplete and %d to %d sources",
				det->host_id,
				det->complete ? "" : "in",
				det->host_data_ids * (det->host_thread - 1),
				det->host_data_ids * (det->host_thread)));

			SPINE_LOG_DEVDBG(("DEBUG: DTF: device = %d, host_id = %d, host_thread = %d,"
							  " host_threads = %d, host_data_ids = %d, complete = %d",
				threads_count,
				det->host_id,
				det->host_thread,
				det->host_threads,
				det->host_data_ids,
				det->complete));
		}
	}

	thread_mutex_unlock(LOCK_THDET);

	if (threads_missing > -1) {
		SPINE_LOG(("WARNING: There were %d threads which did not run", num_rows - threads_missing));
	}
}

void launch_poll_workers(MYSQL *mysql, MYSQL_RES *result, int num_rows,
	pthread_t *threads, spine_permits_t *thread_init_sem,
	const pthread_attr_t *attr, char *host_time) {
	poller_partition_t partition = {.timestamp = host_time};
	poller_thread_t *poller_details = NULL;
	MYSQL_ROW mysql_row;
	int device_counter = 0;
	int current_thread;
	int host_id = 0;
	int change_host = TRUE;
	int canexit = FALSE;
	struct snmp_session session;
	/* initialize the threading code */
	partition.threads = 1;
	current_thread = 0;

	/* poller 1 always polls host 0 but only if it exists */
	if (set.poller.poller_id == 1 && set.hosts.has_device_0 == TRUE) {
		host_id = 0;
		change_host = FALSE;
	} else {
		change_host = TRUE;
	}

	/**
     * We must initialize the first snmp session
     * in the main thread to initialize the mib files
     * and other structures.  After which it's snmp
     * is thread safe in threads
     */
	snmp_sess_init(&session);

	/* loop through devices until done */
	while (canexit == FALSE && device_counter < num_rows) {
		if (change_host) {
			mysql_row = mysql_fetch_row(result);
			/* num_rows comes from this result, so a short read is not expected;
			 * upstream guarded it and the dispatch refactor dropped the check. */
			if (mysql_row == NULL || mysql_row[0] == NULL || mysql_row[1] == NULL) {
				SPINE_LOG(("ERROR: Device list ended after %i of %i devices", device_counter, num_rows));
				thread_mutex_lock(LOCK_THDET);
				set.exit.exit_code = EXIT_FAILURE;
				thread_mutex_unlock(LOCK_THDET);
				break;
			}
			host_id = atoi(mysql_row[0]);
			partition.threads = atoi(mysql_row[1]);
			current_thread = 1;

			if (partition.threads < 1) {
				partition.threads = 1;
			}
		} else {
			current_thread++;
		}

		prepare_device_partition(mysql, host_id, current_thread, &partition);
		change_host = (current_thread >= partition.threads) ? TRUE : FALSE;

		if (current_thread == 1) {
			/* populate the thread structure */
			if (!(poller_details = malloc(sizeof(*poller_details)))) {
				die("ERROR: Fatal malloc error: spine.c poller_details!");
			}

			poller_details->device_counter = device_counter;
			poller_details->host_id = host_id;
			poller_details->host_thread = partition.threads;
			poller_details->host_threads = partition.threads;
			poller_details->host_data_ids = partition.items;

			snprintf(poller_details->host_time, 40, "%s", host_time);

			poller_details->host_time_double = partition.time;
			poller_details->thread_init_sem = thread_init_sem;
			poller_details->complete = FALSE;
			poller_details->threads_complete = 0;
			poller_details->output_failed = FALSE;
			poller_details->poll_failed = FALSE;

			thread_mutex_lock(LOCK_THDET);
			details[device_counter] = poller_details;
			thread_mutex_unlock(LOCK_THDET);
		} else {
			poller_details = details[device_counter];
		}


		if (start_poll_worker(poller_details, current_thread, thread_init_sem, attr, &threads[device_counter])) {
			if (change_host) device_counter++;
			report_worker_launch(poller_details, device_counter);
		} else {
			canexit = TRUE;
		}
	}
}

void prepare_worker_storage(MYSQL_RES *result, int *rows,
	pthread_t **worker_threads, int **host_ids, char **timestamp) {
	int num_rows;
	pthread_t *threads = NULL;
	int *ids = NULL;
	char *host_time = NULL;
	if (set.poller.poller_id == 1) {
		if (set.hosts.has_device_0) {
			num_rows = spine_count_to_int(mysql_num_rows(result) + 1); /* pollerid 1 takes care of non host based data sources */
		} else {
			num_rows = spine_count_to_int(mysql_num_rows(result)); /* pollerid 1 takes care of non host based data sources */
		}
	} else {
		num_rows = spine_count_to_int(mysql_num_rows(result));
	}

	if (num_rows > 0) {
		if (!(threads = malloc(num_rows * sizeof(*threads)))) {
			die("ERROR: Fatal malloc error: spine.c threads!");
		}

		if (!(details = (poller_thread_t **) calloc((size_t) num_rows, sizeof(poller_thread_t *)))) {
			die("ERROR: Fatal malloc error: spine.c details!");
		}

		if (!(ids = malloc(num_rows * sizeof(*ids)))) {
			die("ERROR: Fatal malloc error: spine.c host id's!");
		}

		if (!(host_time = malloc(SMALL_BUFSIZE))) {
			die("ERROR: Fatal malloc error: util.c host_time");
		}

		memset(host_time, 0, SMALL_BUFSIZE);
	}


	*rows = num_rows;
	*worker_threads = threads;
	*host_ids = ids;
	*timestamp = host_time;
}

void free_worker_storage(int num_rows, pthread_t *threads, int *ids,
	char *conf_file, char *host_time) {
	/* free malloc'd variables */
	for (int i = 0; i < num_rows; i++) {
		if (details[i] != NULL) {
			SPINE_FREE(details[i]);
		}
	}

	SPINE_FREE(details);
	SPINE_FREE(threads);
	SPINE_FREE(ids);
	SPINE_FREE(conf_file);
	SPINE_FREE(debug_devices);
	SPINE_FREE(host_time);
	SPINE_FREE(php_processes);

	SPINE_LOG_DEBUG(("DEBUG: Allocated Variable Memory Freed"));
}
