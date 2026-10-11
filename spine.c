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

#include "common.h"
#include "spine.h"
#include <limits.h>

#ifdef SPINE_TEST_PROGRAM_ENTRY
#define main spine_program_main
#endif

/* Global Variables */
int entries = 0;
int num_hosts = 0;
spine_permits_t available_threads;
spine_permits_t available_scripts;
double start_time;
double total_time;

config_t set;
php_t	*php_processes = 0;
char	config_paths[CONFIG_PATHS][BUFSIZE];
int     *debug_devices;

pool_t  *db_pool_local;
pool_t  *db_pool_remote;

poller_thread_t** details = NULL;

static char *getarg(char *opt, char ***pargv);
static void display_help(int only_version);

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
typedef enum {
	CLI_FIRST,
	CLI_LAST,
	CLI_POLLER,
	CLI_THREADS,
	CLI_PINGONLY,
	CLI_MODE,
	CLI_HOSTLIST,
	CLI_MIBS,
	CLI_HELP,
	CLI_VERSION,
	CLI_OPTION,
	CLI_READONLY,
	CLI_CONF,
	CLI_STDOUT,
	CLI_LOG,
	CLI_VERBOSITY,
	CLI_UNKNOWN
} cli_option_t;

typedef struct {
	const char *name;
	cli_option_t option;
	bool ignore_case;
} cli_alias_t;

static cli_option_t lookup_cli_option(const char *arg) {
	static const cli_alias_t aliases[] = {
		{"-f", CLI_FIRST, TRUE},
		{"--first", CLI_FIRST, FALSE},
		{"-l", CLI_LAST, TRUE},
		{"--last", CLI_LAST, TRUE},
		{"-p", CLI_POLLER, FALSE},
		{"--poller", CLI_POLLER, TRUE},
		{"-t", CLI_THREADS, FALSE},
		{"--threads", CLI_THREADS, TRUE},
		{"-P", CLI_PINGONLY, FALSE},
		{"--pingonly", CLI_PINGONLY, TRUE},
		{"-N", CLI_MODE, FALSE},
		{"--mode", CLI_MODE, TRUE},
		{"-H", CLI_HOSTLIST, FALSE},
		{"--hostlist", CLI_HOSTLIST, TRUE},
		{"-M", CLI_MIBS, TRUE},
		{"--mibs", CLI_MIBS, FALSE},
		{"-h", CLI_HELP, TRUE},
		{"--help", CLI_HELP, FALSE},
		{"-v", CLI_VERSION, FALSE},
		{"--version", CLI_VERSION, FALSE},
		{"-O", CLI_OPTION, TRUE},
		{"--option", CLI_OPTION, TRUE},
		{"-R", CLI_READONLY, TRUE},
		{"--readonly", CLI_READONLY, FALSE},
		{"--read-only", CLI_READONLY, FALSE},
		{"-C", CLI_CONF, TRUE},
		{"--conf", CLI_CONF, FALSE},
		{"-S", CLI_STDOUT, TRUE},
		{"--stdout", CLI_STDOUT, FALSE},
		{"-D", CLI_LOG, TRUE},
		{"--log", CLI_LOG, FALSE},
		{"-V", CLI_VERBOSITY, FALSE},
		{"--verbosity", CLI_VERBOSITY, FALSE},
	};
	for (size_t index = 0; index < sizeof(aliases) / sizeof(aliases[0]); index++) {
		bool matches = aliases[index].ignore_case ? STRIMATCH(arg, aliases[index].name) : STRMATCH(arg, aliases[index].name);
		if (matches) return aliases[index].option;
	}
	return CLI_UNKNOWN;
}

static void parse_polling_mode(const char *requested_mode) {
	if (STRIMATCH(requested_mode, "online")) {
		set.poller.mode = REMOTE_ONLINE;
	} else if (STRIMATCH(requested_mode, "offline")) {
		set.poller.mode = REMOTE_OFFLINE;
	} else if (STRIMATCH(requested_mode, "recovery")) {
		set.poller.mode = REMOTE_RECOVERY;
	} else {
		die("ERROR: invalid polling mode '%s' specified", requested_mode);
	}
}

static void parse_host_list(const char *input) {
	if (strnlen(input, sizeof(set.hosts.host_id_list)) == sizeof(set.hosts.host_id_list)) {
		die("ERROR: invalid or oversized host list");
	}
	size_t used = 0;
	const char *cursor = input;
	for (;;) {
		while (isspace((unsigned char)*cursor)) cursor++;
		if (*cursor < '0' || *cursor > '9') die("ERROR: invalid or oversized host list");
		errno = 0;
		char *end;
		unsigned long id = strtoul(cursor, &end, 10);
		if (errno == ERANGE || id > INT_MAX) die("ERROR: invalid or oversized host list");
		while (isspace((unsigned char)*end)) end++;
		if (*end != '\0' && *end != ',') die("ERROR: invalid or oversized host list");
		/* SQL receives only converted integer values and owned separators. */
		used += (size_t)spine_snprintf(set.hosts.host_id_list + used,
			sizeof(set.hosts.host_id_list) - used, "%s%lu", used == 0 ? "" : ",", id);
		if (*end == '\0') return;
		cursor = end + 1;
	}
}

static void parse_cli_argument(const char *arg, char *opt, char ***argv, char **conf_file) {
	switch (lookup_cli_option(arg)) {
		case CLI_FIRST: {
			if (HOSTID_DEFINED(set.hosts.start_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			opt = getarg(opt, argv);
			set.hosts.start_host_id = atoi(opt);

			if (!HOSTID_DEFINED(set.hosts.start_host_id)) {
				die("ERROR: '%s=%s' is invalid first-host ID", arg, opt);
			}
			break;
		}
		case CLI_LAST: {
			if (HOSTID_DEFINED(set.hosts.end_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			opt = getarg(opt, argv);
			set.hosts.end_host_id = atoi(opt);

			if (!HOSTID_DEFINED(set.hosts.end_host_id)) {
				die("ERROR: '%s=%s' is invalid last-host ID", arg, opt);
			}
			break;
		}
		case CLI_POLLER: {
			set.poller.poller_id = atoi(getarg(opt, argv));
			break;
		}
		case CLI_THREADS: {
			set.poller.threads = atoi(getarg(opt, argv));
			set.poller.threads_set = TRUE;
			break;
		}
		case CLI_PINGONLY: {
			set.availability.ping_only = TRUE;
			break;
		}
		case CLI_MODE: {
			parse_polling_mode(getarg(opt, argv));
			break;
		}
		case CLI_HOSTLIST: {
			parse_host_list(getarg(opt, argv));
			break;
		}
		case CLI_MIBS: {
			set.snmp.mibs = 1;
			break;
		}
		case CLI_HELP: {
			display_help(FALSE);

			exit(EXIT_SUCCESS);
		}
		case CLI_VERSION: {
			display_help(TRUE);

			exit(EXIT_SUCCESS);
		}
		case CLI_OPTION: {
			const char *setting = getarg(opt, argv);
			char *value   = strchr(setting, ':');

			if (value != NULL && value != setting) {
				*value++ = '\0';
			} else {
				die("ERROR: -O requires setting:value");
			}

			set_option(setting, value);
			break;
		}
		case CLI_READONLY: {
			set.poller.SQL_readonly = TRUE;
			break;
		}
		case CLI_CONF: {
			char *replacement = strdup(getarg(opt, argv));
			if (replacement == NULL) die("ERROR: Fatal malloc error: spine.c conf_file!");
			SPINE_FREE(*conf_file);
			*conf_file = replacement;
			break;
		}
		case CLI_STDOUT: {
			set_option("log_destination", "STDOUT");
			break;
		}
		case CLI_LOG: {
			set_option("log_destination", getarg(opt, argv));
			break;
		}
		case CLI_VERBOSITY: {
			set_option("log_verbosity", getarg(opt, argv));
			break;
		}
		default:
			if (!HOSTID_DEFINED(set.hosts.start_host_id) && all_digits(arg)) {
				set.hosts.start_host_id = atoi(arg);
			}

			else if (!HOSTID_DEFINED(set.hosts.end_host_id) && all_digits(arg)) {
				set.hosts.end_host_id = atoi(arg);
			}

			else {
				die("ERROR: %s is an unknown command-line parameter", arg);
			}
			break;
	}
}

static void parse_command_line(char **argv, char **conf_file) {
	argv++;
	while (*argv) {
		const char *arg = *argv;
		char *opt = strchr(arg, '=');
		if (opt) *opt++ = '\0';
		parse_cli_argument(arg, opt, &argv, conf_file);
		argv++;
	}
}

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

static char *load_startup_configuration(char *conf_file) {
	int valid_conf_file = FALSE;
	/* read configuration file to establish local environment */
	if (conf_file) {
		if ((read_spine_config(conf_file)) < 0) {
			die("ERROR: Could not read config file: %s", conf_file);
		} else {
			valid_conf_file = TRUE;
		}
	} else {
		if (!(conf_file = calloc(CONFIG_PATHS, DBL_BUFSIZE))) {
			die("ERROR: Fatal malloc error: spine.c conf_file!");
		}

		for (int i=0; i<CONFIG_PATHS; i++) {
			snprintf(conf_file, DBL_BUFSIZE, "%.*s%s", (int) sizeof(config_paths[i]) - 1, config_paths[i], DEFAULT_CONF_FILE);

			if (read_spine_config(conf_file) >= 0) {
				valid_conf_file = TRUE;
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, DBL_BUFSIZE, "%.*s%s", (int) sizeof(config_paths[0]) - 1, config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	if (valid_conf_file) {
		/* read settings table from the database to further establish environment */
		read_config_options();
	} else {
		die("FATAL: Unable to read configuration file!");
	}

	return conf_file;
}

static MYSQL_RES *select_poll_hosts(MYSQL *mysql) {
	char querybuf[MEGA_BUFSIZE];
	char *qp = querybuf;
	/* obtain the list of hosts to poll */
	qp += spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), "SELECT SQL_NO_CACHE id, device_threads, picount, picount/device_threads AS tppi FROM host AS h LEFT JOIN (SELECT host_id, COUNT(*) AS picount FROM poller_item GROUP BY host_id) AS pi ON h.id = pi.host_id");
	qp += spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), " WHERE disabled = ''");

	qp += spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), " AND availability_method != %d", AVAIL_STREAM);

	if (!strlen(set.hosts.host_id_list)) {
		qp += append_hostrange(qp, sizeof(querybuf) - (size_t)(qp - querybuf), "h.id");	/* AND id BETWEEN a AND b */
	} else {
		qp += spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), " AND h.id IN(%s)", set.hosts.host_id_list);
	}

	qp += spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), " AND h.poller_id = %i", set.poller.poller_id);
	spine_snprintf(qp, sizeof(querybuf) - (size_t)(qp - querybuf), " ORDER BY picount DESC");

	SPINE_LOG_DEVDBG(("DEVDBG: Host SQL:%s", querybuf));
	return db_query(mysql, LOCAL, querybuf);

}

static void report_startup_version(int mode) {
	if (set.logging.log_level == POLLER_VERBOSITY_DEBUG) {
		SPINE_LOG_DEBUG(("DEBUG: Version %s starting", VERSION));
		if (set.poller.poller_id > 1) {
			if (mode == REMOTE) {
				SPINE_LOG_DEBUG(("DEBUG: Sending entries to remote database in 'online' mode"));
			} else {
				SPINE_LOG_DEBUG(("DEBUG: Sending entries to local database in 'offline', or 'recovery' mode"));
			}
		}
		return;
	}
	if (set.console.stdout_notty) return;
	printf("Version %s starting\n", VERSION);
	if (set.poller.poller_id <= 1) return;
	if (mode == REMOTE) {
		printf("Sending entries to remote database in 'online' mode\n");
	} else {
		printf("Sending entries to local database in 'offline', or 'recovery' mode\n");
	}
}

static void report_startup(int mode) {
	report_startup_version(mode);
	if (set.hosts.has_device_0) {
		SPINE_LOG_MEDIUM(("Device 0 Poller Items found.  Ensure that these entries are accurate"));
	} else {
		SPINE_LOG_MEDIUM(("No Device 0 Poller Items found."));
	}

	/* see if mysql is thread safe */
	if (mysql_thread_safe()) {
		if (set.logging.log_level == POLLER_VERBOSITY_DEBUG) {
			SPINE_LOG(("DEBUG: MySQL is Thread Safe!"));
		}
	} else {
		SPINE_LOG(("WARNING: MySQL is NOT Thread Safe!"));
	}

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
	spine_snprintf(partition->timestamp, SMALL_BUFSIZE, "%lu", (unsigned long)time(NULL));
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
		SPINE_LOG_DEBUG(("Device[%i] DEBUG: Valid Thread to be Created (%ld)", device->host_id, (unsigned long int)*thread));
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
		device_counter-1, device->host_id, device->host_thread, device->host_threads,
		device->host_data_ids, device->complete));
	thread_mutex_unlock(LOCK_THDET);
}

static int wait_for_workers(double begin_time) {
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

static void report_worker_completion(int num_rows) {
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
				det->complete ? "":"in",
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

static void launch_poll_workers(MYSQL *mysql, MYSQL_RES *result, int num_rows,
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
	partition.threads   = 1;
	current_thread   = 0;

	/* poller 1 always polls host 0 but only if it exists */
	if (set.poller.poller_id == 1 && set.hosts.has_device_0 == TRUE) {
		host_id     = 0;
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
			mysql_row       = mysql_fetch_row(result);
			/* num_rows comes from this result, so a short read is not expected;
			 * upstream guarded it and the dispatch refactor dropped the check. */
			if (mysql_row == NULL || mysql_row[0] == NULL || mysql_row[1] == NULL) {
				SPINE_LOG(("ERROR: Device list ended after %i of %i devices", device_counter, num_rows));
				thread_mutex_lock(LOCK_THDET);
				set.exit.exit_code = EXIT_FAILURE;
				thread_mutex_unlock(LOCK_THDET);
				break;
			}
			host_id         = atoi(mysql_row[0]);
			partition.threads  = atoi(mysql_row[1]);
			current_thread  = 1;

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
			if (!(poller_details = (poller_thread_t *)malloc(sizeof(poller_thread_t)))) {
				die("ERROR: Fatal malloc error: spine.c poller_details!");
			}

			poller_details->device_counter   = device_counter;
			poller_details->host_id          = host_id;
			poller_details->host_thread      = partition.threads;
			poller_details->host_threads     = partition.threads;
			poller_details->host_data_ids    = partition.items;

			snprintf(poller_details->host_time, 40, "%s", host_time);

			poller_details->host_time_double = partition.time;
			poller_details->thread_init_sem  = thread_init_sem;
			poller_details->complete         = FALSE;
			poller_details->threads_complete = 0;
			poller_details->output_failed    = FALSE;
			poller_details->poll_failed      = FALSE;

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

static void prepare_worker_storage(MYSQL_RES *result, int *rows,
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
		if (!(threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t)))) {
			die("ERROR: Fatal malloc error: spine.c threads!");
		}

		if (!(details = (poller_thread_t **)calloc((size_t)num_rows, sizeof(poller_thread_t*)))) {
			die("ERROR: Fatal malloc error: spine.c details!");
		}

		if (!(ids = (int *)malloc(num_rows * sizeof(int)))) {
			die("ERROR: Fatal malloc error: spine.c host id's!");
		}

		if (!(host_time = (char *) malloc(SMALL_BUFSIZE))) {
			die("ERROR: Fatal malloc error: util.c host_time");
		}

		memset(host_time, 0, SMALL_BUFSIZE);
	}


	*rows = num_rows;
	*worker_threads = threads;
	*host_ids = ids;
	*timestamp = host_time;

}

static double initialize_process_defaults(void) {
	double begin_time;
	/* establish php processes and initialize space */
	php_processes = (php_t*) calloc(MAX_PHP_SERVERS, sizeof(php_t));
	if (php_processes == NULL) die("ERROR: Fatal calloc error: spine.c php_processes!");
	php_processes_initialize(php_processes, MAX_PHP_SERVERS);

	/* create the array of debug devices */
	debug_devices = calloc(MAX_DEBUG_DEVICES, sizeof(int));
	if (debug_devices == NULL) die("ERROR: Fatal calloc error: spine.c debug_devices!");

	/* initialize icmp_avail */
	set.availability.icmp_avail = TRUE;
	set.availability.icmp_uses_caps = FALSE;

	/* initialize number of threads */
	set.poller.threads = 1;
	set.poller.threads_set = FALSE;

	/* detect and compensate for stdin/stderr ttys */
	if (!isatty(fileno(stdout))) {
		set.console.stdout_notty = TRUE;
	} else {
		set.console.stdout_notty = FALSE;
	}

	if (!isatty(fileno(stderr))) {
		set.console.stderr_notty = TRUE;
	} else {
		set.console.stderr_notty = FALSE;
	}

	/* set start time for cacti */
	begin_time = get_time_as_double();

	/* set default verbosity */
	set.logging.log_level = POLLER_VERBOSITY_LOW;

	/* set default log separator */
	set.logging.log_datetime_separator = GDC_DEFAULT;

	/* set default log format */
	set.logging.log_datetime_format = GD_DEFAULT;

	/* set the default exit code */
	set.exit.exit_code = 0;
	set.exit.exit_size = 0;

	/* get static defaults for system */
	config_defaults();

	return begin_time;

}

static int initialize_main_database(MYSQL *mysql, MYSQL *mysqlr) {
	MYSQL_RES *result;
	int mode;
	int has_output_regex;
	/* initialize mysql objects for threads */
	mysql_library_init(0, NULL, NULL);

	/* connect for main loop */
	if (!db_connect(LOCAL, mysql)) die("FATAL: Unable to connect to the local database");

	/* setup local connection pool for hosts */
	db_pool_local = (pool_t *) calloc(set.poller.threads, sizeof(pool_t));
	if (db_pool_local == NULL) die("ERROR: Fatal calloc error: spine.c db_pool_local!");
	db_create_connection_pool(LOCAL);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		if (!db_connect(REMOTE, mysqlr)) die("FATAL: Unable to connect to the remote database");
		mode = REMOTE;

		/* setup remote connection pool for hosts */
		db_pool_remote = (pool_t *) calloc(set.poller.threads, sizeof(pool_t));
		if (db_pool_remote == NULL) die("ERROR: Fatal calloc error: spine.c db_pool_remote!");
		db_create_connection_pool(REMOTE);
	} else {
		mode = LOCAL;
	}


	/* check for device 0 items */
	result = db_query(mysql, LOCAL, "SELECT * FROM (SELECT COUNT(*) AS items FROM poller_item WHERE host_id = 0 AND poller_id = 1) AS rs WHERE rs.items > 0");
	if (result == NULL) die("FATAL: Unable to check for Device 0 poller items");
	if (mysql_num_rows(result)) {
		set.hosts.has_device_0 = TRUE;
	}
	db_free_result(result);

	/* check if poller_item has the output_regex column (added in Cacti 1.3.1) */
	has_output_regex = db_column_exists(mysql, LOCAL, "poller_item", "output_regex");
	if (has_output_regex < 0) die("FATAL: Unable to inspect the poller_item table");
	if (has_output_regex) {
		set.hosts.has_output_regex = TRUE;
		SPINE_LOG_DEBUG(("DEBUG: poller_item.output_regex column detected"));
	}

	/* Since MySQL 5.7 the sql_mode defaults are too strict for cacti. The
	 * same policy as the pool, which a reconnect of this handle reapplies. */
	if (!db_set_session_mode(mysql)) die("FATAL: Unable to configure the database session");

	return mode;

}

static void initialize_main_php(void) {
	/* initialize the script server */
	if (set.php.php_required && !set.availability.ping_only) {
		/* A server that started but did not answer stays BUSY for the restart
		 * path; polling can proceed while any server answers. */
		int ready = 0;
		bool started = php_init(PHP_INIT);
		for (int i = 0; started && i < set.php.php_servers; i++) {
			if (php_processes[i].php_state == PHP_READY) ready++;
		}
		if (!started || ready == 0) {
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: PHP Script Server initialization failed");
		}
		if (ready < set.php.php_servers) {
			SPINE_LOG(("WARNING: %i of %i PHP Script Servers did not answer at startup", set.php.php_servers - ready, set.php.php_servers));
		}
		set.php.php_initialized    = TRUE;
		set.php.php_current_server = 0;
	}

}

static void persist_poll_completion(MYSQL *mysql, MYSQL *mysqlr, int mode) {
	char querybuf[MEGA_BUFSIZE];
	/* push data back to the main server */
	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE && !set.poller.SQL_readonly) {
		poller_push_data_to_main();
	}

	/* update the db for |data_time| on graphs */
	if (!set.availability.ping_only) {
		if (set.poller.poller_id == 1) {
			db_insert(mysql, LOCAL, "REPLACE INTO settings (name,value) VALUES ('date',NOW())");
		}

		snprintf(querybuf, BIG_BUFSIZE, "UPDATE poller_time SET end_time=NOW() WHERE poller_id=%i AND pid=%i", set.poller.poller_id, getpid());

		if (mode == REMOTE) {
			db_insert(mysqlr, REMOTE, querybuf);
		} else {
			db_insert(mysql, LOCAL, querybuf);
		}
	}

	if (db_pool_local) {
		db_close_connection_pool(LOCAL);
	}

	if (db_pool_remote) {
		db_close_connection_pool(REMOTE);
	}

}

static void close_main_php(void) {
	/* close the php script server */
	if (set.php.php_required && !set.availability.ping_only) php_close(PHP_INIT);

	SPINE_LOG_DEBUG(("DEBUG: PHP Script Server Pipes Closed"));

}

static void free_worker_storage(int num_rows, pthread_t *threads, int *ids,
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

static void report_poll_statistics(double begin_time, int num_rows) {
	double end_time;
	/* finally add some statistics to the log and exit */
	end_time = get_time_as_double();

	if (set.logging.log_level >= POLLER_VERBOSITY_MEDIUM) {
		SPINE_LOG(("Time: %.4f s, Threads: %i, Devices: %i", (end_time - begin_time), set.poller.threads, num_rows));
	} else {
		/* provide output if running from command line */
		if (!set.console.stdout_notty) {
			fprintf(stdout, "Time: %.4f s, Threads: %i, Devices: %i\n", (end_time - begin_time), set.poller.threads, num_rows);
		}
	}

}

int main(int argc, char *argv[]) {
	char *conf_file = NULL;
	double begin_time;
	int num_rows = 0;
	char querybuf[MEGA_BUFSIZE];
	char *host_time = NULL;
	spine_permits_t thread_init_sem;
	int a_threads_value;

	start_time = get_time_as_double();
	total_time = 0;

	/* Before any option, file or setting is read; see drop_privileges(). */
	drop_privileges();

	pthread_t* threads = NULL;
	pthread_attr_t attr;

	int* ids = NULL;
	int mode = REMOTE;
	MYSQL mysql;
	MYSQL mysqlr;
	MYSQL_RES *result  = NULL;
	int threads_final = 0;


	UNUSED_PARAMETER(argc);		/* we operate strictly with argv */

	/* install the spine signal handler */
	install_spine_signal_handler();

	begin_time = initialize_process_defaults();

	/*! ----------------------------------------------------------------
	 * PROCESS COMMAND LINE
	 *
	 * Run through the list of ARGV words looking for parameters we
	 * know about. Most have two flavors (-C + --conf), and many
	 * themselves take a parameter.
	 *
	 * These parameters can be structured in two ways:
	 *
	 *	--conf=FILE		both parts in one argv[] string
	 *	--conf FILE		two separate argv[] strings
	 *
	 * We set "arg" to point to "--conf", and "opt" to point to FILE.
	 * The helper routine
	 *
	 * In each loop we set "arg" to next argv[] string, then look
	 * to see if it has an equal sign. If so, we split it in half
	 * and point to the option separately.
	 *
	 * NOTE: most direction to the program is given with dash-type
	 * parameters, but we also allow standalone numeric device IDs
	 * in "first last" format: this is how poller.php calls this
	 * program.
	 */

	/* initialize some global variables */
	set.poller.poller_id         = 1;
	set.hosts.start_host_id     = -1;
	set.hosts.end_host_id       = -1;
	set.hosts.host_id_list[0]   = '\0';
	set.php.php_initialized   = FALSE;
	set.logging.logfile_processed = FALSE;
	set.poller.parent_fork       = SPINE_PARENT;
	set.poller.mode              = REMOTE_ONLINE;
	set.hosts.has_device_0      = FALSE;
	set.hosts.has_output_regex  = FALSE;

	parse_command_line(argv, &conf_file);

	if (set.availability.ping_only) {
		set.snmp.mibs = 0;
	}

	/* we attempt to support scripts better in cygwin */
	#if defined(__CYGWIN__)
	setenv("CYGWIN", "nodosfilewarning", 1);
	if (file_exists("./sh.exe")) {
		set.cygwinshloc = 0;
		if (set.logging.log_level == POLLER_VERBOSITY_DEBUG) {
			printf("The Shell Command Exists in the current directory\n");
		}
	} else {
		set.cygwinshloc = 1;
		if (set.logging.log_level == POLLER_VERBOSITY_DEBUG) {
			printf("The Shell Command Exists in the /bin directory\n");
		}
	}
	#endif

	/* we require either both the first and last hosts, or neither host */
	if ((HOSTID_DEFINED(set.hosts.start_host_id) != HOSTID_DEFINED(set.hosts.end_host_id)) &&
		(!strlen(set.hosts.host_id_list))) {
		die("ERROR: must provide both -f/-l, a hostlist (-H/--hostlist), or neither");
	}

	if (set.hosts.start_host_id > set.hosts.end_host_id) {
		die("ERROR: Invalid row spec; first host_id must be less than the second");
	}

	conf_file = load_startup_configuration(conf_file);

	/* set the poller interval for those who use less than 5 minute intervals */
	if (set.poller.poller_interval == 0) {
		set.poller.poller_interval = 300;
	}

	/* tokenize the debug devices */
	if (strlen(set.logging.selective_device_debug)) {
		SPINE_LOG_DEBUG(("DEBUG: Selective Debug Devices %s", set.logging.selective_device_debug));
		parse_debug_devices(set.logging.selective_device_debug, debug_devices, MAX_DEBUG_DEVICES);
	} else {
		debug_devices[0] = '\0';
	}

	mode = initialize_main_database(&mysql, &mysqlr);

	report_startup(mode);

	/* test for asroot permissions for ICMP */
	checkAsRoot();

	/* initialize SNMP */
	SPINE_LOG_DEBUG(("DEBUG: Initializing Net-SNMP API"));
	snmp_spine_init();

	/* initialize PHP if required */
	SPINE_LOG_DEBUG(("DEBUG: Initializing PHP Script Server(s)"));

	/* tell spine that it is parent, and set the poller id */
	set.poller.parent_fork = SPINE_PARENT;

	initialize_main_php();

	result = select_poll_hosts(&mysql);
	if (result == NULL) die("FATAL: Unable to select the devices to poll");

	prepare_worker_storage(result, &num_rows, &threads, &ids, &host_time);

	/* initialize winsock library on Windows */
	SOCK_STARTUP;

	/* mark the spine process as started */
	if (!set.availability.ping_only) {
		snprintf(querybuf, BIG_BUFSIZE, "INSERT INTO poller_time (poller_id, pid, start_time, end_time) VALUES (%i, %i, NOW(), '0000-00-00 00:00:00')", set.poller.poller_id, getpid());
		if (mode == REMOTE) {
			db_insert(&mysqlr, REMOTE, querybuf);
		} else {
			db_insert(&mysql, LOCAL, querybuf);
		}
	}

	/* initialize threads and mutexes */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	/* Initialize process-local concurrency permits before worker startup. */
	if (spine_permits_init(&available_threads, set.poller.threads) != 0 ||
		spine_permits_init(&available_scripts, MAX_SIMULTANEOUS_SCRIPTS) != 0 ||
		spine_permits_init(&thread_init_sem, 1) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to initialize process permits");
	}

	/* specify the point of timeout for timedwait semaphores */

	a_threads_value = spine_permits_available(&available_threads);
	SPINE_LOG_HIGH(("DEBUG: Initial Value of Available Threads is %i (%i outstanding)", a_threads_value, set.poller.threads - a_threads_value));

	/* tell fork processes that they are now active */
	set.poller.parent_fork = SPINE_FORK;

	launch_poll_workers(&mysql, result, num_rows, threads, &thread_init_sem, &attr, host_time);

	a_threads_value = wait_for_workers(begin_time);

	threads_final = set.poller.threads - a_threads_value;

	SPINE_LOG_HIGH(("The final count of Threads is %i", threads_final));

	report_worker_completion(num_rows);

	/* tell Spine that it is now parent */
	set.poller.parent_fork = SPINE_PARENT;

	persist_poll_completion(&mysql, &mysqlr, mode);

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);

	SPINE_LOG_DEBUG(("DEBUG: Thread Cleanup Complete"));

	close_main_php();

	free_worker_storage(num_rows, threads, ids, conf_file, host_time);

	/* close mysql */
	db_free_result(result);
	db_disconnect(&mysql);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		db_disconnect(&mysqlr);
	}

	SPINE_LOG_DEBUG(("DEBUG: MYSQL Free & Close Completed"));

	/* close snmp */
	snmp_spine_close();

	SPINE_LOG_DEBUG(("DEBUG: Net-SNMP Close Completed"));

	report_poll_statistics(begin_time, num_rows);

	/* zero sensitive credentials before exit */
	spine_clear_sensitive(set.database.password, sizeof(set.database.password));
	spine_clear_sensitive(set.remote_database.password, sizeof(set.remote_database.password));

	/* uninstall the spine signal handler */
	uninstall_spine_signal_handler();

	/* clueanup winsock library on Windows */
	SOCK_CLEANUP;

	exit(set.exit.exit_code);
}

/*! \fn static void display_help()
 *  \brief Display Spine usage information to the caller.
 *
 *	Display the help listing: the first line is created at runtime with
 *	the version information, and the rest is strictly static text which
 *	is dumped literally.
 *
 */
static void display_help(int only_version) {
	static const char *const *p;
	static const char * const helptext[] = {
		"Usage: spine [options] [[firstid lastid] || [-H/--hostlist='hostid1,hostid2,...,hostidn']]",
		"",
		"Options:",
		"  -h/--help          Show this brief help listing",
		"  -f/--first=X       Start polling with host id X",
		"  -l/--last=X        End polling with host id X",
		"  -H/--hostlist=X    Poll the list of host ids, separated by comma's",
		"  -p/--poller=X      Set the poller id to X",
		"  -t/--threads=X     Override the database threads setting.",
		"  -C/--conf=F        Read spine configuration from file F",
		"  -O/--option=S:V    Override DB settings 'set' with value 'V'",
		"  -M/--mibs          Refresh the device System Mib data",
		"  -N/--mode=online   For remote pollers, the operating mode.",
		"                     Options include: online, offline, recovery.",
		"                     The default is 'online'.",
		"  -R/--readonly      Spine will not write output to the DB",
		"  -S/--stdout        Logging is performed to standard output",
		"  -P/--pingonly      Ping device and update device status only",
		"  -V/--verbosity=V   Set logging verbosity to <V>",
		"",
		"Either both of --first/--last must be provided, a valid hostlist must be provided.",
        "In their absence, all hosts are processed.",
		"",
		"Without the --conf parameter, spine searches in order:",
		"  current directory, /etc/, /etc/cacti/, ../etc/ for spine.conf.",
		"",
		"Verbosity is one of NONE/LOW/MEDIUM/HIGH/DEBUG or 1..5",
		"",
		"Runtime options are read from the 'settings' table in the Cacti",
		"database, but they can be overridden with the --option=S:V",
		"parameter.",
		"",
		"Spine is distributed under the Terms of the GNU Lesser",
		"General Public License Version 2.1. (http://www.gnu.org/licenses/lgpl.txt)",
		"For more information, see http://www.cacti.net",

		0 /* ENDMARKER */
	};

	printf("SPINE %s  Copyright 2004-2026 by The Cacti Group\n", VERSION);

	if (only_version == FALSE) {
		printf("\n");
		for (p = helptext; *p; p++) {
			puts(*p);	/* automatically adds a newline */
		}
	}
}

/*! \fn static char *getarg(char *opt, char ***pargv)
 *  \brief A function to parse calling parameters
 *
 *	This is a helper for the main arg-processing loop: we work with
 *	options which are either of the form "-X=FOO" or "-X FOO"; we
 *	want an easy way to handle either one.
 *
 *	The idea is that if the parameter has an = sign, we use the rest
 *	of that same argv[X] string, otherwise we have to get the *next*
 *	argv[X] string. But it's an error if an option-requiring param
 *	is at the end of the list with no argument to follow.
 *
 *	The option name could be of the form "-C" or "--conf", but we
 *	grab it from the existing argv[] so we can report it well.
 *
 * \return character pointer to the argument
 *
 */
static char *getarg(char *opt, char ***pargv) {
	const char *const optname = **pargv;

	/* option already set? */
	if (opt) return opt;

	/* advance to next argv[] and try that one */
	if ((opt = *++(*pargv)) != 0) return opt;

	die("ERROR: option %s requires a parameter", optname);
}

#ifdef SPINE_TEST_PROGRAM_ENTRY
#undef main
#endif
