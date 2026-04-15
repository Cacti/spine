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
#include "systemd_notify.h"
#include "platform/platform_sandbox.h"
#include "circuit_breaker.h"

#include <signal.h>

/* SIGHUP-triggered reload flag. Spine is a batch poller: an in-flight config
 * reload would race with worker threads already mid-poll. On HUP we therefore
 * notify systemd of a RELOADING/READY pair and let the current cycle finish;
 * the next invocation picks up the refreshed spine.conf.
 *
 * SIGTERM sets a graceful stop flag. The main loop checks it between devices
 * and exits cleanly so poller_output rows flush and the DB disconnects.
 *
 * volatile sig_atomic_t is the only type async-signal-safe for set/read
 * across the signal-handler boundary. */
static volatile sig_atomic_t spine_reload_requested = 0;
static volatile sig_atomic_t spine_stop_requested   = 0;

static void spine_sighup_handler(int signo) {
    (void)signo;
    spine_reload_requested = 1;
}

static void spine_sigterm_handler(int signo) {
    (void)signo;
    spine_stop_requested = 1;
}

static void spine_install_reload_handler(void) {
    struct sigaction sa;
    sa.sa_handler = spine_sighup_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGHUP, &sa, NULL);

    sa.sa_handler = spine_sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
}

/* Global Variables */
int entries = 0;
int num_hosts = 0;
spine_sem_t available_threads;
spine_sem_t available_scripts;
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
void poller_push_data_to_main(void);

#ifdef HAVE_LCAP
/* This patch is adapted (copied) patch for ntpd from Jarno Huuskonen and
 * Pekka Savola that was adapted (copied) from a patch by Chris Wings to drop
 * root for xntpd.
 */
void drop_root(uid_t server_uid, gid_t server_gid) {
	cap_t caps;
	if (prctl(PR_SET_KEEPCAPS, 1)) {
		SPINE_LOG_HIGH(("prctl(PR_SET_KEEPCAPS, 1) failed"));
		exit(1);
	}

	if (setgroups(0, NULL) == -1) {
		SPINE_LOG_HIGH(("setgroups failed."));
		exit(1);
	}

	if (setegid(server_gid) == -1 || seteuid(server_uid) == -1) {
		SPINE_LOG_HIGH(("setegid/seteuid to uid=%d/gid=%d failed.", server_uid, server_gid));
		exit(1);
	}

	caps = cap_from_text("cap_net_raw=eip");
	if (caps == NULL) {
		SPINE_LOG_HIGH(("cap_from_text failed."));
		exit(1);
	}

	if (cap_set_proc(caps) == -1) {
		SPINE_LOG_HIGH(("cap_set_proc failed."));
		exit(1);
	}

	/* Try to free the memory from cap_from_text */
	cap_free( caps );

	if ( setregid(server_gid, server_gid) == -1 ||
		setreuid(server_uid, server_uid) == -1 ) {
		SPINE_LOG_HIGH(("setregid/setreuid to uid=%d/gid=%d failed.",
			server_uid, server_gid));
		exit(1);
	}

	SPINE_LOG_LOW(("running as uid(%d)/gid(%d) euid(%d)/egid(%d) with cap_net_raw=eip.",
		getuid(), getgid(), geteuid(), getegid()));
}
#endif /* HAVE_LCAP */

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
int main(int argc, char *argv[]) {
	char *conf_file = NULL;
	double begin_time, end_time, cur_time;
	int num_rows = 0;
	int device_counter = 0;
	int valid_conf_file = FALSE;
	char querybuf[MEGA_BUFSIZE], *qp = querybuf;
	char *host_time = NULL;
	double host_time_double = 0;
	int items_per_thread = 0;
	int device_threads;
	spine_sem_t thread_init_sem;
	int a_threads_value;
	//struct timespec until_spec;

	pthread_t* threads = NULL;
	poller_thread_t* poller_details = NULL;
	pthread_attr_t attr;
	int* ids = NULL;
	int mode = REMOTE;
	MYSQL mysql;
	MYSQL mysqlr;
	MYSQL_RES *result  = NULL;
	MYSQL_RES *tresult = NULL;
	MYSQL_ROW mysql_row;
	int canexit = FALSE;
	int host_id = 0;
	int i;
	int thread_status = 0;
	int total_items   = 0;
	int change_host   = TRUE;
	int current_thread;
	int threads_final = 0;
	int threads_missing = -1;
	int threads_count;
	struct snmp_session session;

	start_time = get_time_as_double();
	total_time = 0;

	/* Record the boot-time euid before any privilege drop. The spine.conf
	 * owner check in util.c consults this so that a root-owned config
	 * remains valid after drop_root hands the process to a service uid. */
	spine_capture_startup_euid();

	#ifdef HAVE_LCAP
	if (geteuid() == 0) {
		drop_root(getuid(), getgid());
	}
	#endif /* HAVE_LCAP */

	/* we must initialize snmp in the main thread */

	UNUSED_PARAMETER(argc);		/* we operate strictly with argv */

	/* install the spine signal handler */
	install_spine_signal_handler();

	/* install SIGHUP (reload) and SIGTERM (graceful stop) handlers.
	 * Keep this separate from install_spine_signal_handler(), which covers
	 * fatal signals only and shares state with the die() path. */
	spine_install_reload_handler();

	if (spine_platform_init() != 0) {
		die("ERROR: Failed to initialize platform runtime services.");
	}

	/* Name the main thread so ps(1) / top(1) / perf(1) / Process Explorer
	 * distinguish it from worker threads. Must stay under 15 bytes to
	 * survive Linux's pthread_setname_np truncation. */
	spine_platform_set_thread_name("spine-main");

	/* Seed ICMP echo id randomization before any poll thread can fire. */
	ping_init();

	/* establish php processes and initialize space */
	php_processes = (php_t*) calloc(MAX_PHP_SERVERS, sizeof(php_t));
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		php_processes[i].php_state = PHP_BUSY;
	}

	/* create the array of debug devices */
	debug_devices = calloc(MAX_DEBUG_DEVICES, sizeof(int));

	/* initialize icmp_avail */
	set.icmp_avail = TRUE;

	/* initialize number of threads */
	set.threads = 1;
	set.threads_set = FALSE;

	/* detect and compensate for stdin/stderr ttys */
	if (!spine_platform_stdout_is_terminal()) {
		set.stdout_notty = TRUE;
	} else {
		set.stdout_notty = FALSE;
	}

	if (!spine_platform_stderr_is_terminal()) {
		set.stderr_notty = TRUE;
	} else {
		set.stderr_notty = FALSE;
	}

	/* set start time for cacti */
	begin_time = get_time_as_double();

	/* set default verbosity */
	set.log_level = POLLER_VERBOSITY_LOW;

	/* set default log separator */
	set.log_datetime_separator = GDC_DEFAULT;

	/* set default log format */
	set.log_datetime_format = GD_DEFAULT;

	/* set the default exit code */
	set.exit_code = 0;
	set.exit_size = 0;

	/* get static defaults for system */
	config_defaults();

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
	set.poller_id         = 1;
	set.start_host_id     = -1;
	set.end_host_id       = -1;
	set.host_id_list[0]   = '\0';
	set.php_initialized   = FALSE;
	set.logfile_processed = FALSE;
	set.parent_fork       = SPINE_PARENT;
	set.mode              = REMOTE_ONLINE;
	set.has_device_0      = FALSE;
	set.has_output_regex  = FALSE;
	set.health_check      = FALSE;
	set.dump_config       = FALSE;
	set.dry_run           = FALSE;
	set.log_format        = LOGFMT_AUTO;
	set.circuit_breaker_threshold = 0;

	for (argv++; *argv; argv++) {
		char	*arg = *argv;
		char	*opt = strchr(arg, '=');	/* pick off the =VALUE part */

		if (opt) *opt++ = '\0';

		if (STRIMATCH(arg, "-f") || STRMATCH(arg, "--first")) {
			if (HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.start_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: '%s=%s' is invalid first-host ID", arg, opt);
			}
		}

		else if (STRIMATCH(arg, "-l") || STRIMATCH(arg, "--last")) {
			if (HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.end_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: '%s=%s' is invalid last-host ID", arg, opt);
			}
		}

		else if (STRIMATCH(arg, "-p") || STRIMATCH(arg, "--poller")) {
			set.poller_id = atoi(getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-t") || STRIMATCH(arg, "--threads")) {
			set.threads = atoi(getarg(opt, &argv));
			set.threads_set = TRUE;
		}

		else if (STRMATCH(arg, "-P") || STRIMATCH(arg, "--pingonly")) {
			set.ping_only = TRUE;
		}

		else if (STRMATCH(arg, "-N") || STRIMATCH(arg, "--mode")) {
			const char *mode_arg = getarg(opt, &argv);
			if (STRIMATCH(mode_arg, "online")) {
				set.mode = REMOTE_ONLINE;
			} else if (STRIMATCH(mode_arg, "offline")) {
				set.mode = REMOTE_OFFLINE;
			} else if (STRIMATCH(mode_arg, "recovery")) {
				set.mode = REMOTE_RECOVERY;
			} else {
				die("ERROR: invalid polling mode '%s' specified", mode_arg);
			}
		}

		else if (STRIMATCH(arg, "-H") || STRIMATCH(arg, "--hostlist")) {
			snprintf(set.host_id_list, BIG_BUFSIZE, "%s", getarg(opt, &argv));

			/* Validate host_id_list contains only digits and commas */
			{
				const char *p = set.host_id_list;
				while (*p) {
					if (!isdigit((unsigned char)*p) && *p != ',' && *p != ' ') {
						die("ERROR: --hostlist contains invalid characters. Only digits and commas are allowed.");
					}
					p++;
				}
			}
		}

		else if (STRIMATCH(arg, "-M") || STRMATCH(arg, "--mibs")) {
			set.mibs = 1;
		}

		else if (STRIMATCH(arg, "-h") || STRMATCH(arg, "--help")) {
			display_help(FALSE);

			exit(EXIT_SUCCESS);
		}

		else if (STRMATCH(arg, "-v") || STRMATCH(arg, "--version")) {
			display_help(TRUE);

			exit(EXIT_SUCCESS);
		}

		else if (STRIMATCH(arg, "-O") || STRIMATCH(arg, "--option")) {
			char *setting = getarg(opt, &argv);
			char *value   = strchr(setting, ':');

			if (value != NULL && *value) {
				*value++ = '\0';
			} else {
				die("ERROR: -O requires setting:value");
			}

			set_option(setting, value);
		}

		else if (STRIMATCH(arg, "-R") || STRMATCH(arg, "--readonly") || STRMATCH(arg, "--read-only")) {
			set.SQL_readonly = TRUE;
		}

		else if (STRIMATCH(arg, "-C") || STRMATCH(arg, "--conf")) {
			conf_file = strdup(getarg(opt, &argv));
		}

		else if (STRIMATCH(arg, "-S") || STRMATCH(arg, "--stdout")) {
			set_option("log_destination", "STDOUT");
		}

		else if (STRIMATCH(arg, "-D") || STRMATCH(arg, "--log")) {
			set_option("log_destination", getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-V") || STRMATCH(arg, "--verbosity")) {
			set_option("log_verbosity", getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "--check")) {
			set.health_check = TRUE;
		}

		else if (STRMATCH(arg, "--dump-config")) {
			set.dump_config = TRUE;
		}

		else if (STRMATCH(arg, "--dry-run")) {
			set.dry_run = TRUE;
		}

		else if (STRMATCH(arg, "--log-format")) {
			const char *fmt_arg = getarg(opt, &argv);
			if (STRIMATCH(fmt_arg, "auto")) {
				set.log_format = LOGFMT_AUTO;
			} else if (STRIMATCH(fmt_arg, "text")) {
				set.log_format = LOGFMT_TEXT;
			} else if (STRIMATCH(fmt_arg, "json")) {
				set.log_format = LOGFMT_JSON;
			} else {
				die("ERROR: --log-format must be one of auto|text|json (got '%s')", fmt_arg);
			}
		}

		else if (!HOSTID_DEFINED(set.start_host_id) && all_digits(arg)) {
			set.start_host_id = atoi(arg);
		}

		else if (!HOSTID_DEFINED(set.end_host_id) && all_digits(arg)) {
			set.end_host_id = atoi(arg);
		}

		else {
			die("ERROR: %s is an unknown command-line parameter", arg);
		}
	}

	if (set.ping_only) {
		set.mibs = 0;
	}

	/* we require either both the first and last hosts, or neither host */
	if ((HOSTID_DEFINED(set.start_host_id) != HOSTID_DEFINED(set.end_host_id)) &&
		(!strlen(set.host_id_list))) {
		die("ERROR: must provide both -f/-l, a hostlist (-H/--hostlist), or neither");
	}

	if (set.start_host_id > set.end_host_id) {
		die("ERROR: Invalid row spec; first host_id must be less than the second");
	}

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

		for (i=0; i<CONFIG_PATHS; i++) {
			snprintf(conf_file, DBL_BUFSIZE, "%s%s", config_paths[i], DEFAULT_CONF_FILE);

			if (read_spine_config(conf_file) >= 0) {
				valid_conf_file = TRUE;
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, DBL_BUFSIZE, "%s%s", config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	if (!valid_conf_file) {
		die("FATAL: Unable to read configuration file!");
	}

	/* Operational short-circuits. --dump-config prints what we parsed from
	 * spine.conf and exits; --check additionally tries to open a MySQL
	 * connection and a raw ICMP socket, emits JSON, and exits. Both run
	 * before read_config_options() so operators can probe connectivity
	 * without a live settings table. */
	if (set.dump_config) {
		spine_dump_config();
		exit(EXIT_SUCCESS);
	}

	if (set.health_check) {
		mysql_library_init(0, NULL, NULL);
		exit(spine_health_check() ? EXIT_SUCCESS : EXIT_FAILURE);
	}

	if (set.dry_run) {
		SPINE_LOG(("NOTE: --dry-run active; all SQL writes will be logged, not executed"));
	}

	/* read settings table from the database to further establish environment */
	read_config_options();

	spine_cb_init();

	/* set the poller interval for those who use less than 5 minute intervals */
	if (set.poller_interval == 0) {
		set.poller_interval = 300;
	}

	/* tokenize the debug devices */
	if (strlen(set.selective_device_debug)) {
		int debug_idx = 0;
		char *token;
		SPINE_LOG_DEBUG(("DEBUG: Selective Debug Devices %s", set.selective_device_debug));
		token = strtok(set.selective_device_debug, ",");
		while(token && debug_idx < MAX_DEBUG_DEVICES - 1) {
			debug_devices[debug_idx]   = atoi(token);
			debug_devices[debug_idx+1] = '\0';
			token = strtok(NULL, ",");
			debug_idx++;
		}
	} else {
		debug_devices[0] = '\0';
	}

	/* initialize mysql objects for threads */
	mysql_library_init(0, NULL, NULL);

	/* connect for main loop */
	db_connect(LOCAL, &mysql);

	/* setup local connection pool for hosts */
	db_pool_local = (pool_t *) calloc(set.threads, sizeof(pool_t));
	db_create_connection_pool(LOCAL);

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		db_connect(REMOTE, &mysqlr);
		mode = REMOTE;

		/* setup remote connection pool for hosts */
		db_pool_remote = (pool_t *) calloc(set.threads, sizeof(pool_t));
		db_create_connection_pool(REMOTE);
	} else {
		mode = LOCAL;
	}


	/* check for device 0 items */
	result = db_query(&mysql, LOCAL, "SELECT * FROM (SELECT COUNT(*) AS items FROM poller_item WHERE host_id = 0 AND poller_id = 1) AS rs WHERE rs.items > 0");
	if (mysql_num_rows(result)) {
		set.has_device_0 = TRUE;
	}
	db_free_result(result);

	/* check if poller_item has the output_regex column (added in Cacti 1.3.1) */
	if (db_column_exists(&mysql, LOCAL, "poller_item", "output_regex")) {
		set.has_output_regex = TRUE;
		SPINE_LOG_DEBUG(("DEBUG: poller_item.output_regex column detected"));
	}

	/* Since MySQL 5.7 the sql_mode defaults are too strict for cacti */
	db_insert(&mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
	db_insert(&mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		SPINE_LOG_DEBUG(("DEBUG: Version %s starting", VERSION));

		if (set.poller_id > 1) {
			if (mode == REMOTE) {
				SPINE_LOG_DEBUG(("DEBUG: Sending entries to remote database in 'online' mode"));
			} else {
				SPINE_LOG_DEBUG(("DEBUG: Sending entries to local database in 'offline', or 'recovery' mode"));
			}
		}
	} else {
		if (!set.stdout_notty) {
			printf("Version %s starting\n", VERSION);

			if (set.poller_id > 1) {
				if (mode == REMOTE) {
					printf("Sending entries to remote database in 'online' mode\n");
				} else {
					printf("Sending entries to local database in 'offline', or 'recovery' mode\n");
				}
			}
		}
	}

	if (set.has_device_0) {
		SPINE_LOG_MEDIUM(("Device 0 Poller Items found.  Ensure that these entries are accurate"));
	} else {
		SPINE_LOG_MEDIUM(("No Device 0 Poller Items found."));
	}

	/* see if mysql is thread safe */
	if (mysql_thread_safe()) {
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			SPINE_LOG(("DEBUG: MySQL is Thread Safe!"));
		}
	} else {
		SPINE_LOG(("WARNING: MySQL is NOT Thread Safe!"));
	}

	/* test for asroot permissions for ICMP */
	checkAsRoot();

	/* initialize SNMP */
	SPINE_LOG_DEBUG(("DEBUG: Initializing Net-SNMP API"));
	snmp_spine_init();

	/* initialize PHP if required */
	SPINE_LOG_DEBUG(("DEBUG: Initializing PHP Script Server(s)"));

	/* tell spine that it is parent, and set the poller id */
	set.parent_fork = SPINE_PARENT;

	/* initialize the script server */
	if (set.php_required && !set.ping_only) {
		php_init(PHP_INIT);
		set.php_initialized    = TRUE;
		set.php_current_server = 0;
	}

	/* Opt-in sandbox activation. DB, SNMP, PHP script servers, and the log
	 * file are all open at this point, so the remaining syscall/path surface
	 * is bounded. The gate stays opt-in because a too-narrow allowlist would
	 * break site-specific poll scripts that exec unexpected binaries. */
	if (getenv("SPINE_SANDBOX") != NULL) {
		const char *scripts_dir = NULL;
#ifdef CACTI_SCRIPTS_PATH
		scripts_dir = CACTI_SCRIPTS_PATH;
#endif
		spine_sandbox_unveil_paths(set.path_logfile, NULL, scripts_dir);
		spine_sandbox_restrict();
	}

	/* obtain the list of hosts to poll */
	{
		int remaining = MEGA_BUFSIZE - (qp - querybuf);
		qp += snprintf(qp, remaining, "SELECT SQL_NO_CACHE id, device_threads, picount, picount/device_threads AS tppi FROM host AS h LEFT JOIN (SELECT host_id, COUNT(*) AS picount FROM poller_item GROUP BY host_id) AS pi ON h.id = pi.host_id");
		remaining = MEGA_BUFSIZE - (qp - querybuf);
		qp += snprintf(qp, remaining, " WHERE disabled = ''");

		remaining = MEGA_BUFSIZE - (qp - querybuf);
		qp += snprintf(qp, remaining, " AND availability_method != %d", AVAIL_STREAM);

		if (!strlen(set.host_id_list)) {
			qp += append_hostrange(qp, "h.id");	/* AND id BETWEEN a AND b */
		} else {
			remaining = MEGA_BUFSIZE - (qp - querybuf);
			qp += snprintf(qp, remaining, " AND h.id IN(%s)", set.host_id_list);
		}

		remaining = MEGA_BUFSIZE - (qp - querybuf);
		qp += snprintf(qp, remaining, " AND h.poller_id = %i", set.poller_id);
		remaining = MEGA_BUFSIZE - (qp - querybuf);
		qp += snprintf(qp, remaining, " ORDER BY picount DESC");
	}

	SPINE_LOG_DEVDBG(("DEVDBG: Host SQL:%s", querybuf));
	result = db_query(&mysql, LOCAL, querybuf);

	if (set.poller_id == 1) {
		if (set.has_device_0) {
			num_rows = mysql_num_rows(result) + 1; /* pollerid 1 takes care of non host based data sources */
		} else {
			num_rows = mysql_num_rows(result); /* pollerid 1 takes care of non host based data sources */
		}
	} else {
		num_rows = mysql_num_rows(result);
	}

	if (num_rows > 0) {
		if (!(threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t)))) {
			die("ERROR: Fatal malloc error: spine.c threads!");
		}

		if (!(details = (poller_thread_t **)malloc(num_rows * sizeof(poller_thread_t*)))) {
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

	/* mark the spine process as started */
	if (!set.ping_only) {
		snprintf(querybuf, BIG_BUFSIZE, "INSERT INTO poller_time (poller_id, pid, start_time, end_time) VALUES (%i, %lu, NOW(), '0000-00-00 00:00:00')", set.poller_id, spine_platform_process_id());
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

	/* initialize available_threads semaphore */
	spine_sem_init(&available_threads, set.threads);

	/* initialize available_scripts semaphore */
	spine_sem_init(&available_scripts, MAX_SIMULTANEOUS_SCRIPTS);

	/* initialize thread initialization semaphore */
	spine_sem_init(&thread_init_sem, 1);

	/* specify the point of timeout for timedwait semaphores */
	//until_spec.tv_sec = (time_t)(set.poller_interval + begin_time - 0.2);
	//until_spec.tv_nsec = 0;

	spine_sem_getvalue(&available_threads, &a_threads_value);
	SPINE_LOG_HIGH(("DEBUG: Initial Value of Available Threads is %i (%i outstanding)", a_threads_value, set.threads - a_threads_value));

	/* tell fork processes that they are now active */
	set.parent_fork = SPINE_FORK;

	/* initialize the threading code */
	device_threads   = 1;
	current_thread   = 0;

	/* poller 1 always polls host 0 but only if it exists */
	if (set.poller_id == 1 && set.has_device_0 == TRUE) {
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

	/* Notify systemd that spine is fully initialised. Safe no-op when not
	 * running under systemd or when libsystemd was not linked. */
	spine_sd_ready();
	spine_sd_status("Polling %d device%s with %d thread%s",
	                num_rows, num_rows == 1 ? "" : "s",
	                set.threads, set.threads == 1 ? "" : "s");

	/* loop through devices until done */
	while (canexit == FALSE && device_counter < num_rows) {
		/* Systemd watchdog ping. sd_notify() short-circuits when
		 * NOTIFY_SOCKET is unset so this stays cheap on cron/non-systemd
		 * invocations. */
		spine_sd_watchdog();

		/* Graceful stop requested (SIGTERM from systemd or operator).
		 * Break out between devices so in-flight threads can drain. */
		if (spine_stop_requested) {
			SPINE_LOG(("NOTE: SIGTERM received, stopping after current device"));
			spine_sd_stopping("SIGTERM received");
			canexit = TRUE;
			break;
		}

		/* Config reload requested (SIGHUP). We re-read spine.conf between
		 * devices so log path and SNMP client address changes take effect
		 * without restarting the daemon. Database credentials are replayed
		 * into set.db_* but the existing MYSQL handles stay attached until
		 * the next cycle; reconnecting a busy pool mid-loop would tear down
		 * worker threads. Operators needing a DB host swap should restart. */
		if (spine_reload_requested) {
			spine_reload_requested = 0;
			spine_sd_reloading();

			if (conf_file && read_spine_config(conf_file) >= 0) {
				SPINE_LOG(("NOTE: SIGHUP received; reloaded spine.conf [%s]", conf_file));
			} else {
				SPINE_LOG(("WARNING: SIGHUP received; failed to reload spine.conf"));
			}

			spine_sd_ready();
		}

		int loop_count = 0;
		double progress_time = 0;
		int sem_err = 0;
		int spine_timeout = FALSE;

		if (change_host) {
			mysql_row       = mysql_fetch_row(result);
			host_id         = atoi(mysql_row[0]);
			device_threads  = atoi(mysql_row[1]);
			current_thread  = 1;

			if (device_threads < 1) {
				device_threads = 1;
			}
		} else {
			current_thread++;
		}

		/* adjust device threads in cases where the host does not have sufficient data sources */
		if (!set.ping_only) {
			if (set.active_profiles != 1) {
				snprintf(querybuf, BIG_BUFSIZE, "SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item WHERE host_id=%i AND rrd_next_step <=0", host_id);
			} else {
				snprintf(querybuf, BIG_BUFSIZE, "SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item WHERE host_id=%i", host_id);
			}

			tresult   = db_query(&mysql, LOCAL, querybuf);
			mysql_row = mysql_fetch_row(tresult);

			total_items = atoi(mysql_row[0]);
			db_free_result(tresult);

			if (total_items && total_items < device_threads) {
				device_threads = total_items;
			}
		} else {
			device_threads = 1;
		}

		change_host = (current_thread >= device_threads) ? TRUE : FALSE;

		/* determine how many items will be polled per thread */
		if (device_threads > 1) {
			if (current_thread == 1) {
				if (set.active_profiles != 1) {
					snprintf(querybuf, BIG_BUFSIZE, "SELECT SQL_NO_CACHE CEIL(COUNT(local_data_id)/%i) FROM poller_item WHERE host_id=%i AND rrd_next_step <=0", device_threads, host_id);
				} else {
					snprintf(querybuf, BIG_BUFSIZE, "SELECT SQL_NO_CACHE CEIL(COUNT(local_data_id)/%i) FROM poller_item WHERE host_id=%i", device_threads, host_id);
				}

				tresult   = db_query(&mysql, LOCAL, querybuf);
				mysql_row = mysql_fetch_row(tresult);

				items_per_thread = atoi(mysql_row[0]);

				db_free_result(tresult);

				snprintf(host_time, SMALL_BUFSIZE, "%lu", (unsigned long) time(NULL));
				host_time_double = get_time_as_double();
			} else if (host_time_double == 0 || host_time == 0 || host_time == NULL) {
				snprintf(host_time, SMALL_BUFSIZE, "%lu", (unsigned long) time(NULL));
				host_time_double = get_time_as_double();
			}
		} else {
			snprintf(querybuf, BIG_BUFSIZE, "SELECT SQL_NO_CACHE COUNT(local_data_id) FROM poller_item WHERE host_id=%i AND rrd_next_step <=0", host_id);
			tresult   = db_query(&mysql, LOCAL, querybuf);
			mysql_row = mysql_fetch_row(tresult);

			items_per_thread = atoi(mysql_row[0]);

			db_free_result(tresult);

			snprintf(host_time, SMALL_BUFSIZE, "%lu", (unsigned long) time(NULL));
			host_time_double = get_time_as_double();
		}

		/* populate the thread structure */
		if (!(poller_details = (poller_thread_t *)malloc(sizeof(poller_thread_t)))) {
			die("ERROR: Fatal malloc error: spine.c poller_details!");
		}

		poller_details->device_counter   = device_counter;
		poller_details->host_id          = host_id;
		poller_details->host_thread      = current_thread;
		poller_details->host_threads     = device_threads;
		poller_details->host_data_ids    = items_per_thread;

		snprintf(poller_details->host_time, 40, "%s", host_time);

		poller_details->host_time_double = host_time_double;
		poller_details->thread_init_sem  = &thread_init_sem;
		poller_details->complete         = FALSE;
		poller_details->threads_complete = 0;

		thread_mutex_lock(LOCK_THDET);
		details[device_counter] = poller_details;
		thread_mutex_unlock(LOCK_THDET);

		/* dev note - errno was never primed at this point in previous version of code */
		loop_count = 0;
		progress_time = 0;
		sem_err = 0;
		spine_timeout = FALSE;

		while (TRUE) {
			sem_err = spine_sem_trywait(&available_threads);

			if (sem_err == 0) {
				/* acquired a thread */
				break;
			} else if (errno == EINTR) {
				/* interrupted by signal handler */
			} else if (errno == EDEADLK) {
				SPINE_LOG_DEVDBG(("WARNING: Device[%i] HT[%i] would have deadlocked acquiring Available Thread Lock", host_id, current_thread));
			} else if (errno == EAGAIN) {
				/* keep trying */
			}

			loop_count++;

			if (loop_count == 10) {
				progress_time = get_time_as_double() - start_time;

				if (progress_time + 1 > set.poller_interval) {
					SPINE_LOG(("ERROR: Device[%i] HT[%i] polling timed out while acquiring Available Thread Lock", host_id, current_thread));
					spine_timeout = TRUE;
					break;
				}

				loop_count = 0;
			}

			spine_platform_sleep_us(10000);

			total_time = get_time_as_double();

			if (total_time - start_time > set.poller_interval) {
				SPINE_LOG(("ERROR: Device[%i] HT[%i] Spine Timed Out While Processing Devices External", host_id, current_thread));
				spine_timeout = TRUE;
				canexit = TRUE;
				break;
			}
		}

		loop_count = 0;

		while (!spine_timeout) {
			sem_err = spine_sem_trywait(&thread_init_sem);

			if (sem_err == 0) {
				// Acquired a thread
				break;
			} else if (sem_err == EINTR) {
				// Interrupted by signal handler
			} else if (sem_err == EDEADLK) {
				SPINE_LOG_DEVDBG(("WARNING: Device[%i] HT[%i] would have deadlocked acquiring Thread Initialization Lock", host_id, current_thread));
			} else if (sem_err == EAGAIN) {
				// Keep trying
			} else {
				SPINE_LOG_DEVDBG(("WARNING: Device[%i] HT[%i] errored with %d while acquiring Thread Initialization Lock", host_id, current_thread, sem_err));
			}

			if (loop_count == 10) {
				progress_time = get_time_as_double() - start_time;

				if (progress_time + 1 > set.poller_interval) {
					SPINE_LOG(("ERROR: Device[%i] HT[%i] polling timed out while acquiring Thread Init Lock", host_id, current_thread));
					spine_timeout = TRUE;
					break;
				}

				loop_count = 0;
			}

			spine_platform_sleep_us(10000);

			total_time = get_time_as_double();

			if (total_time - start_time > set.poller_interval) {
				SPINE_LOG(("ERROR: Device[%i] HT[%i] Spine Timed Out While Processing Devices Internal", host_id, current_thread));
				spine_timeout = TRUE;
				canexit = TRUE;
				break;
			}
		}

		if (!spine_timeout) {
			/* create child process */
			thread_retry:

			thread_mutex_lock(LOCK_HOST_TIME);

			thread_status = pthread_create(&threads[device_counter], &attr, child, poller_details);

			if (thread_status == 0) {
				SPINE_LOG_DEBUG(("DEBUG: Device[%i] Valid Thread to be Created (%ld)", poller_details->host_id, (unsigned long int)threads[device_counter]));

				if (change_host) {
					device_counter++;
				}

				spine_sem_getvalue(&available_threads, &a_threads_value);
				SPINE_LOG_HIGH(("DEBUG: Device[%i] Available Threads is %i (%i outstanding)", poller_details->host_id, a_threads_value, set.threads - a_threads_value));

				spine_sem_post(&thread_init_sem);

				SPINE_LOG_DEVDBG(("DEBUG: DTS: device = %d, host_id = %d, host_thread = %d,"
					" host_threads = %d, host_data_ids = %d, complete = %d",
					device_counter-1,
					poller_details->host_id,
					poller_details->host_thread,
					poller_details->host_threads,
					poller_details->host_data_ids,
					poller_details->complete));
			} else if (thread_status == EAGAIN) {
				thread_mutex_unlock(LOCK_HOST_TIME);
				spine_platform_sleep_us(10000);
				goto thread_retry;
			} else if (thread_status == EINVAL) {
				SPINE_LOG(("ERROR: The Thread Attribute is Not Initialized"));
			}

			/* Restore thread initialization semaphore if thread creation failed */
			if (thread_status) {
				thread_mutex_unlock(LOCK_HOST_TIME);
				spine_sem_post(&thread_init_sem);
			}
		}
	}

	spine_sem_getvalue(&available_threads, &a_threads_value);

	/* wait for all threads to 'complete'
 	 * using the mutex here as the semaphore will
     * show zero before the children are done.
     *
     * SIGTERM shortens the deadline to SPINE_SIGTERM_DRAIN_SECS so systemd's
     * TimeoutStopSec (90s default) is satisfied with margin. On the normal
     * path the existing poller_interval deadline still applies. */
	const int SPINE_SIGTERM_DRAIN_SECS = 30;
	double drain_deadline = begin_time + set.poller_interval;
	if (spine_stop_requested) {
		double sigterm_deadline = get_time_as_double() + SPINE_SIGTERM_DRAIN_SECS;
		if (sigterm_deadline < drain_deadline) {
			drain_deadline = sigterm_deadline;
		}
	}

	while (a_threads_value < set.threads) {
		cur_time = get_time_as_double();

		if (cur_time > drain_deadline) {
			SPINE_LOG(("ERROR: Polling timed out while waiting for %d Threads to End", set.threads - a_threads_value));
			break;
		}

		/* If SIGTERM arrived while we were inside this loop, tighten the
		 * deadline now. The check is intentionally one-way: we never extend
		 * a shorter deadline back out. */
		if (spine_stop_requested) {
			double sigterm_deadline = get_time_as_double() + SPINE_SIGTERM_DRAIN_SECS;
			if (sigterm_deadline < drain_deadline) {
				drain_deadline = sigterm_deadline;
			}
		}

		SPINE_LOG_HIGH(("NOTE: Polling sleeping while waiting for %d Threads to End", set.threads - a_threads_value));
		spine_platform_sleep_us(500000);
		spine_sem_getvalue(&available_threads, &a_threads_value);
	}

	threads_final = set.threads - a_threads_value;

	SPINE_LOG_HIGH(("The final count of Threads is %i", threads_final));

	if (!set.ping_only) {
		thread_mutex_lock(LOCK_THDET);

		for (threads_count = 0; threads_count < num_rows; threads_count++) {
			poller_thread_t* det = details[threads_count];

			if (threads_missing == -1 && det == NULL) {
				threads_missing = threads_count;
			}

			if (det != NULL) { // && !det->complete) {
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
	}

	if (threads_missing > -1) {
		SPINE_LOG(("WARNING: There were %d threads which did not run", num_rows - threads_missing));
	}

	/* tell Spine that it is now parent */
	set.parent_fork = SPINE_PARENT;

	/* push data back to the main server */
	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE && !set.SQL_readonly) {
		poller_push_data_to_main();
	}

	/* update the db for |data_time| on graphs */
	if (!set.ping_only) {
		if (set.poller_id == 1) {
			db_insert(&mysql, LOCAL, "REPLACE INTO settings (name,value) VALUES ('date',NOW())");
		}

		snprintf(querybuf, BIG_BUFSIZE, "UPDATE poller_time SET end_time=NOW() WHERE poller_id=%i AND pid=%lu", set.poller_id, spine_platform_process_id());

		if (mode == REMOTE) {
			db_insert(&mysqlr, REMOTE, querybuf);
		} else {
			db_insert(&mysql, LOCAL, querybuf);
		}
	}

	if (db_pool_local) {
		db_close_connection_pool(LOCAL);
	}

	if (db_pool_remote) {
		db_close_connection_pool(REMOTE);
	}

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);

	SPINE_LOG_DEBUG(("DEBUG: Thread Cleanup Complete"));

	/* close the php script server */
	if (set.php_required && !set.ping_only) {
		php_close(PHP_INIT);
	}

	SPINE_LOG_DEBUG(("DEBUG: PHP Script Server Pipes Closed"));

	/* free malloc'd variables */
	for (i = 0; i < num_rows; i++) {
		if (details[i] != NULL) {
			SPINE_FREE(details[i]);
		}
	}

	SPINE_FREE(details);
	SPINE_FREE(threads);
	SPINE_FREE(ids);
	SPINE_FREE(conf_file);
	SPINE_FREE(host_time);
	SPINE_FREE(php_processes);

	SPINE_LOG_DEBUG(("DEBUG: Allocated Variable Memory Freed"));

	/* close mysql */
	db_free_result(result);
	db_disconnect(&mysql);

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		db_disconnect(&mysqlr);
	}

	SPINE_LOG_DEBUG(("DEBUG: MYSQL Free & Close Completed"));

	/* close snmp */
	snmp_spine_close();

	SPINE_LOG_DEBUG(("DEBUG: Net-SNMP Close Completed"));

	/* finally add some statistics to the log and exit */
	end_time = get_time_as_double();

	if (set.log_level >= POLLER_VERBOSITY_MEDIUM) {
		SPINE_LOG(("Time: %.4f s, Threads: %i, Devices: %i", (end_time - begin_time), set.threads, num_rows));
	} else {
		/* provide output if running from command line */
		if (!set.stdout_notty) {
			fprintf(stdout, "Time: %.4f s, Threads: %i, Devices: %i\n", (end_time - begin_time), set.threads, num_rows);
		}
	}

	/* zero sensitive credentials before exit */
	{
		volatile char *vp;
		vp = (volatile char *)set.db_pass;
		memset((char *)vp, 0, sizeof(set.db_pass));
		vp = (volatile char *)set.rdb_pass;
		memset((char *)vp, 0, sizeof(set.rdb_pass));
	}

	spine_cb_shutdown();

	/* Tell systemd we are stopping. Sent before the final cleanup so the
	 * unit never sits in "stopping" state waiting for STOPPING=1. */
	spine_sd_stopping("Poll cycle complete");

	/* uninstall the spine signal handler */
	uninstall_spine_signal_handler();

	spine_platform_cleanup();

	exit(EXIT_SUCCESS);
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
		"  --check            DB + ICMP reachability probe; prints JSON and exits",
		"  --dump-config      Print effective merged configuration and exit",
		"  --dry-run          Run one poll cycle with DB and RRD writes skipped",
		"  --log-format=F     Log format: auto (default), text, or json",
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
