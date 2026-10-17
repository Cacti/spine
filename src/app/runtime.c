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
#include "app/runtime.h"
#include "app/startup_internal.h"
#include <limits.h>


/* Global Variables */
int entries = 0;
int num_hosts = 0;
spine_permits_t available_threads;
spine_permits_t available_scripts;
double start_time;
double total_time;

config_t set;
php_t *php_processes = NULL;
char config_paths[CONFIG_PATHS][BUFSIZE];
int *debug_devices;

pool_t *db_pool_local;
pool_t *db_pool_remote;

poller_thread_t **details = NULL;

#include "app/cli_internal.h"

_Noreturn void spine_run(int argc, char *argv[]) {
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

	pthread_t *threads = NULL;
	pthread_attr_t attr;

	int *ids = NULL;
	int mode = REMOTE;
	MYSQL mysql;
	MYSQL mysqlr;
	MYSQL_RES *result = NULL;
	int threads_final = 0;


	UNUSED_PARAMETER(argc); /* we operate strictly with argv */

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
	set.poller.poller_id = 1;
	set.hosts.start_host_id = -1;
	set.hosts.end_host_id = -1;
	set.hosts.host_id_list[0] = '\0';
	set.php.php_initialized = FALSE;
	set.logging.logfile_processed = FALSE;
	set.poller.parent_fork = SPINE_PARENT;
	set.poller.mode = REMOTE_ONLINE;
	set.hosts.has_device_0 = FALSE;
	set.hosts.has_output_regex = FALSE;

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
	if (spine_thread_attr_init(&attr) != 0 ||
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to initialize polling thread attributes");
	}

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
