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

char *load_startup_configuration(char *conf_file) {
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

		for (int i = 0; i < CONFIG_PATHS; i++) {
			snprintf(conf_file, DBL_BUFSIZE, "%.*s%s", (int) sizeof(config_paths[i]) - 1, config_paths[i], DEFAULT_CONF_FILE);

			if (read_spine_config(conf_file) >= 0) {
				valid_conf_file = TRUE;
				break;
			}

			if (i == CONFIG_PATHS - 1) {
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

void report_startup(int mode) {
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

double initialize_process_defaults(void) {
	double begin_time;
	/* establish php processes and initialize space */
	php_processes = calloc(MAX_PHP_SERVERS, sizeof(*php_processes));
	if (php_processes == NULL) die("ERROR: Fatal calloc error: spine.c php_processes!");
	php_processes_initialize(php_processes, MAX_PHP_SERVERS);

	/* create the array of debug devices */
	debug_devices = calloc(MAX_DEBUG_DEVICES, sizeof(*debug_devices));
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

int initialize_main_database(MYSQL *mysql, MYSQL *mysqlr) {
	MYSQL_RES *result;
	int mode;
	int has_output_regex;
	/* initialize mysql objects for threads */
	mysql_library_init(0, NULL, NULL);

	/* connect for main loop */
	if (!db_connect(LOCAL, mysql)) die("FATAL: Unable to connect to the local database");

	/* setup local connection pool for hosts */
	db_pool_local = calloc(set.poller.threads, sizeof(*db_pool_local));
	if (db_pool_local == NULL) die("ERROR: Fatal calloc error: spine.c db_pool_local!");
	db_create_connection_pool(LOCAL);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		if (!db_connect(REMOTE, mysqlr)) die("FATAL: Unable to connect to the remote database");
		mode = REMOTE;

		/* setup remote connection pool for hosts */
		db_pool_remote = calloc(set.poller.threads, sizeof(*db_pool_remote));
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

void initialize_main_php(void) {
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
		set.php.php_initialized = TRUE;
		set.php.php_current_server = 0;
	}
}



void close_main_php(void) {
	/* close the php script server */
	if (set.php.php_required && !set.availability.ping_only) php_close(PHP_INIT);

	SPINE_LOG_DEBUG(("DEBUG: PHP Script Server Pipes Closed"));
}

void report_poll_statistics(double begin_time, int num_rows) {
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
