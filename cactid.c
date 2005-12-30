/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 *	Provide the name of the Cactid configuration file, which contains
 *	the parameters for connecting to the database. In the absense of
 *	this, it looks [WHERE?]
 *
 * -f | --first=ID
 *
 *	Start polling with device <ID> (else starts at the beginning)
 *
 * -l | --last=ID
 *
 *	Stop polling after device <ID> (else ends with the last one)
 *
 * -O | --option=setting:value
 *
 *	Override a DB-provided value from the settings table in the DB.
 *
 * -C | -conf=FILE
 *
 *	Specify the location of the Cactid configuration file.
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
 * duties across multiple "cactid" instances: each one gets a subset of
 * the polling range.
 *
 * For compatibility with poller.php, we also accept the first and last
 * device IDs as standalone parameters on the command line.
*/

#include "common.h"
#include "cactid.h"
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <assert.h>
#include "poller.h"
#include "locks.h"
#include "snmp.h"
#include "php.h"
#include "sql.h"
#include "util.h"
#include "nft_popen.h"

/* Global Variables */
int entries = 0;
int num_hosts = 0;
int active_threads = 0;

config_t set;
php_t	*php_processes = 0;
char	 start_datetime[20];
char	 config_paths[CONFIG_PATHS][BUFSIZE];

static char *getarg(char *opt, char ***pargv);
static void display_help(void);

/*! \fn main(int argc, char *argv[])
 *  \brief The Cactid program entry point
 *  \param argc The number of arguments passed to the function plus one (+1)
 *  \param argv An array of the command line arguments
 *
 *  The Cactid entry point.  This function performs the following tasks.
 *  1) Processes command line input parameters
 *  2) Processes the Cactid configuration file to obtain database access information
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
	struct timeval now;
	char *conf_file = NULL;
	double begin_time, end_time, current_time;
	int poller_interval;
	int num_rows;
	int device_counter = 0;
	int poller_counter = 0;
	int last_active_threads = 0;
	long int EXTERNAL_THREAD_SLEEP = 100000;
	long int internal_thread_sleep;
	time_t nowbin;
	struct tm now_time;
	struct tm *now_ptr;

	pthread_t* threads = NULL;
	pthread_attr_t attr;

	int* ids = NULL;
	MYSQL mysql;
	MYSQL_RES *result = NULL;
	MYSQL_ROW mysql_row;
	int canexit = 0;
	int host_id;
	int i;
	int mutex_status = 0;
	int thread_status = 0;

	/* establish php processes and initialize space */
	php_processes = (php_t*) calloc(MAX_PHP_SERVERS, sizeof(php_t));
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		php_processes[i].php_state = PHP_BUSY;
	}

	/* set start time for cacti */
	gettimeofday(&now, NULL);
	begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	/* get time for poller_output table */
	if (time(&nowbin) == (time_t) - 1) {
		die("ERROR: Could not get time of day from time()\n");
	}
	localtime_r(&nowbin,&now_time);
	now_ptr = &now_time;

	if (strftime(start_datetime, sizeof(start_datetime), "%Y-%m-%d %H:%M:%S", now_ptr) == (size_t) 0) {
		die("ERROR: Could not get string from strftime()\n");
	}

	/* set default verbosity */
	set.log_level = POLLER_VERBOSITY_LOW;

	/* get static defaults for system */
	config_defaults(&set);

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

	#define MATCH(a, b)	(strcasecmp((a),(b)) == 0)

	/* initialize some global variables */
	set.start_host_id = -1;
	set.end_host_id   = -1;
	set.php_initialized = FALSE;
	set.logfile_processed = FALSE;
	set.parent_fork = CACTID_PARENT;

	for (argv++; *argv; argv++) {
		char	*arg = *argv;
		char	*opt = strchr(arg, '=');	/* pick off the =VALUE part */

		if (opt) *opt++ = '\0';

		if (MATCH(arg, "-f") ||
			MATCH(arg, "--first")) {
			if (HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.start_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: '%s=%s' is invalid first-host ID", arg, opt);
			}
		}

		else if (MATCH(arg, "-l") ||
				 MATCH(arg, "--last")) {
			if (HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.end_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: '%s=%s' is invalid last-host ID", arg, opt);
			}
		}

		else if (MATCH(arg, "-p") ||
				 MATCH(arg, "--poller")) {
			set.poller_id = atoi(getarg(opt, &argv));
		}

		else if (MATCH(arg, "-h") ||
				 MATCH(arg, "-v") ||
				 MATCH(arg, "--help") ||
				 MATCH(arg, "--version")) {
			display_help();

			exit(0);
		}

		else if (MATCH(arg, "-O") ||
				 MATCH(arg, "--option")) {
			char	*setting = getarg(opt, &argv);
			char	*value   = strchr(setting, ':');

			if (*value) {
				*value++ = '\0';
			}else{
				die("ERROR: -O requires setting:value");
			}

			set_option(setting, value);
		}

		else if (MATCH(arg, "-R") ||
				 MATCH(arg, "--readonly") ||
				 MATCH(arg, "--read-only")) {
			set.SQL_readonly = TRUE;
		}

		else if (MATCH(arg, "-C") ||
				 MATCH(arg, "--conf")) {
			conf_file = strdup(getarg(opt, &argv));
		}

		else if (MATCH(arg, "-S") ||
				 MATCH(arg, "--stdout")) {
			set_option("log_destination", "STDOUT");
		}

		else if (MATCH(arg, "-L") ||
				 MATCH(arg, "--log")) {
			set_option("log_destination", getarg(opt, &argv));
		}

		else if (MATCH(arg, "-V") ||
				 MATCH(arg, "--verbosity")) {
			set_option("log_verbosity", getarg(opt, &argv));
		}

		else if (MATCH(arg, "--snmponly") ||
				 MATCH(arg, "--snmp-only")) {
			set.snmponly = TRUE;
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

	#undef MATCH

	/* we require either both the first and last hosts, or niether host */
	if (HOSTID_DEFINED(set.start_host_id) != HOSTID_DEFINED(set.end_host_id)) {
		die("ERROR: must provide both -f/-l, or neither");
	}

	if (set.start_host_id > set.end_host_id) {
		die("ERROR: Invalid row spec; first host_id must be less than the second");
	}

	/* read configuration file to establish local environment */
	if (conf_file) {
		if ((read_cactid_config(conf_file, &set)) < 0) {
			die("ERROR: Could not read config file: %s\n", conf_file);
		}
	}else{
		if (!(conf_file = calloc(1, BUFSIZE))) {
			die("ERROR: Fatal malloc error: cactid.c conf_file!\n");
		}

		for (i=0; i<CONFIG_PATHS; i++) {
			snprintf(conf_file, BUFSIZE-1, "%s%s", config_paths[i], DEFAULT_CONF_FILE);

			if (read_cactid_config(conf_file, &set) >= 0) {
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, BUFSIZE-1, "%s%s", config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	/* read settings table from the database to further establish environment */
	read_config_options(&set);

	/* set the poller interval for those who use less than 5 minute intervals */
	if (set.poller_interval == 0) {
		poller_interval = 300;
	}else {
		poller_interval = set.poller_interval;
	}

	/* calculate the external_tread_sleep value */
	internal_thread_sleep = EXTERNAL_THREAD_SLEEP * set.num_parent_processes / 2;

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("CACTID: Version %s starting\n", VERSION);
	}else{
		printf("CACTID: Version %s starting\n", VERSION);
	}

	/* connect to database */
	db_connect(set.dbdb, &mysql);

	/* initialize SNMP */
	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("CACTID: Initializing Net-SNMP API\n");
	}
	snmp_cactid_init();

	/* initialize PHP if required */
	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("CACTID: Initializing PHP Script Server\n");
	}

	/* tell cactid that it is parent, and set the poller id */
	set.parent_fork = CACTID_PARENT;
	set.poller_id = 0;

	/* initialize the script server */
	if (set.php_required) {
		php_init(PHP_INIT);
		set.php_initialized = TRUE;
		set.php_current_server = 0;
	}

	/* obtain the list of hosts to poll */
	{
	char querybuf[256], *qp = querybuf;

	qp += sprintf(qp, "SELECT id FROM host");
	qp += sprintf(qp, " WHERE disabled=''");
	qp += append_hostrange(qp, "id", &set);	/* AND id BETWEEN a AND b */
	qp += sprintf(qp, " ORDER BY id");

	result = db_query(&mysql, querybuf);
	}

	num_rows = mysql_num_rows(result) + 1; /* add 1 for host = 0 */

	if (!(threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t)))) {
		die("ERROR: Fatal malloc error: cactid.c threads!\n");
	}

	if (!(ids = (int *)malloc(num_rows * sizeof(int)))) {
		die("ERROR: Fatal malloc error: cactid.c host id's!\n");
	}

	/* initialize threads and mutexes */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Initial Value of Active Threads is %i\n", active_threads);
	}

	/* tell fork processes that they are now active */
	set.parent_fork = CACTID_FORK;

	/* loop through devices until done */
	while ((device_counter < num_rows) && (canexit == 0)) {
		mutex_status = thread_mutex_trylock(LOCK_THREAD);

		switch (mutex_status) {
		case 0:
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			while ((active_threads < set.threads) && (device_counter < num_rows)) {
				if (device_counter > 0) {
					mysql_row = mysql_fetch_row(result);
					host_id = atoi(mysql_row[0]);
					ids[device_counter] = host_id;
				}else{
					ids[device_counter] = 0;
				}

				/* create child process */
				thread_status = pthread_create(&threads[device_counter], &attr, child, &ids[device_counter]);

				switch (thread_status) {
					case 0:
						if (set.log_level == POLLER_VERBOSITY_DEBUG) {
							cacti_log("DEBUG: Valid Thread to be Created\n");
						}

						device_counter++;
						active_threads++;

						if (set.log_level == POLLER_VERBOSITY_DEBUG) {
							cacti_log("DEBUG: The Value of Active Threads is %i\n", active_threads);
						}

						break;
					case EAGAIN:
						cacti_log("ERROR: The System Lacked the Resources to Create a Thread\n");
						break;
					case EFAULT:
						cacti_log("ERROR: The Thread or Attribute Was Invalid\n");
						break;
					case EINVAL:
						cacti_log("ERROR: The Thread Attribute is Not Initialized\n");
						break;
					default:
						cacti_log("ERROR: Unknown Thread Creation Error\n");
						break;
				}
				usleep(internal_thread_sleep);

				/* get current time and exit program if time limit exceeded */
				if (poller_counter >= 20) {
					gettimeofday(&now, NULL);
					current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

					if ((current_time - begin_time + 6) > poller_interval) {
						cacti_log("ERROR: Cactid Timed Out While Processing Hosts Internal\n");
						canexit = 1;
						break;
					}

					poller_counter = 0;
				}else{
					poller_counter++;
				}
			}

			thread_mutex_unlock(LOCK_THREAD);

			break;
		case EDEADLK:
			cacti_log("ERROR: Deadlock Occured\n");
			break;
		case EBUSY:
			break;
		case EINVAL:
			cacti_log("ERROR: Attempt to Unlock an Uninitialized Mutex\n");
			break;
		case EFAULT:
			cacti_log("ERROR: Attempt to Unlock an Invalid Mutex\n");
			break;
		default:
			cacti_log("ERROR: Unknown Mutex Lock Error Code Returned\n");
			break;
		}

		usleep(internal_thread_sleep);

		/* get current time and exit program if time limit exceeded */
		if (poller_counter >= 20) {
			gettimeofday(&now, NULL);
			current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			if ((current_time - begin_time + 6) > poller_interval) {
				cacti_log("ERROR: Cactid Timed Out While Processing Hosts Internal\n");
				canexit = 1;
				break;
			}

			poller_counter = 0;
		}else{
			poller_counter++;
		}
	}

	/* wait for all threads to complete */
	while (canexit == 0) {
		if (thread_mutex_trylock(LOCK_THREAD) == 0) {
			if (last_active_threads != active_threads) {
				last_active_threads = active_threads;
			}

			if (active_threads == 0) {
				canexit = 1;
			}

			thread_mutex_unlock(LOCK_THREAD);
		}

		usleep(EXTERNAL_THREAD_SLEEP);

		/* get current time and exit program if time limit exceeded */
		if (poller_counter >= 20) {
			gettimeofday(&now, NULL);
			current_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			if ((current_time - begin_time + 6) > poller_interval) {
				cacti_log("ERROR: Cactid Timed Out While Processing Hosts Internal\n");
				canexit = 1;
				break;
			}

			poller_counter = 0;
		}else{
			poller_counter++;
		}
	}

	/* tell Cactid that it is now parent */
	set.parent_fork = CACTID_PARENT;

	/* print out stats */
	gettimeofday(&now, NULL);

	/* update the db for |data_time| on graphs */
	db_insert(&mysql, "replace into settings (name,value) values ('date',NOW())");
	db_insert(&mysql, "insert into poller_time (poller_id, start_time, end_time) values (0, NOW(), NOW())");

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Thread Cleanup Complete\n");
	}

	/* close the php script server */
	if (set.php_required) {
		php_close(PHP_INIT);
	}

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: PHP Script Server Pipes Closed\n");
	}

	/* free malloc'd variables */
	free(threads);
	free(ids);
	free(conf_file);

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: Allocated Variable Memory Freed\n");
	}

	/* shutdown SNMP */
	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("CACTID: Shutting down Net-SNMP API\n");
	}
	snmp_cactid_close();

	/* close mysql */
	mysql_free_result(result);
	mysql_close(&mysql);

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: MYSQL Free & Close Completed\n");
	}

	/* finally add some statistics to the log and exit */
	end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

	if ((set.log_level >= POLLER_VERBOSITY_MEDIUM) && (argc != 1)) {
		cacti_log("Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
	}else{
		printf("CACTID: Execution Time: %.4f s, Threads: %i, Hosts: %i\n", (end_time - begin_time), set.threads, num_rows);
	}

	exit(0);
}

/*! \fn static void display_help()
 *  \brief Display Cactid usage information to the caller.
 *
 *	Display the help listing: the first line is created at runtime with
 *	the version information, and the rest is strictly static text which
 *	is dumped literally.
 *
 */
static void display_help(void) {
	static const char *const *p;
	static const char * const helptext[] = {
		"Usage: cactid [options] [firstid lastid]",
		"",
		"Options:",
		"",
		"  -h/--help          Show this brief help listing",
		"  -f/--first=X       Start polling with host X",
		"  -l/--last=X        End polling with host X",
		"  -p/--poller=X      Poller ID = X",
		"  -C/--conf=F        Read Cactid configuration from file F",
		"  -O/--option=S:V    Override DB settings 'set' with value 'V'",
		"  -R/--readonly      This Cactid run is readonly with respect to the database",
		"  -S/--stdout        Logging is performed to the standard output",
		"  -V/--verbosity=V   Set logging verbosity to <V>",
		"  --snmponly         Only do SNMP polling: no script stuff",
		"",
		"Either both of --first/--last must be provided, or neither can be,",
		"and in their absense, all hosts are processed.",
		"",
		"Without the --conf parameter, cactid searches for its cactid.conf",
		"file in the usual places.",
		"",
		"Verbosity is one of NONE/LOW/MEDIUM/HIGH/DEBUG or 1..5",
		"",
		"Runtime options are read from the 'settings' table in the Cacti",
		"database, but they can be overridden with the --option=S:V",
		"parameter.",
		"",
		"Cactid is distributed under the Terms of the GNU General",
		"Public License Version 2. (www.gnu.org/copyleft/gpl.html)",
		"For more information, see http://www.cacti.net",

		0 /* ENDMARKER */
	};

	printf("CACTID %s  Copyright 2002-2005 by The Cacti Group\n\n", VERSION);

	for (p = helptext; *p; p++) {
		puts(*p);	/* automatically adds a newline */
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

