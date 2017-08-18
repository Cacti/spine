/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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
 *	Provide the name of the Spine configuration file, which contains
 *	the parameters for connecting to the database. In the absence of
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

/* Global Variables */
int entries = 0;
int num_hosts = 0;
int pending_threads = 0;
sem_t active_threads;
sem_t active_scripts;

config_t set;
php_t	*php_processes = 0;
char	config_paths[CONFIG_PATHS][BUFSIZE];
int     *debug_devices;

static char *getarg(char *opt, char ***pargv);
static void display_help(int only_version);

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

	if ( setgroups(0, NULL) == -1 ) {
		SPINE_LOG_HIGH(("setgroups failed."));
		exit(1);
	}

	if ( setegid(server_gid) == -1 || seteuid(server_uid) == -1 ) {
		SPINE_LOG_HIGH(("setegid/seteuid to uid=%d/gid=%d failed.", server_uid,
			server_gid));
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
	struct timeval now;
	char *conf_file = NULL;
	double begin_time, end_time, cur_time;
	int num_rows = 0;
	int device_counter = 0;
	int valid_conf_file = FALSE;
	char querybuf[BIG_BUFSIZE], *qp = querybuf;
	char *host_time = NULL;
	double host_time_double = 0;
	int itemsPT = 0;
	int device_threads;
	sem_t thread_init_sem;
	int a_threads_value;
	struct timespec until;

	#ifdef HAVE_LCAP
	if (geteuid() == 0)
		drop_root(getuid(), getgid());
	#endif /* HAVE_LCAP */

	pthread_t* threads = NULL;
	poller_thread_t* poller_details = NULL;
	pthread_attr_t attr;

	int* ids = NULL;
	MYSQL mysql;
	MYSQL_RES *result  = NULL;
	MYSQL_RES *tresult = NULL;
	MYSQL_ROW mysql_row;
	int canexit = FALSE;
	int host_id = 0;
	int i;
	int thread_status = 0;
	int change_host   = TRUE;
	int current_thread;

	UNUSED_PARAMETER(argc);		/* we operate strictly with argv */

	/* install the spine signal handler */
	install_spine_signal_handler();

	/* establish php processes and initialize space */
	php_processes = (php_t*) calloc(MAX_PHP_SERVERS, sizeof(php_t));
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		php_processes[i].php_state = PHP_BUSY;
	}

	/* create the array of debug devices */
	debug_devices = calloc(100, sizeof(int));

	/* initialize icmp_avail */
	set.icmp_avail = TRUE;

	/* detect and compensate for stdin/stderr ttys */
	if (!isatty(fileno(stdout))) {
		set.stdout_notty = TRUE;
	}else{
		set.stdout_notty = FALSE;
	}

	if (!isatty(fileno(stderr))) {
		set.stderr_notty = TRUE;
	}else{
		set.stderr_notty = FALSE;
	}

	/* set start time for cacti */
	begin_time = get_time_as_double();

	/* set default verbosity */
	set.log_level = POLLER_VERBOSITY_LOW;

	/* set the default exit code */
	set.exit_code = 0;

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

	for (argv++; *argv; argv++) {
		char	*arg = *argv;
		char	*opt = strchr(arg, '=');	/* pick off the =VALUE part */

		if (opt) *opt++ = '\0';

		if (STRMATCH(arg, "-f") ||
			STRMATCH(arg, "--first")) {
			if (HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.start_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.start_host_id)) {
				die("ERROR: '%s=%s' is invalid first-host ID", arg, opt);
			}
		}

		else if (STRMATCH(arg, "-l") ||
				 STRIMATCH(arg, "--last")) {
			if (HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: %s can only be used once", arg);
			}

			set.end_host_id = atoi(opt = getarg(opt, &argv));

			if (!HOSTID_DEFINED(set.end_host_id)) {
				die("ERROR: '%s=%s' is invalid last-host ID", arg, opt);
			}
		}

		else if (STRMATCH(arg, "-p") ||
				 STRIMATCH(arg, "--poller")) {
			set.poller_id = atoi(getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-N") ||
				 STRIMATCH(arg, "--mode")) {

			if (STRIMATCH(getarg(opt, &argv), "online")) {
				set.mode = REMOTE_ONLINE;
			} 

			else if (STRIMATCH(getarg(opt, &argv), "offline")) {
				set.mode = REMOTE_OFFLINE;
			} 

			else if (STRIMATCH(getarg(opt, &argv), "recovery")) {
				set.mode = REMOTE_RECOVERY;
			}

			else {
				die("ERROR: invalid polling mode '%s' specified", opt);
			}
		}

		else if (STRMATCH(arg, "-H") ||
				 STRIMATCH(arg, "--hostlist")) {
			snprintf(set.host_id_list, BIG_BUFSIZE, "%s", getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-M") ||
				 STRMATCH(arg, "--mibs")) {
			set.mibs = 1;
		}

		else if (STRMATCH(arg, "-h") || STRMATCH(arg, "--help")) {
			display_help(FALSE);

			exit(EXIT_SUCCESS);
		}

		else if (STRMATCH(arg, "-v") || STRMATCH(arg, "--version")) {
			display_help(TRUE);

			exit(EXIT_SUCCESS);
		}

		else if (STRMATCH(arg, "-O") ||
				 STRIMATCH(arg, "--option")) {
			char	*setting = getarg(opt, &argv);
			char	*value   = strchr(setting, ':');

			if (*value) {
				*value++ = '\0';
			}else{
				die("ERROR: -O requires setting:value");
			}

			set_option(setting, value);
		}

		else if (STRMATCH(arg, "-R") ||
				 STRMATCH(arg, "--readonly") ||
				 STRMATCH(arg, "--read-only")) {
			set.SQL_readonly = TRUE;
		}

		else if (STRMATCH(arg, "-C") ||
				 STRMATCH(arg, "--conf")) {
			conf_file = strdup(getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-S") ||
				 STRMATCH(arg, "--stdout")) {
			set_option("log_destination", "STDOUT");
		}

		else if (STRMATCH(arg, "-L") ||
				 STRMATCH(arg, "--log")) {
			set_option("log_destination", getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "-V") ||
				 STRMATCH(arg, "--verbosity")) {
			set_option("log_verbosity", getarg(opt, &argv));
		}

		else if (STRMATCH(arg, "--snmponly") ||
				 STRMATCH(arg, "--snmp-only")) {
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

	/* we attempt to support scripts better in cygwin */
	#if defined(__CYGWIN__)
	setenv("CYGWIN", "nodosfilewarning", 1);
	if (file_exists("./sh.exe")) {
		set.cygwinshloc = 0;
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			printf("NOTE: The Shell Command Exists in the current directory\n");
		}
	}else{
		set.cygwinshloc = 1;
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			printf("NOTE: The Shell Command Exists in the /bin directory\n");
		}
	}
	#endif

	/* we require either both the first and last hosts, or niether host */
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
		}else{
			valid_conf_file = TRUE;
		}
	}else{
		if (!(conf_file = calloc(CONFIG_PATHS, BUFSIZE))) {
			die("ERROR: Fatal malloc error: spine.c conf_file!");
		}

		for (i=0; i<CONFIG_PATHS; i++) {
			snprintf(conf_file, BUFSIZE, "%s%s", config_paths[i], DEFAULT_CONF_FILE);

			if (read_spine_config(conf_file) >= 0) {
				valid_conf_file = TRUE;
				break;
			}

			if (i == CONFIG_PATHS-1) {
				snprintf(conf_file, BUFSIZE, "%s%s", config_paths[0], DEFAULT_CONF_FILE);
			}
		}
	}

	if (valid_conf_file) {
		/* read settings table from the database to further establish environment */
		read_config_options();
	}else{
		die("FATAL: Unable to read configuration file!");
	}

	/* set the poller interval for those who use less than 5 minute intervals */
	if (set.poller_interval == 0) {
		set.poller_interval = 300;
	}

	/* tokenize the debug devices */
	if (strlen(set.selective_device_debug)) {
		SPINE_LOG_DEBUG(("Selective Debug Devices %s", set.selective_device_debug));
		int i = 0;
		char *token = strtok(set.selective_device_debug, ",");
		while(token) {
			debug_devices[i]   = atoi(token);
			debug_devices[i+1] = '\0';
			token = strtok(NULL, ",");
			i++;
		}
	}else{
		debug_devices[0] = '\0';
	}

	/* connect to database */
	db_connect(set.dbdb, &mysql);

	/* Since MySQL 5.7 the sql_mode defaults are too strict for cacti */
	db_insert(&mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
	db_insert(&mysql, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");

	if (set.log_level == POLLER_VERBOSITY_DEBUG) {
		SPINE_LOG_DEBUG(("Version %s starting", VERSION));
	}else{
		if (!set.stdout_notty) {
			printf("SPINE: Version %s starting\n", VERSION);
		}
	}

	/* see if mysql is thread safe */
	if (mysql_thread_safe()) {
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			SPINE_LOG(("DEBUG: MySQL is Thread Safe!"));
		}
	}else{
		SPINE_LOG(("WARNING: MySQL is NOT Thread Safe!"));
	}

	/* test for asroot permissions for ICMP */
	checkAsRoot();

	/* initialize SNMP */
	SPINE_LOG_DEBUG(("SPINE: Initializing Net-SNMP API"));
	snmp_spine_init();

	/* initialize PHP if required */
	SPINE_LOG_DEBUG(("SPINE: Initializing PHP Script Server(s)"));

	/* tell spine that it is parent, and set the poller id */
	set.parent_fork = SPINE_PARENT;

	/* initialize the script server */
	if (set.php_required) {
		php_init(PHP_INIT);
		set.php_initialized    = TRUE;
		set.php_current_server = 0;
	}

	/* determine if the poller_id field exists in the host table */
	result = db_query(&mysql, "SHOW COLUMNS FROM host LIKE 'poller_id'");
	if (mysql_num_rows(result)) {
		set.poller_id_exists = TRUE;
	}else{
		set.poller_id_exists = FALSE;

		if (set.poller_id > 0) {
			SPINE_LOG(("WARNING: PollerID > 0, but 'host' table does NOT contain the poller_id column!!"));
		}
	}
	db_free_result(result);

	/* determine if the device_threads field exists in the host table */
	result = db_query(&mysql, "SHOW COLUMNS FROM host LIKE 'device_threads'");
	if (mysql_num_rows(result)) {
		set.device_threads_exists = TRUE;
	}else{
		set.device_threads_exists = FALSE;
	}
	db_free_result(result);

	if (set.device_threads_exists) {
		SPINE_LOG_MEDIUM(("NOTE: Spine will support multithread device polling."));
	}else{
		SPINE_LOG_MEDIUM(("NOTE: Spine did not detect multithreaded device polling."));  
	}

	/* obtain the list of hosts to poll */
	if (set.device_threads_exists) {
		qp += sprintf(qp, "SELECT id, device_threads FROM host");
	}else{
		qp += sprintf(qp, "SELECT id, '1' as device_threads FROM host");
	}
	qp += sprintf(qp, " WHERE disabled=''");
	if (!strlen(set.host_id_list)) {
		qp += append_hostrange(qp, "id");	/* AND id BETWEEN a AND b */
	}else{
		qp += sprintf(qp, " AND id IN(%s)", set.host_id_list);
	}
	if (set.poller_id_exists) {
		qp += sprintf(qp, " AND host.poller_id=%i", set.poller_id);
	}
	qp += sprintf(qp, " ORDER BY polling_time DESC");

	result = db_query(&mysql, querybuf);
	if (set.poller_id == 0) {
		num_rows = mysql_num_rows(result) + 1; /* add 1 for host = 0 */
	}else{
		num_rows = mysql_num_rows(result); /* pollerid 0 takes care of not host based data sources */
	}

	if (!(threads = (pthread_t *)malloc(num_rows * sizeof(pthread_t)))) {
		die("ERROR: Fatal malloc error: spine.c threads!");
	}

	if (!(ids = (int *)malloc(num_rows * sizeof(int)))) {
		die("ERROR: Fatal malloc error: spine.c host id's!");
	}

	/* mark the spine process as started */
	snprintf(querybuf, BIG_BUFSIZE, "INSERT INTO poller_time (poller_id, pid, start_time, end_time) VALUES (%i, %i, NOW(), '0000-00-00 00:00:00')", set.poller_id, getpid());
	db_insert(&mysql, querybuf);

	/* initialize threads and mutexes */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	init_mutexes();

	/* initialize active_threads semaphore */
	sem_init(&active_threads, 0, set.threads);

	/* initialize active_scripts semaphore */
	sem_init(&active_scripts, 0, MAX_SIMULTANEOUS_SCRIPTS);

	/* initialize thread initialization semaphore */
	sem_init(&thread_init_sem, 0, 1);

	/* specify the point of timeout for timedwait semaphores */
	until.tv_sec = (time_t)(set.poller_interval + begin_time - 0.2);
	until.tv_nsec = 0;

	sem_getvalue(&active_threads, &a_threads_value);
	SPINE_LOG_MEDIUM(("DEBUG: Initial Value of Active Threads is %i", set.threads - a_threads_value));

	/* tell fork processes that they are now active */
	set.parent_fork = SPINE_FORK;

	/* initialize the threading code */
	device_threads   = 1;
	current_thread   = 0;

	/* poller 0 always polls host 0 */
	if (set.poller_id == 0) {
		host_id     = 0;
		change_host = FALSE;
	}else{
		change_host = TRUE;
	}

	/* loop through devices until done */
	while (canexit == FALSE && device_counter < num_rows) {
		if (change_host) {
			mysql_row       = mysql_fetch_row(result);
			host_id         = atoi(mysql_row[0]);
			device_threads  = atoi(mysql_row[1]);
			current_thread  = 1;
		}else{
			current_thread++;
		}

		change_host = (current_thread >= device_threads) ? TRUE : FALSE;

		/* determine how many items will be polled per thread */
		if (device_threads > 1) {
			if (current_thread == 1) {
				snprintf(querybuf, BIG_BUFSIZE, "SELECT CEIL(COUNT(*)/%i) FROM poller_item WHERE host_id=%i AND rrd_next_step <=0", device_threads, host_id);
				tresult   = db_query(&mysql, querybuf);
				mysql_row = mysql_fetch_row(tresult);

				itemsPT   = atoi(mysql_row[0]);
				db_free_result(tresult);

				if (host_time) free(host_time);
				host_time = get_host_poll_time();
				host_time_double = get_time_as_double();
			}
		}else{
			itemsPT   = 0;
			if (host_time) free(host_time);
			host_time = get_host_poll_time();
			host_time_double = get_time_as_double();
		}

		/* populate the thread structure */
		if (!(poller_details = (poller_thread_t *)malloc(sizeof(poller_thread_t)))) {
			die("ERROR: Fatal malloc error: spine.c poller_details!");
		}

		poller_details->host_id          = host_id;
		poller_details->host_thread      = current_thread;
		poller_details->last_host_thread = device_threads;
		poller_details->host_data_ids    = itemsPT;
		poller_details->host_time        = host_time;
		poller_details->host_time_double = host_time_double;
		poller_details->thread_init_sem  = &thread_init_sem;

		retry1:

		if (sem_timedwait(&active_threads, &until) == -1) {
			if (errno == ETIMEDOUT) {
				SPINE_LOG(("ERROR: Spine Timed Out While Processing Devices Internal"));
				canexit = TRUE;
				break;
			}else if (errno == EINTR) {
				usleep(10000);
				goto retry1;
			}
		}

		/* create child process */
		sem_wait(&thread_init_sem);

		thread_status = pthread_create(&threads[device_counter], &attr, child, poller_details);

		switch (thread_status) {
			case 0:
				SPINE_LOG_DEBUG(("DEBUG: Valid Thread to be Created"));

				if (change_host) {
					device_counter++;
				}

				sem_wait(&thread_init_sem);
				thread_mutex_lock(LOCK_PEND);
				pending_threads++;

				sem_getvalue(&active_threads, &a_threads_value);
				SPINE_LOG_MEDIUM(("SPINE: Active Threads is %i, Pending is %i", set.threads - a_threads_value, pending_threads));

				thread_mutex_unlock(LOCK_PEND);
				sem_post(&thread_init_sem);

				break;
			case EAGAIN:
				SPINE_LOG(("ERROR: The System Lacked the Resources to Create a Thread"));
				break;
			case EFAULT:
				SPINE_LOG(("ERROR: The Thread or Attribute were Invalid"));
				break;
			case EINVAL: SPINE_LOG(("ERROR: The Thread Attribute is Not Initialized"));
				break;
			default:
				SPINE_LOG(("ERROR: Unknown Thread Creation Error"));
				break;
		}

		/* Restore thread initialization semaphore if thread creation failed */
		if (thread_status)
			sem_post(&thread_init_sem);
	}

	/* wait for all threads to 'complete'
 	 * using the mutex here as the semaphore will
     * show zero before the children are done */
	while (TRUE) {
		thread_mutex_lock(LOCK_PEND);

		cur_time = get_time_as_double();

		if (pending_threads == 0) {
			break;
		} else if (cur_time - begin_time > set.poller_interval) {
			SPINE_LOG(("ERROR: Spine Timed Out While Waiting for Threads to End"));
			break;
		}

		thread_mutex_unlock(LOCK_PEND);

		sleep(1);
	}

	sem_getvalue(&active_threads, &a_threads_value);
	SPINE_LOG_MEDIUM(("SPINE: The Final Value of Threads is %i", set.threads - a_threads_value));

	/* tell Spine that it is now parent */
	set.parent_fork = SPINE_PARENT;

	/* print out stats */
	gettimeofday(&now, NULL);

	/* update the db for |data_time| on graphs */
	if (set.poller_id == 1) {
		db_insert(&mysql, "REPLACE INTO settings (name,value) VALUES ('date',NOW())");
	}

	snprintf(querybuf, BIG_BUFSIZE, "UPDATE poller_time SET end_time=NOW() WHERE poller_id=%i AND pid=%i", set.poller_id, getpid());
	db_insert(&mysql, querybuf);

	/* cleanup and exit program */
	pthread_attr_destroy(&attr);

	SPINE_LOG_DEBUG(("DEBUG: Thread Cleanup Complete"));

	/* close the php script server */
	if (set.php_required) {
		php_close(PHP_INIT);
	}

	SPINE_LOG_DEBUG(("DEBUG: PHP Script Server Pipes Closed"));

	/* free malloc'd variables */
	free(threads);
	free(ids);
	free(conf_file);
	free(debug_devices);

	SPINE_LOG_DEBUG(("DEBUG: Allocated Variable Memory Freed"));

	/* close mysql */
	db_free_result(result);
	mysql_close(&mysql);

	SPINE_LOG_DEBUG(("DEBUG: MYSQL Free & Close Completed"));

	/* close snmp */
	snmp_spine_close();

	SPINE_LOG_DEBUG(("DEBUG: Net-SNMP Close Completed"));

	/* finally add some statistics to the log and exit */
	end_time = TIMEVAL_TO_DOUBLE(now);

	if (set.log_level >= POLLER_VERBOSITY_MEDIUM) {
		SPINE_LOG(("Time: %.4f s, Threads: %i, Devices: %i", (end_time - begin_time), set.threads, num_rows));
	}else{
		/* provide output if running from command line */
		if (!set.stdout_notty) {
			fprintf(stdout,"SPINE: Time: %.4f s, Threads: %i, Devices: %i\n", (end_time - begin_time), set.threads, num_rows);
		}
	}

	/* uninstall the spine signal handler */
	uninstall_spine_signal_handler();

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
		"  -C/--conf=F        Read spine configuration from file F",
		"  -O/--option=S:V    Override DB settings 'set' with value 'V'",
		"  -M/--mibs          Refresh the device System Mib data",
		"  -N/--mode=online   For remote pollers, the operating mode.",
		"                     Options include: online, offline, recovery.",
		"                     The default is 'online'.",
		"  -R/--readonly      Spine will not write output to the DB",
		"  -S/--stdout        Logging is performed to standard output",
		"  -V/--verbosity=V   Set logging verbosity to <V>",
		"  --snmponly         Only do SNMP polling: no scripts",
		"",
		"Either both of --first/--last must be provided, a valid hostlist must be provided.",
        "In their absence, all hosts are processed.",
		"",
		"Without the --conf parameter, spine searches for its spine.conf",
		"file in the usual places.",
		"",
		"Verbosity is one of NONE/LOW/MEDIUM/HIGH/DEBUG or 1..5",
		"",
		"Runtime options are read from the 'settings' table in the Cacti",
		"database, but they can be overridden with the --option=S:V",
		"parameter.",
		"",
		"Spine is distributed under the Terms of the GNU Lessor",
		"General Public License Version 2.1. (http://www.gnu.org/licenses/lgpl.txt)",
		"For more information, see http://www.cacti.net",

		0 /* ENDMARKER */
	};

	printf("SPINE %s  Copyright 2004-2017 by The Cacti Group\n", VERSION);

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

