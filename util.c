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
*/

#include "common.h"
#include "spine.h"

static int nopts = 0;

/*! Override Options Structure
 *
 * When we fetch a setting from the database, we allow the user to override
 * it from the command line. These overrides are provided with the --option
 * parameter and stored in this table: we *use* them when the config code
 * reads from the DB.
 *
 * It's not an error to set an option which is unknown, but maybe should be.
 *
 */
static struct {
	const char *opt;
	const char *val;
} opttable[256];

/*! \fn void set_option(const char *option, const char *value)
 *  \brief Override spine setting from the Cacti settings table.
 *
 *	Called from the command-line processing code, this provides a value
 *	to replace any DB-stored option settings.
 *
 */
void set_option(const char *option, const char *value) {
	opttable[nopts  ].opt = option;
	opttable[nopts++].val = value;
}

/*! \fn static const char *getsetting(MYSQL *psql, const char *setting)
 *  \brief Returns a character pointer to a Cacti setting.
 *
 *  Given a pointer to a database and the name of a setting, return the string
 *  which represents the value from the settings table. Return NULL if we
 *  can't find a setting for whatever reason.
 *
 *  NOTE: if the user has provided one of these options on the command line,
 *  it's intercepted here and returned, overriding the database setting.
 *
 *  \return the database option setting
 *
 */
static const char *getsetting(MYSQL *psql, const char *setting) {
	char      qstring[256];
	char      *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int       i;

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (i=0; i<nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			retval = strdup(opttable[i].val);
			return retval;
		}
	}

	sprintf(qstring, "SELECT value FROM settings WHERE name = '%s'", setting);

	result = db_query(psql, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);
		
			if (mysql_row != NULL) {
				retval = strdup(mysql_row[0]);
				db_free_result(result);
				return retval;
			}else{
				return 0;
			}
		}else{
			db_free_result(result);
			return 0;
		}
	}else{
		return 0;
	}
}

/*! \fn static int getboolsetting(MYSQL *psql, const char *setting, int dflt)
 *  \brief Obtains a boolean option from the database.
 *
 *	Given the parameters for fetching a setting from the database,
 *	do so for a *Boolean* value. We parse the usual set of words
 *	meaning true/false, and if we don't get a value, or if we don't
 *	understand what we fetched, we use the default value provided.
 *
 *  \return boolean TRUE or FALSE based upon database setting or the DEFAULT if not found
 */
static int getboolsetting(MYSQL *psql, const char *setting, int dflt) {
	const char *rc;

	assert(psql    != 0);
	assert(setting != 0);

	rc = getsetting(psql, setting);

	if (rc == 0) return dflt;

	if (STRIMATCH(rc, "on"  ) ||
		STRIMATCH(rc, "yes" ) ||
		STRIMATCH(rc, "true") ||
		STRIMATCH(rc, "1"   ) ) {
		free((char *)rc);
		return TRUE;
	}

	if (STRIMATCH(rc, "off"  ) ||
		STRIMATCH(rc, "no"   ) ||
		STRIMATCH(rc, "false") ||
		STRIMATCH(rc, "0"    ) ) {
		free((char *)rc);
		return FALSE;
	}

	/* doesn't really match one of our keywords: what to do? */
	free((char *)rc);

	return dflt;
}

/*! \fn static const char *getglobalvariable(MYSQL *psql, const char *setting)
 *  \brief Returns a character pointer to a MySQL global variable setting.
 *
 *  Given a pointer to a database and the name of a global variable, return the string
 *  which represents that value from the settings table. Return NULL if we
 *  can't find a variable for whatever reason.
 *
 *  \return the database global variable setting
 *
 */
static const char *getglobalvariable(MYSQL *psql, const char *setting) {
	char      qstring[256];
	char      *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int       i;

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (i=0; i<nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			return opttable[i].val;
		}
	}

	sprintf(qstring, "SHOW GLOBAL VARIABLES LIKE '%s'", setting);

	result = db_query(psql, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);
		
			if (mysql_row != NULL) {
				retval = strdup(mysql_row[1]);
				db_free_result(result);
				return retval;
			}else{
				return 0;
			}
		}else{
			db_free_result(result);
			return 0;
		}
	}else{
		return 0;
	}
}

/*! \fn int is_debug_device(int device_id)
 *  \brief Determine if a device is a debug device
 *
 */
int is_debug_device(int device_id) {
	extern int *debug_devices;
	int i = 0;

	while(i < 100) {
		if (debug_devices[i] == '\0') break;
		if (debug_devices[i] == device_id) {
			return TRUE;
		}

		i++;
	}

	return FALSE;
}

/*! \fn void read_config_options(void)
 *  \brief Reads the default Spine runtime parameters from the database and set's the global array
 *
 *  load default values from the database for poller processing
 *
 */
void read_config_options() {
	MYSQL      mysql;
	MYSQL_RES  *result;
	int        num_rows;
	char       web_root[BUFSIZE];
	char       sqlbuf[SMALL_BUFSIZE], *sqlp = sqlbuf;
	const char *res;

	db_connect(set.dbdb, &mysql);

	/* get the mysql server version */
	set.dbversion = 0;
	if ((res = getglobalvariable(&mysql, "version")) != 0) {
		set.dbversion = atoi(res);
		free((char *)res);
	}

	/* get logging level from database - overrides spine.conf */
	if ((res = getsetting(&mysql, "log_verbosity")) != 0) {
		const int n = atoi(res);
		free((char *)res);
		if (n != 0) set.log_level = n;
	}

	/* determine script server path operation and default log file processing */
	if ((res = getsetting(&mysql, "path_webroot")) != 0) {
		snprintf(set.path_php_server, SMALL_BUFSIZE, "%s/script_server.php", res);
		snprintf(web_root, BUFSIZE, "%s", res);
		free((char *)res);
	}

	/* determine logfile path */
	if ((res = getsetting(&mysql, "path_cactilog")) != 0) {
		if (strlen(res) != 0) {
			snprintf(set.path_logfile, SMALL_BUFSIZE, "%s", res);
		}else{
			if (strlen(web_root) != 0) {
				snprintf(set.path_logfile, SMALL_BUFSIZE, "%s/log/cacti.log", web_root);
			}else{
				set.path_logfile[0] ='\0';
			}
		}
		free((char *)res);
	}else{
		snprintf(set.path_logfile, SMALL_BUFSIZE, "%s/log/cacti.log", web_root);
 	}

	/* log the path_webroot variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php_server variable is %s", set.path_php_server));

	/* log the path_cactilog variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_cactilog variable is %s", set.path_logfile));

	/* determine log file, syslog or both, default is 1 or log file only */
	if ((res = getsetting(&mysql, "log_destination")) != 0) {
		set.log_destination = parse_logdest(res, LOGDEST_FILE);
		free((char *)res);
	}else{
		set.log_destination = LOGDEST_FILE;
	}

	/* log the log_destination variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_destination variable is %i (%s)",
			set.log_destination,
			printable_logdest(set.log_destination)));
	set.logfile_processed = TRUE;

	/* get PHP Path Information for Scripting */
	if ((res = getsetting(&mysql, "path_php_binary")) != 0) {
		STRNCOPY(set.path_php, res);
		free((char *)res);
	}

	/* log the path_php variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php variable is %s", set.path_php));

	/* set availability_method */
	if ((res = getsetting(&mysql, "availability_method")) != 0) {
		set.availability_method = atoi(res);
		free((char *)res);
	}

	/* log the availability_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The availability_method variable is %i", set.availability_method));

	/* set ping_recovery_count */
	if ((res = getsetting(&mysql, "ping_recovery_count")) != 0) {
		set.ping_recovery_count = atoi(res);
		free((char *)res);
	}

	/* log the ping_recovery_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_recovery_count variable is %i", set.ping_recovery_count));

	/* set ping_failure_count */
	if ((res = getsetting(&mysql, "ping_failure_count")) != 0) {
		set.ping_failure_count = atoi(res);
		free((char *)res);
	}

	/* log the ping_failure_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_failure_count variable is %i", set.ping_failure_count));

	/* set ping_method */
	if ((res = getsetting(&mysql, "ping_method")) != 0) {
		set.ping_method = atoi(res);
		free((char *)res);
	}

	/* log the ping_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_method variable is %i", set.ping_method));

	/* set ping_retries */
	if ((res = getsetting(&mysql, "ping_retries")) != 0) {
		set.ping_retries = atoi(res);
		free((char *)res);
	}

	/* log the ping_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_retries variable is %i", set.ping_retries));

	/* set ping_timeout */
	if ( (res = getsetting(&mysql, "ping_timeout")) != 0) {
		set.ping_timeout = atoi(res);
		free((char *)res);
	}

	/* log the ping_timeout variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_timeout variable is %i", set.ping_timeout));

	/* set snmp_retries */
	if ( (res = getsetting(&mysql, "snmp_retries")) != 0) {
		set.snmp_retries = atoi(res);
		free((char *)res);
	}

	/* log the snmp_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The snmp_retries variable is %i", set.snmp_retries));

	/* set logging option for errors */
	set.log_perror = getboolsetting(&mysql, "log_perror", FALSE);

	/* log the log_perror variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_perror variable is %i", set.log_perror));

	/* set logging option for errors */
	set.log_pwarn = getboolsetting(&mysql, "log_pwarn", FALSE);

	/* log the log_pwarn variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pwarn variable is %i", set.log_pwarn));

	/* set logging option for errors */
	set.boost_redirect = getboolsetting(&mysql, "boost_redirect", FALSE);

	/* log the log_pwarn variable */
	SPINE_LOG_DEBUG(("DEBUG: The boost_redirect variable is %i", set.boost_redirect));

	/* set logging option for statistics */
	set.log_pstats = getboolsetting(&mysql, "log_pstats", FALSE);

	/* log the log_pstats variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pstats variable is %i", set.log_pstats));

	/* get Cacti defined max threads override spine.conf */
	if ((res = getsetting(&mysql, "max_threads")) != 0) {
		set.threads = atoi(res);
		free((char *)res);
		if (set.threads > MAX_THREADS) {
			set.threads = MAX_THREADS;
		}
	}

	/* log the threads variable */
	SPINE_LOG_DEBUG(("DEBUG: The threads variable is %i", set.threads));

	/* get the poller_interval for those who have elected to go with a 1 minute polling interval */
	if ((res = getsetting(&mysql, "poller_interval")) != 0) {
		set.poller_interval = atoi(res);
		free((char *)res);
	}else{
		set.poller_interval = 0;
	}

	/* log the poller_interval variable */
	if (set.poller_interval == 0) {
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is the system default"));
	}else{
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is %i seconds", set.poller_interval));
	}

	/* get the concurrent_processes variable to determine thread sleep values */
	if ((res = getsetting(&mysql, "concurrent_processes")) != 0) {
		set.num_parent_processes = atoi(res);
		free((char *)res);
	}else{
		set.num_parent_processes = 1;
	}

	/* log the concurrent processes variable */
	SPINE_LOG_DEBUG(("DEBUG: The number of concurrent processes is %i", set.num_parent_processes));

	/* get the script timeout to establish timeouts */
	if ((res = getsetting(&mysql, "script_timeout")) != 0) {
		set.script_timeout = atoi(res);
		free((char *)res);
		if (set.script_timeout < 5) {
			set.script_timeout = 5;
		}
	}else{
		set.script_timeout = 25;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The script timeout is %i", set.script_timeout));

	/* get selective_device_debug string */
	if ((res = getsetting(&mysql, "selective_device_debug")) != 0) {
		STRNCOPY(set.selective_device_debug, res);
		free((char *)res);
	}

	/* log the selective_device_debug variable */
	SPINE_LOG_DEBUG(("DEBUG: The selective_device_debug variable is %s", set.selective_device_debug));

	/* get spine_log_level */
	if ((res = getsetting(&mysql, "spine_log_level")) != 0) {
		set.spine_log_level = atoi(res);
		free((char *)res);
	}

	/* log the spine_log_level variable */
	SPINE_LOG_DEBUG(("DEBUG: The spine_log_level variable is %i", set.spine_log_level));

	/* get the number of script server processes to run */
	if ((res = getsetting(&mysql, "php_servers")) != 0) {
		set.php_servers = atoi(res);
		free((char *)res);

		if (set.php_servers > MAX_PHP_SERVERS) {
			set.php_servers = MAX_PHP_SERVERS;
		}

		if (set.php_servers <= 0) {
			set.php_servers = 1;
		}
	}else{
		set.php_servers = 2;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of php script servers to run is %i", set.php_servers));

	/*----------------------------------------------------------------
	 * determine if the php script server is required by searching for
	 * all the host records for an action of POLLER_ACTION_PHP_SCRIPT_SERVER.
	 * If we get even one, it means we have to deal with the PHP script
	 * server.
	 *
	 */
	set.php_required = FALSE;		/* assume no */

	/* log the requirement for the script server */
	if (!strlen(set.host_id_list)) {
		sqlp = sqlbuf;
		sqlp += sprintf(sqlp, "SELECT action FROM poller_item");
		sqlp += sprintf(sqlp, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += append_hostrange(sqlp, "host_id");
		if (set.poller_id_exists) {
			sqlp += sprintf(sqlp, " AND poller_id=%i", set.poller_id);
		}
		sqlp += sprintf(sqlp, " LIMIT 1");

		result = db_query(&mysql, sqlbuf);
		num_rows = mysql_num_rows(result);
		db_free_result(result);

		if (num_rows > 0) set.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: StartDevice='%i', EndDevice='%i', TotalPHPScripts='%i'",
			set.start_host_id,
			set.end_host_id,
			num_rows));
	}else{
		sqlp = sqlbuf;
		sqlp += sprintf(sqlp, "SELECT action FROM poller_item");
		sqlp += sprintf(sqlp, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += sprintf(sqlp, " AND host_id IN(%s)", set.host_id_list);
		if (set.poller_id_exists) {
			sqlp += sprintf(sqlp, " AND poller_id=%i", set.poller_id);
		}
		sqlp += sprintf(sqlp, " LIMIT 1");

		result = db_query(&mysql, sqlbuf);
		num_rows = mysql_num_rows(result);
		db_free_result(result);

		if (num_rows > 0) set.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: Device List to be polled='%s', TotalPHPScripts='%i'",
			set.host_id_list,
			num_rows));
	}

	SPINE_LOG_DEBUG(("DEBUG: The PHP Script Server is %sRequired",
		set.php_required
		? ""
		: "Not "));

	/* determine the maximum oid's to obtain in a single get request */
	if ((res = getsetting(&mysql, "max_get_size")) != 0) {
		set.snmp_max_get_size = atoi(res);
		free((char *)res);

		if (set.snmp_max_get_size > 128) {
			set.snmp_max_get_size = 128;
		}
	}else{
		set.snmp_max_get_size = 25;
	}

	/* log the snmp_max_get_size variable */
	SPINE_LOG_DEBUG(("DEBUG: The Maximum SNMP OID Get Size is %i", set.snmp_max_get_size));

	db_disconnect(&mysql);
}

/*! \fn int read_spine_config(char *file)
 *  \brief obtain default startup variables from the spine.conf file.
 *  \param file the spine config file
 *
 *  \return 0 if successful or -1 if the file could not be opened
 */
int read_spine_config(char *file) {
	FILE *fp;
	char buff[BUFSIZE];
	char *buffer;
	char p1[BUFSIZE];
	char p2[BUFSIZE];

	if ((fp = fopen(file, "rb")) == NULL) {
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			if (!set.stderr_notty) {
				fprintf(stderr, "ERROR: Could not open config file [%s]\n", file);
			}
		}
		return -1;
	}else{
		if (!set.stdout_notty) {
			fprintf(stdout, "SPINE: Using spine config file [%s]\n", file);
		}

		while(!feof(fp)) {
			buffer = fgets(buff, BUFSIZE, fp);
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%15s %255s", p1, p2);

				if (STRIMATCH(p1, "RDB_Host"))              STRNCOPY(set.rdbhost, p2);
				else if (STRIMATCH(p1, "RDB_Database"))     STRNCOPY(set.rdbdb, p2);
				else if (STRIMATCH(p1, "RDB_User"))         STRNCOPY(set.rdbuser, p2);
				else if (STRIMATCH(p1, "RDB_Pass"))         STRNCOPY(set.rdbpass, p2);
				else if (STRIMATCH(p1, "RDB_Port"))         set.rdbport    = atoi(p2);
				else if (STRIMATCH(p1, "DB_Host"))          STRNCOPY(set.dbhost, p2);
				else if (STRIMATCH(p1, "DB_Database"))      STRNCOPY(set.dbdb, p2);
				else if (STRIMATCH(p1, "DB_User"))          STRNCOPY(set.dbuser, p2);
				else if (STRIMATCH(p1, "DB_Pass"))          STRNCOPY(set.dbpass, p2);
				else if (STRIMATCH(p1, "DB_Port"))          set.dbport    = atoi(p2);
				else if (STRIMATCH(p1, "Poller"))           set.poller_id = atoi(p2);
				else if (STRIMATCH(p1, "DB_PreG")) {
					if (!set.stderr_notty) {
						fprintf(stderr,"WARNING: DB_PreG is no longer supported\n");
					}
				}
				else if (STRIMATCH(p1, "SNMP_Clientaddr"))  STRNCOPY(set.snmp_clientaddr, p2);
				else if (!set.stderr_notty) {
					fprintf(stderr,"WARNING: Unrecongized directive: %s=%s in %s\n", p1, p2, file);
				}

				*p1 = '\0';
				*p2 = '\0';
			}
		}

		if (strlen(set.dbpass) == 0) *set.dbpass = '\0';

		return 0;
	}
}

/*! \fn void config_defaults(void)
 *  \brief populates the global configuration structure with default spine.conf file settings
 *  \param *set global runtime parameters
 *
 */
void config_defaults() {
	set.threads = DEFAULT_THREADS;

	/* default server */
	set.dbport  = DEFAULT_DB_PORT;

	STRNCOPY(set.dbhost, DEFAULT_DB_HOST);
	STRNCOPY(set.dbdb,   DEFAULT_DB_DB  );
	STRNCOPY(set.dbuser, DEFAULT_DB_USER);
	STRNCOPY(set.dbpass, DEFAULT_DB_PASS);

	/* remote default server */
	set.rdbport  = DEFAULT_DB_PORT;

	STRNCOPY(set.rdbhost, DEFAULT_DB_HOST);
	STRNCOPY(set.rdbdb,   DEFAULT_DB_DB  );
	STRNCOPY(set.rdbuser, DEFAULT_DB_USER);
	STRNCOPY(set.rdbpass, DEFAULT_DB_PASS);

	STRNCOPY(config_paths[0], CONFIG_PATH_1);
	STRNCOPY(config_paths[1], CONFIG_PATH_2);
	STRNCOPY(config_paths[2], CONFIG_PATH_3);
	STRNCOPY(config_paths[3], CONFIG_PATH_4);

	set.log_destination = LOGDEST_FILE;
}

/*! \fn void die(const char *format, ...)
 *  \brief a method to end Spine while returning the fatal error to stderr
 *
 *	Given a printf-style argument list, format it to the standard
 *	error, append a newline, then exit Spine.
 *
 */
void die(const char *format, ...) {
	va_list	args;
	char logmessage[BUFSIZE];
	char flogmessage[BUFSIZE];
	int old_errno = errno;

	va_start(args, format);
	vsprintf(logmessage, format, args);
	va_end(args);

	if (set.log_perror) {
		char perr[BUFSIZE];
		snprintf(perr, BUFSIZE, " [%d, %s]", old_errno, strerror(old_errno));
		strcat(logmessage,perr);
	}

	if (set.logfile_processed) {
		if (set.parent_fork == SPINE_PARENT) {
			snprintf(flogmessage, BUFSIZE, "%s (Spine parent)", logmessage);
		}else{
			snprintf(flogmessage, BUFSIZE, "%s (Spine thread)", logmessage);
		}
	}else{
		snprintf(flogmessage, BUFSIZE, "%s (Spine init)", logmessage);
	}

	SPINE_LOG(("%s", flogmessage));

	if (set.parent_fork == SPINE_PARENT) {
		if (set.php_initialized) {
			php_close(PHP_INIT);
		}
	}

	exit(set.exit_code);
}

/*! \fn void spine_log(const char *format, ...)
 *  \brief output's log information to the desired cacti logfile.
 *  \param *logmessage a pointer to the pre-formated log message.
 *
 */
int spine_log(const char *format, ...) {
	va_list	args;

	FILE *log_file = NULL;
	FILE *fp = NULL;

	/* variables for time display */
	time_t nowbin;
	struct tm now_time;
	struct tm *now_ptr;

	/* keep track of an errored log file */
	static int log_error = FALSE;

	char logprefix[SMALL_BUFSIZE]; /* Formatted Log Prefix */
	char ulogmessage[LOGSIZE];     /* Un-Formatted Log Message */
	char flogmessage[LOGSIZE];     /* Formatted Log Message */

	va_start(args, format);
	vsnprintf(ulogmessage, LOGSIZE - 1, format, args);
	va_end(args);

	/* default for "console" messages to go to stdout */
	fp = stdout;

	if (IS_LOGGING_TO_STDOUT()) {
		puts(trim(ulogmessage));
		return TRUE;
	}

	/* log message prefix */
	snprintf(logprefix, SMALL_BUFSIZE, "SPINE: Poller[%i] ", set.poller_id);

	/* get time for poller_output table */
	nowbin = time(&nowbin);

	localtime_r(&nowbin,&now_time);
	now_ptr = &now_time;

	if (strftime(flogmessage, 50, "%Y-%m-%d %H:%M:%S - ", now_ptr) == (size_t) 0) {
		#ifdef DISABLE_STDERR
		fp = stdout;
		#else
		fp = stderr;
		#endif

		if ((set.stderr_notty) && (fp == stderr)) {
			/* do nothing stderr does not exist */
		}else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		}else{
			fprintf(fp, "ERROR: Could not get string from strftime()\n");
		}
	}

	strncat(flogmessage, logprefix,   sizeof(flogmessage) - 1);
	strncat(flogmessage, ulogmessage, sizeof(flogmessage) - 50);

	/* output to syslog/eventlog */
	if (IS_LOGGING_TO_SYSLOG()) {
		thread_mutex_lock(LOCK_SYSLOG);
		openlog("Cacti", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
		if ((strstr(flogmessage,"ERROR") || (strstr(flogmessage, "FATAL"))) && (set.log_perror)) {
			syslog(LOG_CRIT,"%s\n", flogmessage);
		}

		if ((strstr(flogmessage,"WARNING")) && (set.log_pwarn)){
			syslog(LOG_WARNING,"%s\n", flogmessage);
		}

		if ((strstr(flogmessage,"STATS")) && (set.log_pstats)){
			syslog(LOG_NOTICE,"%s\n", flogmessage);
		}

		closelog();
		thread_mutex_unlock(LOCK_SYSLOG);
	}

	/* append a line feed to the log message if needed */
	if (!strstr(flogmessage, "\n")) {
		strncat(flogmessage, "\n", 1);
	}

	if ((IS_LOGGING_TO_FILE() &&
		(set.log_level != POLLER_VERBOSITY_NONE) &&
		(strlen(set.path_logfile) != 0))) {
		if (set.logfile_processed) {
			if (!file_exists(set.path_logfile)) {
				log_file = fopen(set.path_logfile, "w");
			}else {
				log_file = fopen(set.path_logfile, "a");
			}

			if (log_file) {
				fputs(flogmessage, log_file);
				fclose(log_file);
			}else{
				if (!log_error) {
					printf("ERROR: Spine Log File Could Not Be Opened/Created\n");
					log_error = TRUE;
				}
			}
		}
	}

	if (set.log_level >= POLLER_VERBOSITY_NONE) {
		if ((strstr(flogmessage,"ERROR"))   ||
			(strstr(flogmessage,"WARNING")) ||
			(strstr(flogmessage,"FATAL"))) {
			#ifdef DISABLE_STDERR
			fp = stdout;
			#else
			fp = stderr;
			#endif
		}

		if ((set.stderr_notty) && (fp == stderr)) {
			/* do nothing stderr does not exist */
		}else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		}else{
			fprintf(fp, "%s", flogmessage);
		}
	}

	return TRUE;
}

/*! \fn int file_exists(const char *filename)
 *  \brief checks for the existance of a file.
 *  \param *filename the name of the file to check for.
 *
 *  \return TRUE if found FALSE if not.
 *
 */
int file_exists(const char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return FALSE;
	}else{
		return TRUE;
	}
}

/*! \fn all_digits(const char *string)
 *  \brief verifies that a string is contains only numeric characters
 *  \param string the string to check
 *
 *  This function has no leeway: spaces and minus signs and decimal points
 *  are not digits, and an empty string is (by convention) not
 *  all-digits too.
 *
 *  \return TRUE if not alpha or special characters found, FALSE if non numeric found
 *
 */
int all_digits(const char *string) {
	/* empty string is not all digits */
	if ( *string == '\0' ) return FALSE;

	while ( isdigit((int)*string) )
		string++;

	return *string == '\0';
}

/*! \fn is_ipaddress(const char *string)
 *  \brief verifies that a string is an ip address either v4 or v6
 *  \param string the string to check
 *
 *  This function simply checks to see if a string object is an ip address.
 *  If it is, it returns true else false.
 *
 *  \return TRUE if an ip address, or FALSE if non
 *
 */
int is_ipaddress(const char *string) {
	while (*string) {
		if ((isdigit((int)*string)) ||
			(*string == '.') ||
			(*string == ':')) {
			string++;

			continue;
		}

		return FALSE;
	}

	return TRUE;
}

/*! \fn int is_numeric(const char *string)
 *  \brief check to see if a string is long or double
 *  \param string the string to check
 *
 *  \return TRUE if long or double, FALSE if not
 *
 */
int is_numeric(char *string) {
	long local_lval;
	double local_dval;
	char *end_ptr_long, *end_ptr_double;
	int conv_base=10;
	int length;

	length = strlen(trim(string));

	if (!length) {
		return FALSE;
	}

 	/* check for an integer */
	errno = 0;
	local_lval = strtol(string, &end_ptr_long, conv_base);

	if (errno != ERANGE) {
		if (end_ptr_long == string + length) { /* integer string */
			return TRUE;
		}else if (end_ptr_long == string) {
			if (*end_ptr_long != '\0' &&
				*end_ptr_long != '.' &&
				*end_ptr_long != '-' &&
				*end_ptr_long != '+') { /* ignore partial string matches but doubles can begin with '+', '-', '.' */
				return FALSE;
			}
		}
	}else{
		end_ptr_long = NULL;
	}

 	/* check for a float */
	errno = 0;
	local_dval = strtod(string, &end_ptr_double);
	if (errno != ERANGE) {
		if (end_ptr_double == string + length) { /* floating point string */
			return TRUE;
		}
	}else{
		end_ptr_double = NULL;
	}

	return FALSE;
}

/*! \fn int is_hexadecimal(const char *str, const short ignore_space)
 *  \brief test whether a string represents a hex number.
 *  \param str string to test
 *  \param ignore_space nonzero to skip tabs and spaces
 *
 *  \return TRUE if the string is valid hex, FALSE otherwise
 *
 */
int is_hexadecimal(const char * str, const short ignore_space) {
	int i = 0;

	if (!str) return FALSE;

	while (*str) {
		switch (*str) {
		case '0': case '1': case '2': case '3':
		case '4': case '5': case '6': case '7':
		case '8': case '9':
		case 'a': case 'A': case 'b': case 'B':
		case 'c': case 'C': case 'd': case 'D':
		case 'e': case 'E': case 'f': case 'F':
		case '"':
			break;
		case ' ': case '\t':
			if (ignore_space) break;
		default:
			return FALSE;
		}
		str++;
		i++;
	}

	if (i < 3) return FALSE;

	return TRUE;
}

/*! \fn char *strip_alpha(char *string)
 *  \brief remove trailing alpha characters from a string.
 *  \param string the string to strip characters from
 *
 *  \return a pointer to the modified string
 *
 */
char *strip_alpha(char *string) {
	int i;

	i = strlen(string);

	while (i >= 0) {
		if (isdigit((int)string[i])) {
			break;
		}else{
			string[i] = '\0';
		}
		i--;
	}

	return string;
}

/*! \fn char *add_slashes(char *string)
 *  \brief add escaping to back slashes on for Windows type commands.
 *  \param string the string to replace slashes
 *
 *  \return a pointer to the modified string. Variable must be freed by parent.
 *
 */
char *add_slashes(char *string) {
	int length;
	int position;
	int new_position;
	char *return_str;

	if (!(return_str = (char *) malloc(BUFSIZE))) {
		die("ERROR: Fatal malloc error: util.c add_slashes!");
	}
	return_str[0] = '\0';

	length       = strlen(string);
	position     = 0;
	new_position = 0;

	/* simply return on blank string */
	if (!length) {
		return return_str;
	}

	while (position < length) {
		/* backslash detected, change to forward slash */
		if (string[position] == '\\') {
			return_str[new_position] = '\\';
			new_position++;
			return_str[new_position] = '\\';
		}else{
			return_str[new_position] = string[position];
		}
		new_position++;
		position++;
	}
	return_str[new_position] = '\0';

	return(return_str);
}

/*! \fn char *strncopy(char *dst, const char *src, size_t obuf)
 *  \brief copies source to destination add a NUL terminator
 *
 *	Copy from source to destination, insuring a NUL termination.
 *	The size of the buffer *includes* the terminating NUL. Note
 *	that strncpy() does NOT NUL terminate if the source is the
 *	size of the destination (yuck).
 *
 *	NOTE: it's very common to call this as:
 *
 *	  strncopy(buf, src, sizeof buf)
 *
 *	so we provide an STRNCOPY() macro which adds the size.
 *
 *  \return pointer to destination string
 *
 */
char *strncopy(char *dst, const char *src, size_t obuf) {
	assert(dst != 0);
	assert(src != 0);

	size_t len;

	len = strlen(src);

	if (!len) {
		dst[0] = '\0';
	}else if (len < obuf) {
		strncpy(dst, src, len);
		dst[len] = '\0';
	}else{
		strncpy(dst, src, --obuf);
		dst[obuf] = '\0';
	}

	return dst;
}

/*! \fn double get_time_as_double()
 *  \brief fetches system time as a double-precison value
 *
 *  \return system time (at microsecond resolution) as a double
 */
double get_time_as_double(void) {
	struct timeval now;

	gettimeofday(&now, NULL);

	return TIMEVAL_TO_DOUBLE(now);
}

/*! \fn string *get_host_poll_time()
 *  \brief fetches start time for host being polled
 *
 *  \return host_time as a string
 */
char *get_host_poll_time() {
	time_t nowbin;
	struct tm now_time;
	struct tm *now_ptr;
	char *host_time;

	#define HOST_TIME_STRING_LEN 20

	if (!(host_time = (char *) malloc(HOST_TIME_STRING_LEN))) {
		die("ERROR: Fatal malloc error: util.c host_time");
	}
	host_time[0] = '\0';

	/* get time for poller_output table */
	if (time(&nowbin) == (time_t) - 1) {
		die("ERROR: Could not get time of day from time() util.c get_host_poll_time()");
	}
	localtime_r(&nowbin,&now_time);
	now_ptr = &now_time;

	if (strftime(host_time, HOST_TIME_STRING_LEN, "%Y-%m-%d %H:%M:%S", now_ptr) == (size_t) 0) {
		die("ERROR: Could not get string from strftime() util.c get_host_poll_time()");
	}

	return(host_time);
}

/*! \fn trim()
 *  \brief removes leading and trailing blanks, tabs, line feeds and
 *         carriage returns from a string.
 *
 *  \return the trimmed string.
 */
char *trim(char *str) {
	return ltrim(rtrim(str));
}

/*! \fn rtrim()
 *  \brief removes trailing blanks, tabs, line feeds, carriage returns
 *         single and double quotes and back-slashed from a string.
 *
 *  \return the trimmed string.
 */
char *rtrim(char *str) {
	char    *end;
	char    *trim = " \"\'\\\t\n\r";

	if (!str) return NULL;

	end = str + strlen(str);

	while (end-- > str) {
		if (!strchr(trim, *end)) return str;

		*end = 0;
	}

	return str;
}

/*! \fn ltrim()
 *  \brief removes leading blanks, tabs, line feeds, carriage returns
 *         single and double quotes and back-slashed from a string.
 *
 *  \return the trimmed string.
 */
char *ltrim(char *str) {
	char    *trim = " \"\'\\\t\n\r";

	if (!str) return NULL;

	while (*str) {
		if (!strchr(trim, *str)) return str;

		++str;
	}

	return str;
}

/*! \fn reverse()
 *  \brief reverses a string in place.
 *
 *  \return the reversed string.
 */
char *reverse(char* str) {
	int end   = strlen(str)-1;
	int start = 0;

	while (start < end) {
		str[start] ^= str[end];
		str[end]   ^= str[start];
		str[start] ^= str[end];

		++start;
		--end;
	}

	return str;
}

/*! \fn char_count()
 *  \brief counts occurrences of char in string.
 *
 *  \return number of occurrences.
 */
int char_count(const char *str, int chr) {
	const unsigned char *my_str = (const unsigned char *) str;
	const unsigned char my_chr = chr;
	int count = 0;

	if (!my_chr) return 1;

	while (*my_str) {
		if (*my_str++ == my_chr) {
			count++;
		}
	}
	return count;
}

unsigned long long hex2dec(char *str) {
	int i = 0;
	unsigned long long number = 0;
	
	if (!str) return 0;

	/* first revers the string */
	reverse(str);
	
	while (*str) {
		switch (*str) {
		case '0': 
			i++;
			break;
		case '1': 
			number += pow(16, i) * 1;
			i++;
			break;
		case '2': 
			number += pow(16, i) * 2;
			i++;
			break;
		case '3':
			number += pow(16, i) * 3;
			i++;
			break;
		case '4': 
			number += pow(16, i) * 4;
			i++;
			break;
		case '5': 
			number += pow(16, i) * 5;
			i++;
			break;
		case '6': 
			number += pow(16, i) * 6;
			i++;
			break;
		case '7':
			number += pow(16, i) * 7;
			i++;
			break;
		case '8': 
			number += pow(16, i) * 8;
			i++;
			break;
		case '9':
			number += pow(16, i) * 9;
			i++;
			break;
		case 'a': case 'A': 
			number += pow(16, i) * 10;
			i++;
			break;
		case 'b': case 'B':
			number += pow(16, i) * 11;
			i++;
			break;
		case 'c': case 'C': 
			number += pow(16, i) * 12;
			i++;
			break;
		case 'd': case 'D':
			number += pow(16, i) * 13;
			i++;
			break;
		case 'e': case 'E': 
			number += pow(16, i) * 14;
			i++;
			break;
		case 'f': case 'F':
			number += pow(16, i) * 15;
			i++;
			break;
		case '"': case ' ': case '\t':
			break;
		default:
			return 0;
		}

		str++;
	}

	return number;
}

int hasCaps() {
	#ifdef HAVE_LCAP
	cap_t caps;
	cap_value_t capval;
	cap_flag_value_t capflag;

	/* Recommended caps: cap_net_raw=eip */
	caps = cap_get_proc();
	if (caps == NULL) {
		SPINE_LOG(("ERROR: cap_get_proc failed."));
		return FALSE;
	}

    /* check if cap_net_raw is in effective set */
	if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &capflag)) {
		SPINE_LOG(("ERROR: cap_get_flag for CAP_NET_RAW failed. ICMP ping will not work as non-root user."));
		return FALSE;
	}

	if (capflag != CAP_SET) {
		SPINE_LOG(("ERROR: Capability CAP_NET_RAW is not set. ICMP ping will not work as non-root user."));
		return FALSE;
	}

	SPINE_LOG_DEBUG(("DEBUG: Capability CAP_NET_RAW is set."));
	cap_free(caps);

	return TRUE;
	#else
	return FALSE;
	#endif
}

void checkAsRoot() {
	#ifndef __CYGWIN__
	#ifdef SOLAR_PRIV
	priv_set_t *privset;
	char *p;

	/* Get the basic set */
	privset = priv_str_to_set("basic", ",", NULL);
	if (privset == NULL) {
		die("ERROR: Could not get basic privset from priv_str_to_set().");
	} else {
		p = priv_set_to_str(privset, ',', 0);
		SPINE_LOG_DEBUG(("DEBUG: Basic privset is: '%s'.", p != NULL ? p : "Unknown"));
	}

	/* Add priviledge to send/receive ICMP packets */
	if (priv_addset(privset, PRIV_NET_ICMPACCESS) < 0) {
		SPINE_LOG_DEBUG(("Warning: Addition of PRIV_NET_ICMPACCESS to privset failed: '%s'.", strerror(errno)));
	}

	/* Compute the set of privileges that are never needed */
	priv_inverse(privset);

	/* Remove the set of unneeded privs from Permitted (and by
	 * implication from Effective) */
	if (setppriv(PRIV_OFF, PRIV_PERMITTED, privset) < 0) {
		SPINE_LOG_DEBUG(("Warning: Dropping privileges from PRIV_PERMITTED failed: '%s'.", strerror(errno)));
	}

	/* Remove unneeded priv set from Limit to be safe */
	if (setppriv(PRIV_OFF, PRIV_LIMIT, privset) < 0) {
		SPINE_LOG_DEBUG(("Warning: Dropping privileges from PRIV_LIMIT failed: '%s'.", strerror(errno)));
	}

	boolean_t pe = priv_ineffect(PRIV_NET_ICMPACCESS);
	SPINE_LOG_DEBUG(("DEBUG: Privilege PRIV_NET_ICMPACCESS is: '%s'.", pe != 0 ? "Enabled" : "Disabled"));

	set.icmp_avail = pe;

	/* Free the privset */
	priv_freeset(privset);
	free(p);
	#else
	if (hasCaps() != TRUE) {
		seteuid(0);
	
		if (geteuid() != 0) {
			SPINE_LOG_DEBUG(("WARNING: Spine NOT running asroot.  This is required if using ICMP.  Please run \"chown root:root spine;chmod +s spine\" to resolve."));
			set.icmp_avail = FALSE;
		}else{
			SPINE_LOG_DEBUG(("DEBUG: Spine is running asroot."));
			set.icmp_avail = TRUE;
			seteuid(getuid());
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Spine has cap_net_raw capability."));
		set.icmp_avail = TRUE;
	}
	#endif
	#endif
}
