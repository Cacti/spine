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
*/

#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include "common.h"
#include "cactid.h"
#include "util.h"
#include "snmp.h"
#include "locks.h"
#include "sql.h"
#include "php.h"

/*! \fn void set_option(const char *option, const char *value)
 *  \brief Override cactid setting from the Cacti settings table.
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
 *  ===TODO: use a prepared statement?
 *
 *  \return the database option setting
 *
 */
static const char *getsetting(MYSQL *psql, const char *setting) {
	char      qstring[256];
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int       i;

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (i=0; i<nopts; i++) {
		if (strcasecmp(setting, opttable[i].opt) == 0) {
			/* FOUND IT! */
			return opttable[i].val;
		}
	}

	sprintf(qstring, "SELECT value FROM settings WHERE name = '%s'", setting);

	result = db_query(psql, qstring);

	if ((mysql_num_rows(result) > 0) &&
		(mysql_row = mysql_fetch_row(result)) != 0)	{
		return mysql_row[0];
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

	if (strcasecmp(rc, "on"  ) == 0 ||
		strcasecmp(rc, "yes" ) == 0 ||
		strcasecmp(rc, "true") == 0 ||
		strcasecmp(rc, "1"   ) == 0 ) {
		return TRUE;
	}

	if (strcasecmp(rc, "off"  ) == 0 ||
		strcasecmp(rc, "no"   ) == 0 ||
		strcasecmp(rc, "false") == 0 ||
		strcasecmp(rc, "0"    ) == 0 ) {
		return FALSE;
	}

	/* doesn't really match one of our keywords: what to do? */

	return dflt;
}

/*! \fn void read_config_options(config_t *set)
 *  \brief reads default cactid runtime parameters from the database and set's the global array
 *  \param *set - A structure containing all global Cactid runtime parameters
 *  
 *  load default values from the database for poller processing
 *
 */
void read_config_options(config_t *set) {
	MYSQL mysql;
	MYSQL_RES *result;
	int num_rows;
	char web_root[BUFSIZE];
	char sqlbuf[256], *sqlp = sqlbuf;
	const char *res;

	db_connect(set->dbdb, &mysql);

	/* get logging level from database - overrides cactid.conf */
	if ((res = getsetting(&mysql, "log_verbosity")) != 0 ) {
		const int n = atoi(res);
		if (n != 0) set->log_level = n;
	}

	/* determine script server path operation and default log file processing */
	if ((res = getsetting(&mysql, "path_webroot")) != 0 ) {
		snprintf(set->path_php_server, sizeof(set->path_php_server)-1, "%s/script_server.php", res);
		snprintf(web_root, sizeof(web_root)-1, "%s", res);
	}

	/* determine logfile path */
	if ((res = getsetting(&mysql, "path_cactilog")) != 0 ) {
		if (strlen(res) != 0) {
			snprintf(set->path_logfile, sizeof(set->path_logfile)-1, res);
		}else{
			if (strlen(web_root) != 0) {
				snprintf(set->path_logfile, sizeof(set->path_logfile)-1, "%s/log/cacti.log", web_root);
			}else{
				memset(set->path_logfile, 0, sizeof(set->path_logfile));
			}
		}
	}else{
		snprintf(set->path_logfile, sizeof(set->path_logfile)-1, "%s/log/cacti.log", web_root);
 	}

	/* log the path_webroot variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The path_php_server variable is %s\n", set->path_php_server);
	}

	/* log the path_cactilog variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The path_cactilog variable is %s\n", set->path_logfile);
	}

	/* determine log file, syslog or both, default is 1 or log file only */
	if ((res = getsetting(&mysql, "log_destination")) != 0 ) {
		set->log_destination = parse_logdest(res, LOGDEST_FILE);
	}else{
		set->log_destination = LOGDEST_FILE;
	}

	/* log the log_destination variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The log_destination variable is %i (%s)\n",
			set->log_destination,
			printable_logdest(set->log_destination));
	}

	/* get PHP Path Information for Scripting */
	if ((res = getsetting(&mysql, "path_php_binary")) != 0 ) {
		STRNCOPY(set->path_php, res);
	}

	/* log the path_php variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The path_php variable is %s\n", set->path_php);
	}

	/* set availability_method */
	if ((res = getsetting(&mysql, "availability_method")) != 0 ) {
		set->availability_method = atoi(res);
	}

	/* log the availability_method variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The availability_method variable is %i\n", set->availability_method);
	}

	/* set ping_recovery_count */
	if ((res = getsetting(&mysql, "ping_recovery_count")) != 0 ) {
		set->ping_recovery_count = atoi(res);
	}

	/* log the ping_recovery_count variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The ping_recovery_count variable is %i\n", set->ping_recovery_count);
	}

	/* set ping_failure_count */
	if ((res = getsetting(&mysql, "ping_failure_count")) != 0) {
		set->ping_failure_count = atoi(res);
	}

	/* log the ping_failure_count variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The ping_failure_count variable is %i\n", set->ping_failure_count);
	}

	/* set ping_method */
	if ((res = getsetting(&mysql, "ping_method")) != 0 ) {
		set->ping_method = atoi(res);
	}

	/* log the ping_method variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The ping_method variable is %i\n", set->ping_method);
	}

	/* set ping_retries */
	if ((res = getsetting(&mysql, "ping_retries")) != 0 ) {
		set->ping_retries = atoi(res);
	}

	/* log the ping_retries variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The ping_retries variable is %i\n", set->ping_retries);
	}

	/* set ping_timeout */
	if ( (res = getsetting(&mysql, "ping_timeout")) != 0 ) {
		set->ping_timeout = atoi(res);
	}

	/* log the ping_timeout variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The ping_timeout variable is %i\n", set->ping_timeout);
	}

	/* set logging option for errors */
	set->log_perror = getboolsetting(&mysql, "log_perror", FALSE);

	/* log the log_perror variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The log_perror variable is %i\n", set->log_perror);
	}

	/* set logging option for errors */
	set->log_pwarn = getboolsetting(&mysql, "log_pwarn", FALSE);

	/* log the log_pwarn variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The log_pwarn variable is %i\n", set->log_pwarn);
	}

	/* set logging option for statistics */
	set->log_pstats = getboolsetting(&mysql, "log_pstats", FALSE);

	/* log the log_pstats variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The log_pstats variable is %i\n", set->log_pstats);
	}

	/* get Cacti defined max threads override cactid.conf */
	if ((res = getsetting(&mysql, "max_threads")) != 0 ) {
		set->threads = atoi(res);
		if (set->threads > MAX_THREADS) {
			set->threads = MAX_THREADS;
		}
	}

	/* log the threads variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The threads variable is %i\n", set->threads);
	}

	/* get the poller_interval for those who have elected to go with a 1 minute polling interval */
	if ((res = getsetting(&mysql, "poller_interval")) != 0 ) {
		set->poller_interval = atoi(res);
	}else{
		set->poller_interval = 0;
	}

	/* log the poller_interval variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		if (set->poller_interval == 0) {
			cacti_log("DEBUG: The polling interval is the system default\n");
		}else{
			cacti_log("DEBUG: The polling interval is %i seconds\n", set->poller_interval);
		}
	}

	/* get the concurrent_processes variable to determine thread sleep values */
	if ((res = getsetting(&mysql, "concurrent_processes")) != 0 ) {
		set->num_parent_processes = atoi(res);
	}else{
		set->num_parent_processes = 1;
	}

	/* log the concurrent processes variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The number of concurrent processes is %i\n", set->num_parent_processes);
	}

	/* get the script timeout to establish timeouts */
	if ((res = getsetting(&mysql, "script_timeout")) != 0 ) {
		set->script_timeout = atoi(res);
		if (set->script_timeout < 5) {
			set->script_timeout = 5;
		}
	}else{
		set->script_timeout = 25;
	}

	/* log the script timeout value */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The script timeout is %i\n", set->script_timeout);
	}

	/* get the number of script server processes to run */
	if ((res = getsetting(&mysql, "php_servers")) != 0 ) {
		set->php_servers = atoi(res);

		if (set->php_servers > MAX_PHP_SERVERS) {
			set->php_servers = MAX_PHP_SERVERS;
		}
		
		if (set->php_servers <= 0) {
			set->php_servers = 1;
		}
	}else{
		set->php_servers = 2;
	}

	/* log the script timeout value */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The number of php script servers to run is %i\n", set->php_servers);
	}

	/*----------------------------------------------------------------
	 * determine if the php script server is required by searching for
	 * all the host records for an action of POLLER_ACTION_PHP_SCRIPT_SERVER.
	 * If we get even one, it means we have to deal with the PHP script
	 * server.
	 *
	 */
	set->php_required = FALSE;		/* assume no */

	sqlp = sqlbuf;
	sqlp += sprintf(sqlp, "SELECT action FROM poller_item");
	sqlp += sprintf(sqlp, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
	sqlp += append_hostrange(sqlp, "host_id", set);
	sqlp += sprintf(sqlp, " LIMIT 1");

	result = db_query(&mysql, sqlbuf);
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) set->php_required = TRUE;

	/* log the requirement for the script server */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: StartHost='%i', EndHost='%i', TotalPHPScripts='%i'\n", set->start_host_id,set->end_host_id,num_rows);

		cacti_log("DEBUG: The PHP Script Server is %sRequired\n",
			set->php_required
			? ""
			: "Not ");
	}

	/* determine the maximum oid's to obtain in a single get request */
	if ((res = getsetting(&mysql, "max_get_size")) != 0 ) {
		set->snmp_max_get_size = atoi(res);

		if (set->snmp_max_get_size > 128) {
			set->snmp_max_get_size = 128;
		}
	}else{
		set->snmp_max_get_size = 25;
	}

	/* log the snmp_max_get_size variable */
	if (set->log_level == POLLER_VERBOSITY_DEBUG) {
		cacti_log("DEBUG: The Maximum SNMP OID Get Size is %i\n", set->snmp_max_get_size);
	}

	mysql_free_result(result);
	db_disconnect(&mysql);
}

/*! \fn int read_cactid_config(char *file, config_t *set) 
 *  \brief obtain default startup variables from the cactid.conf file.
 *  \param file the cactid config file
 *  \param set global runtime parameters
 *
 *  \return 0 if successful or -1 if the file could not be opened
 */
int read_cactid_config(char *file, config_t *set) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];

	if ((fp = fopen(file, "rb")) == NULL) {
		if (set->log_level == POLLER_VERBOSITY_DEBUG) {
			printf("ERROR: Could not open config file [%s]\n", file);
		}
		return -1;
	}else{
		printf("CACTID: Using cactid config file [%s]\n", file);
		while(!feof(fp)) {
			fgets(buff, BUFSIZE, fp);
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%15s %255s", p1, p2);

				if (!strcasecmp(p1, "DB_Host")) snprintf(set->dbhost, sizeof(set->dbhost)-1, "%s", p2);
				else if (!strcasecmp(p1, "DB_Database")) snprintf(set->dbdb, sizeof(set->dbdb)-1, "%s", p2);
				else if (!strcasecmp(p1, "DB_User")) snprintf(set->dbuser, sizeof(set->dbuser)-1, "%s", p2);
				else if (!strcasecmp(p1, "DB_Pass")) snprintf(set->dbpass, sizeof(set->dbpass)-1, "%s", p2);
				else if (!strcasecmp(p1, "DB_Port")) set->dbport = atoi(p2);
				else {
					printf("WARNING: Unrecongized directive: %s=%s in %s\n", p1, p2, file);
				}
			}
		}

		return 0;
	}
}

/*! \fn void config_defaults(config_t *set)
 *  \brief populates the global configuration structure with default cactid.conf file settings
 *  \param *set global runtime parameters
 *
 */
void config_defaults(config_t *set) {
	set->threads = DEFAULT_THREADS;
	set->dbport = DEFAULT_DB_PORT;

	STRNCOPY(set->dbhost, DEFAULT_DB_HOST);
	STRNCOPY(set->dbdb,   DEFAULT_DB_DB  );
	STRNCOPY(set->dbuser, DEFAULT_DB_USER);
	STRNCOPY(set->dbpass, DEFAULT_DB_PASS);

	STRNCOPY(config_paths[0], CONFIG_PATH_1);
	STRNCOPY(config_paths[1], CONFIG_PATH_2);

	set->log_destination = LOGDEST_FILE;
}

/*! \fn void exit_cactid() 
 *  \brief shut's down Cactid after a fatal error.  Make sure you shut down the script server.
 *
 */
void exit_cactid() {
	if (set.parent_fork == CACTID_PARENT) {
		if (set.php_initialized) {
			php_close(PHP_INIT);
		}

		cacti_log("ERROR: Cactid Parent Process Encountered a Serious Error and Must Exit\n");
	}else{
		cacti_log("ERROR: Cactid Fork Process Encountered a Serious Error and Must Exit\n");			
	}

	exit(-1);
}

/*! \fn void cacti_log(char *logmessage)
 *  \brief output's log information to the desired cacti logfile.
 *  \param *logmessage a pointer to the pre-formated log message.
 *
 */
void cacti_log(const char *format, ...) {
	va_list	args;

	FILE *log_file = NULL;
	FILE *fp = NULL;

	/* variables for time display */
	time_t nowbin;
	struct tm now_time;
	struct tm *now_ptr;

	char logprefix[40]; /* Formatted Log Prefix */
	char ulogmessage[LOGSIZE];	/* Un-Formatted Log Message */
	char flogmessage[LOGSIZE];	/* Formatted Log Message */
	extern config_t set;
	int fileopen = 0;

	va_start(args, format);
	vsprintf(ulogmessage, format, args);
	va_end(args);

	/* default for "console" messages to go to stdout */
	fp = stdout;

	/* log message prefix */
	snprintf(logprefix, sizeof(logprefix)-1, "CACTID: Poller[%i] ", set.poller_id);

	if (set.log_destination == LOGDEST_STDOUT) {
		puts(ulogmessage);
		return;
	}

	if (((set.log_destination == LOGDEST_FILE) || (set.log_destination == LOGDEST_BOTH)) && (set.log_level != POLLER_VERBOSITY_NONE) && (strlen(set.path_logfile) != 0)) {
		while (!fileopen) {
			if (!file_exists(set.path_logfile)) {
				log_file = fopen(set.path_logfile, "w");
			}else {
				log_file = fopen(set.path_logfile, "a");
			}

			if (log_file != NULL) {
				fileopen = 1;
			}else {
				if (set.log_level == POLLER_VERBOSITY_DEBUG) {
					fprintf(stderr, "ERROR: Could not open Logfile will not be logging\n");
				}
				break;
			}
		}
	}

	/* get time for poller_output table */
	if (time(&nowbin) == (time_t) - 1) {
		fprintf(stderr, "ERROR: Could not get time of day from time()\n");
		exit_cactid();
	}
	localtime_r(&nowbin,&now_time);
	now_ptr = &now_time;

	if (strftime(flogmessage, 50, "%m/%d/%Y %I:%M:%S %p - ", now_ptr) == (size_t) 0)
		fprintf(stderr, "ERROR: Could not get string from strftime()\n");

	strncat(flogmessage, logprefix, strlen(logprefix));
	strncat(flogmessage, ulogmessage, strlen(ulogmessage));

	if (fileopen != 0) {
		fputs(flogmessage, log_file);
		fclose(log_file);
	}

	/* output to syslog/eventlog */
	if ((set.log_destination == LOGDEST_SYSLOG) || (set.log_destination == LOGDEST_BOTH)) {
		thread_mutex_lock(LOCK_SYSLOG);
		openlog("Cacti", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
		if ((strstr(flogmessage,"ERROR")) && (set.log_perror)) {
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

	if (set.log_level >= POLLER_VERBOSITY_NONE) {
		if ((strstr(flogmessage,"ERROR")) || (strstr(flogmessage,"WARNING"))) {
			fp = stderr;
		}

		snprintf(flogmessage, LOGSIZE-1, "CACTID: %s", ulogmessage);
		fprintf(fp, "%s", flogmessage);
	}
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

	while ( isdigit(*string) )
		string++;

	return *string == '\0';
}

/*! \fn int is_numeric(const char *string)
 *  \brief check to see if a string is long or double
 *  \param string the string to check
 *
 *  \return TRUE if long or double, FALSE if not
 *
 */
int is_numeric(const char *string)
{
	long local_lval;
	double local_dval;
	char *end_ptr_long, *end_ptr_double;
	int conv_base=10;
	int length;

	length = strlen(string);

	if (!length) {
		return FALSE;
	}

 	/* check for an integer */
	errno = 0;
	local_lval = strtol(string, &end_ptr_long, conv_base);
	if (errno != ERANGE) {
		if (end_ptr_long == string + length) { /* integer string */
			return TRUE;
		}else if (end_ptr_long == string && *end_ptr_long != '\0') { /* ignore partial string matches */
			return FALSE;
		}
	}else{
		end_ptr_long = NULL;
	}

	errno = 0;
	local_dval = strtod(string, &end_ptr_double);
	if (errno != ERANGE) {
		if (end_ptr_double == string + length) { /* floating point string */
			return TRUE;
		}
	}else{
		end_ptr_double = NULL;
	}

	if (!errno) {
		return TRUE;
	}else{
		return FALSE;
 	}
}

/*! \fn char *strip_alpha(char *string)
 *  \brief remove trailing alpha characters from a string.
 *  \param string the string to string characters from
 *
 *  \return a pointer to the modified string
 *
 */
char *strip_alpha(char *string)
{
	int i;
	
	i = strlen(string);

	while (i >= 0) {
		if ((string[i] > 47) && (string[i] < 58)) {
			break;
		}else{
			string[i] = '\0';
		}
		i--;
	}

	return string;
}

/*! \fn char *add_slashes(char *string, int arguments_2_strip)
 *  \brief change all backslashes to forward slashes for the first n arguements.
 *  \param string the string to replace slashes
 *  \param arguments_2_strip the number of space delimited arguments to reverse
 *
 *  \return a pointer to the modified string. Variable must be freed by parent.
 *
 */
char *add_slashes(char *string, int arguments_2_strip) {
	int length;
	int space_count;
	int position;
	int new_position;
	char *return_str;
	
	if (!(return_str = (char *) malloc(BUFSIZE))) {
		cacti_log("ERROR: Fatal malloc error: util.c add_slashes!\n");
		exit_cactid();
	}
	memset(return_str, 0, BUFSIZE);

	length = strlen(string);
	space_count = 0;
	position = 0;
	new_position = position;

	/* simply return on blank string */
	if (!length) {
		return return_str;
	}

	while (position < length) {
		/* backslash detected, change to forward slash */
		if (string[position] == '\\') {	
			/* only add slashes for first x arguments */
			if (space_count < arguments_2_strip) {
				return_str[new_position] = '/';
			}else{
				return_str[new_position] = string[position];
			}
		/* end of argument detected */
		}else if (string[position] == ' ') {
			return_str[new_position] = ' ';
			space_count++;
		/* normal character detected */
		}else{
			return_str[new_position] = string[position];
		}
		new_position++;
		position++;
	}
	return_str[new_position] = '\0';

	return(return_str);
}

/*! \fn char *strip_string_crlf(char *string)
 *  \brief remove trailing cr-lf from a string
 *  \param string the string that requires trimming
 *
 *  \return a pointer to the modified string.
 *
 */
char *strip_string_crlf(char *string) {
	char *posptr;

	posptr = strchr(string,'\n');

	while(posptr != NULL) {
		*posptr = '\0';
		posptr = strchr(string,'\n');
	}

	posptr = strchr(string,'\r');

	while(posptr != NULL) {
		*posptr = '\0';
		posptr = strchr(string,'\r');
	}

	return(string);
} 

/*! \fn char *strip_quotes(char *string)
 *  \brief remove single and double quotes from a string
 *  \param string the string that requires trimming
 *
 *  \return a pointer to the modified string.
 *
 */
char *strip_quotes(char *string) {
	int length;
	char *startptr;
	char type;

	/* find first quote in the string, determine type */
	while (1) {
		length = strlen(string);

		/* simply return on blank string */
		if (!length) {
			return string;
		}

		/* set starting postion of string */
		startptr = string;

		/* search for quote characters and remove */
		if (string[0] == '"') {
			type = '"';
			memmove(startptr, startptr+1, strlen(string) - 1);
		}else if (string[0] == '\'') {
			type = '\'';
			memmove(startptr, startptr+1, strlen(string) - 1);
		}else if (string[0] == '\\') {
			type = '\\';
			memmove(startptr, startptr+1, strlen(string) - 1);
		}else{
			break;
		}

		string[length-1] = '\0';
	}

	return string;
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

	strncpy(dst, src, --obuf);

	dst[obuf] = '\0';

	return dst;
}
