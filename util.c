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
*/

#include "common.h"
#include "spine.h"
#include "regex.h"

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
	if (nopts >= (int)(sizeof(opttable) / sizeof(opttable[0]))) {
		die("ERROR: too many --option overrides");
	}

	opttable[nopts  ].opt = option;
	opttable[nopts++].val = value;
}

/* Settings cache.
 *
 * read_config_options() looks up two dozen settings and each one was its own
 * round trip.  The settings table is small, so it is read once up front and
 * served from memory for the duration of that call.  Only ever populated and
 * used from read_config_options(), which runs before any poller thread
 * exists, so no locking is required.
 */
typedef struct setting_cache_entry {
	char *name;
	char *value;
} setting_cache_t;

static setting_cache_t *settings_cache       = NULL;
static int              settings_cache_count = 0;

static void settings_cache_free(void) {
	int i;

	if (settings_cache == NULL) return;

	for (i = 0; i < settings_cache_count; i++) {
		free(settings_cache[i].name);
		free(settings_cache[i].value);
	}

	free(settings_cache);
	settings_cache       = NULL;
	settings_cache_count = 0;
}

static void settings_cache_load(MYSQL *psql, int mode) {
	MYSQL_RES *result;
	MYSQL_ROW  row;
	my_ulonglong rows;
	setting_cache_t *table;
	int i = 0;

	assert(psql != 0);

	settings_cache_free();

	result = db_query(psql, mode, "SELECT SQL_NO_CACHE name, value FROM settings");

	if (result == NULL) return;

	rows = mysql_num_rows(result);

	if (rows == 0 || rows > (my_ulonglong) INT_MAX) {
		db_free_result(result);
		return;
	}

	table = (setting_cache_t *) calloc((size_t) rows, sizeof(setting_cache_t));

	if (table == NULL) {
		db_free_result(result);
		return;
	}

	while ((row = mysql_fetch_row(result)) != NULL && i < (int) rows) {
		if (row[0] == NULL) continue;

		table[i].name  = strdup(row[0]);
		table[i].value = strdup(row[1] != NULL ? row[1] : "");

		if (table[i].name == NULL || table[i].value == NULL) {
			free(table[i].name);
			free(table[i].value);
			break;
		}

		i++;
	}

	db_free_result(result);

	settings_cache       = table;
	settings_cache_count = i;

	SPINE_LOG_DEBUG(("DEBUG: Loaded %i Cacti settings in one query", i));
}

/*! \fn static char *getsetting(MYSQL *psql, int mode, const char *setting)
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
static char *getsetting(MYSQL *psql, int mode, const char *setting) {
	char      qstring[BUFSIZE];
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

	/* served from the bulk-loaded table when read_config_options() is running */
	if (settings_cache != NULL) {
		for (i = 0; i < settings_cache_count; i++) {
			if (STRIMATCH(setting, settings_cache[i].name)) {
				return strdup(settings_cache[i].value);
			}
		}

		return strdup("");
	}

	snprintf(qstring, sizeof(qstring), "SELECT SQL_NO_CACHE value FROM settings WHERE name = '%s'", setting);

	result = db_query(psql, mode, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);

			if (mysql_row != NULL) {
				retval = strdup(mysql_row[0]);
				db_free_result(result);
				return retval;
			}else{
				db_free_result(result);
				return strdup("");
			}
		}else{
			db_free_result(result);
			return strdup("");
		}
	}else{
		return strdup("");
	}
}

/*! \fn int putsetting(MYSQL *psql, const char *setting, const char *value)
 *  \brief Set's a specific Cacti setting.
 *
 *  Given a pointer to a database and the name of a setting, and value of that setting
 *  set the Cacti setting in the database to the value.
 *
 *  \return true for successful or false for failed
 *
 */
static int putsetting(MYSQL *psql, int mode, const char *mysetting, const char *myvalue) {
	char  qstring[BUFSIZE];
	int   result = 0;

	assert(psql    != 0);
	assert(mysetting != 0);
	assert(myvalue   != 0);

	if (set.dbonupdate == 0) {
		snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
			"VALUES ('%s', '%s') "
			"ON DUPLICATE KEY UPDATE value = VALUES(value)", mysetting, myvalue);
	} else {
		snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
			"VALUES ('%s', '%s') AS rs "
			"ON DUPLICATE KEY UPDATE value = rs.value", mysetting, myvalue);
	}

	result = db_insert(psql, mode, qstring);

	if (result == 0) {
		return TRUE;
	} else {
		return FALSE;
	}
}

/*! \fn static char *getpsetting(MYSQL *psql, const char *setting)
 *  \brief Returns a character pointer to a Cacti poller setting.
 *
 *  Given a pointer to a database and the name of a setting,
 *  return the string which represents the value from the poller table.
 *  Return NULL if we can't find a setting for whatever reason.
 *
 *  NOTE: if the user has provided one of these options on the command line,
 *  it's intercepted here and returned, overriding the database setting.
 *
 *  \return the database option setting
 *
 */
static char *getpsetting(MYSQL *psql, int mode, const char *setting) {
	char      qstring[BUFSIZE];
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

	snprintf(qstring, sizeof(qstring), "SELECT SQL_NO_CACHE %s FROM poller WHERE id = '%d'", setting, set.poller_id);

	result = db_query(psql, mode, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);

			if (mysql_row != NULL) {
				retval = strdup(mysql_row[0]);
				db_free_result(result);
				return retval;
			} else {
				db_free_result(result);
				return 0;
			}
		} else {
			db_free_result(result);
			return 0;
		}
	} else {
		return 0;
	}
}

/*! \fn static int getboolsetting(MYSQL *psql, int mode, const char *setting, int dflt)
 *  \brief Obtains a boolean option from the database.
 *
 *	Given the parameters for fetching a setting from the database,
 *	do so for a *Boolean* value. We parse the usual set of words
 *	meaning true/false, and if we don't get a value, or if we don't
 *	understand what we fetched, we use the default value provided.
 *
 *  \return boolean TRUE or FALSE based upon database setting or the DEFAULT if not found
 */
static int getboolsetting(MYSQL *psql, int mode, const char *setting, int dflt) {
	char *rc;

	assert(psql    != 0);
	assert(setting != 0);

	rc = getsetting(psql, mode, setting);

	if (rc == 0) return dflt;

	if (STRIMATCH(rc, "on"  ) ||
		STRIMATCH(rc, "yes" ) ||
		STRIMATCH(rc, "true") ||
		STRIMATCH(rc, "1"   ) ) {
		free(rc);
		return TRUE;
	}

	if (STRIMATCH(rc, "off"  ) ||
		STRIMATCH(rc, "no"   ) ||
		STRIMATCH(rc, "false") ||
		STRIMATCH(rc, "0"    ) ) {
		free(rc);
		return FALSE;
	}

	/* doesn't really match one of our keywords: what to do? */
	free(rc);

	return dflt;
}

/*! \fn static char *getglobalvariable(MYSQL *psql, const char *setting)
 *  \brief Returns a character pointer to a MySQL global variable setting.
 *
 *  Given a pointer to a database and the name of a global variable, return the string
 *  which represents that value from the settings table. Return NULL if we
 *  can't find a variable for whatever reason.
 *
 *  \return the database global variable setting
 *
 */
static char *getglobalvariable(MYSQL *psql, int mode, const char *setting) {
	char      qstring[BUFSIZE];
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

	snprintf(qstring, sizeof(qstring), "SHOW GLOBAL VARIABLES LIKE '%s'", setting);

	result = db_query(psql, mode, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);

			if (mysql_row != NULL) {
				retval = strdup(mysql_row[1]);
				db_free_result(result);
				return retval;
			} else {
				db_free_result(result);
				return 0;
			}
		} else {
			db_free_result(result);
			return 0;
		}
	} else {
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

	while (i < 100) {
		if (debug_devices[i] == '\0') break;
		if (debug_devices[i] == device_id) {
			return TRUE;
		}

		i++;
	}

	return FALSE;
}

/*! \fn static void read_availability_settings(MYSQL *psql)
 *  \brief load the device availability and ping settings
 *
 *  Split out of read_config_options() unchanged; the settings and their
 *  fallbacks are exactly as they were.
 */
static void read_availability_settings(MYSQL *psql) {
	char *res;

	/* set availability_method */
	if ((res = getsetting(psql, LOCAL, "availability_method")) != 0) {
		set.availability_method = atoi(res);
		free(res);
	}

	/* log the availability_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The availability_method variable is %i", set.availability_method));

	/* set ping_recovery_count */
	if ((res = getsetting(psql, LOCAL, "ping_recovery_count")) != 0) {
		set.ping_recovery_count = atoi(res);
		free(res);
	}

	/* log the ping_recovery_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_recovery_count variable is %i", set.ping_recovery_count));

	/* set ping_failure_count */
	if ((res = getsetting(psql, LOCAL, "ping_failure_count")) != 0) {
		set.ping_failure_count = atoi(res);
		free(res);
	}

	/* log the ping_failure_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_failure_count variable is %i", set.ping_failure_count));

	/* set ping_method */
	if ((res = getsetting(psql, LOCAL, "ping_method")) != 0) {
		set.ping_method = atoi(res);
		free(res);
	}

	/* log the ping_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_method variable is %i", set.ping_method));

	/* set ping_retries */
	if ((res = getsetting(psql, LOCAL, "ping_retries")) != 0) {
		set.ping_retries = atoi(res);
		free(res);
	}

	/* log the ping_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_retries variable is %i", set.ping_retries));

	/* set ping_timeout */
	if ((res = getsetting(psql, LOCAL, "ping_timeout")) != 0) {
		set.ping_timeout = atoi(res);
		free(res);
	} else {
		set.ping_timeout = 400;
	}

	/* log the ping_timeout variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_timeout variable is %i", set.ping_timeout));

	/* set snmp_retries */
	if ((res = getsetting(psql, LOCAL, "snmp_retries")) != 0) {
		set.snmp_retries = atoi(res);
		free(res);
	} else {
		set.snmp_retries = 3;
	}

	/* log the snmp_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The snmp_retries variable is %i", set.snmp_retries));
}

/*! \fn void read_config_options(void)
 *  \brief Reads the default Spine runtime parameters from the database and set's the global array
 *
 *  load default values from the database for poller processing
 *
 */
void read_config_options(void) {
	MYSQL      mysql;
	MYSQL      mysqlr;
	MYSQL_RES  *result;
	int        num_rows;
	int        mode;
	char       web_root[BUFSIZE];
	char       sqlbuf[HUGE_BUFSIZE];
	char       *sqlp = sqlbuf;
	size_t     remaining;
	char       *res;
	char       spine_priv[BUFSIZE];
	char       spine_auth[BUFSIZE];
	char       spine_capabilities[BUFSIZE];

	web_root[0] = '\0';

	/* publish spine snmpv3 capabilities to the database */
	memset(spine_capabilities, 0, sizeof(spine_capabilities));
	memset(spine_priv, 0, sizeof(spine_priv));
	memset(spine_auth, 0, sizeof(spine_auth));

	db_connect(LOCAL, &mysql);

	/* one round trip instead of one per setting */
	settings_cache_load(&mysql, LOCAL);

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		db_connect(REMOTE, &mysqlr);
		mode = REMOTE;
	} else {
		mode = LOCAL;
	}

	/* get the mysql server version */
	if ((res = getglobalvariable(&mysql, LOCAL, "version")) != 0) {
		snprintf(set.dbversion, BUFSIZE, "%s", res);
		free(res);
	}

	if (STRIMATCH(set.dbversion, "mariadb")) {
		set.dbonupdate = 0;
	} else if (strpos(set.dbversion, "8.") == 0) {
		set.dbonupdate = 1;
	} else {
		set.dbonupdate = 0;
	}

	/* get the cacti version from the database */
	set.cacti_version = get_cacti_version(&mysql, LOCAL);

	/* log the path_webroot variable */
	SPINE_LOG_DEBUG(("DEBUG: The binary Cacti version is %d", set.cacti_version));

	/* Warn when Spine and Cacti come from different release lines.  Point
	 * releases are expected to drift, so only major.minor is compared;
	 * cacti_version is encoded as major*1000 + minor*100 + point. */
	if (set.cacti_version > 0) {
		int spine_major = 0, spine_minor = 0, spine_point = 0;

		if (sscanf(VERSION, "%d.%d.%d", &spine_major, &spine_minor, &spine_point) >= 2) {
			int spine_line = (spine_major * 1000) + (spine_minor * 100);
			int cacti_line = (set.cacti_version / 100) * 100;

			if (spine_line != cacti_line) {
				SPINE_LOG(("WARNING: Spine %s does not match the Cacti release line (Cacti reports %d.%d). Use the Spine built for this Cacti version.",
					VERSION, set.cacti_version / 1000, (set.cacti_version / 100) % 10));
			}
		}
	}

	/* get logging level from database - overrides spine.conf */
	if ((res = getsetting(&mysql, LOCAL, "log_verbosity")) != 0) {
		const int n = atoi(res);
		free(res);
		if (n != 0) set.log_level = n;
	}

	/* determine script server path operation and default log file processing */
	if ((res = getsetting(&mysql, LOCAL, "path_webroot")) != 0) {
		snprintf(set.path_php_server, BUFSIZE, "%s/script_server.php", res);
		snprintf(web_root, BUFSIZE, "%s", res);
		free(res);
	}

	/* determine logfile path */
	if ((res = getsetting(&mysql, LOCAL, "path_cactilog")) != 0) {
		if (strlen(res) != 0) {
			snprintf(set.path_logfile, DBL_BUFSIZE, "%s", res);
		} else {
			if (strlen(web_root) != 0) {
				snprintf(set.path_logfile, DBL_BUFSIZE, "%s/log/cacti.log", web_root);
			} else {
				set.path_logfile[0] ='\0';
			}
		}
		free(res);
	} else {
		snprintf(set.path_logfile, DBL_BUFSIZE, "%s/log/cacti.log", web_root);
 	}

	/* get log separator */
	if ((res = getsetting(&mysql, LOCAL, "default_datechar")) != 0) {
		set.log_datetime_separator = atoi(res);
		free(res);

		if (set.log_datetime_separator < GDC_MIN || set.log_datetime_separator > GDC_MAX) {
			set.log_datetime_separator = GDC_DEFAULT;
		}
	}

	/* get log date format */
	if ((res = getsetting(&mysql, LOCAL, "default_date_format")) != 0) {
		set.log_datetime_format = atoi(res);
		free(res);

		if (set.log_datetime_format < GD_MIN || set.log_datetime_format > GD_MAX) {
			set.log_datetime_format = GD_DEFAULT;
		}
	}

	/* determine log file, syslog or both, default is 1 or log file only */
	if ((res = getsetting(&mysql, LOCAL, "log_destination")) != 0) {
		set.log_destination = parse_logdest(res, LOGDEST_FILE);
		free(res);
	} else {
		set.log_destination = LOGDEST_FILE;
	}

	/* log the path_webroot variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php_server variable is %s", set.path_php_server));

	/* log the path_cactilog variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_cactilog variable is %s", set.path_logfile));

	/* the version variable */
	SPINE_LOG_DEBUG(("DEBUG: The version variable is %s", set.dbversion));

	/* log the log_destination variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_destination variable is %i (%s)",
		set.log_destination,
		printable_logdest(set.log_destination)));

	set.logfile_processed = TRUE;

	/* get PHP Path Information for Scripting */
	if ((res = getsetting(&mysql, LOCAL, "path_php_binary")) != 0) {
		STRNCOPY(set.path_php, res);
		free(res);
	}

	/* log the path_php variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php variable is %s", set.path_php));

	read_availability_settings(&mysql);

	/* set logging option for errors */
	set.log_perror = getboolsetting(&mysql, LOCAL, "log_perror", FALSE);

	/* log the log_perror variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_perror variable is %i", set.log_perror));

	/* set logging option for errors */
	set.log_pwarn = getboolsetting(&mysql, LOCAL, "log_pwarn", FALSE);

	/* log the log_pwarn variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pwarn variable is %i", set.log_pwarn));

	/* set option to increase insert performance */
	set.boost_redirect = getboolsetting(&mysql, LOCAL, "boost_redirect", FALSE);

	/* log the boost_redirect variable */
	SPINE_LOG_DEBUG(("DEBUG: The boost_redirect variable is %i", set.boost_redirect));

	/* set option for determining if boost is enabled */
	set.boost_enabled = getboolsetting(&mysql, LOCAL, "boost_rrd_update_enable", FALSE);

	/* log the boost_rrd_update_enable variable */
	SPINE_LOG_DEBUG(("DEBUG: The boost_rrd_update_enable variable is %i", set.boost_enabled));

	/* set logging option for statistics */
	set.log_pstats = getboolsetting(&mysql, LOCAL, "log_pstats", FALSE);

	/* log the log_pstats variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pstats variable is %i", set.log_pstats));

	/* get Cacti defined max threads override spine.conf */
	if (set.threads_set == FALSE) {
		if ((res = getpsetting(&mysql, mode, "threads")) != 0) {
			set.threads = atoi(res);
			free(res);
			if (set.threads > MAX_THREADS) {
				set.threads = MAX_THREADS;
			}
		}
	}

	/* log the threads variable */
	SPINE_LOG_DEBUG(("DEBUG: The threads variable is %i", set.threads));

	/* get the poller_interval for those who have elected to go with a 1 minute polling interval */
	if ((res = getsetting(&mysql, LOCAL, "poller_interval")) != 0) {
		set.poller_interval = atoi(res);
		free(res);
	} else {
		set.poller_interval = 0;
	}

	/* log the poller_interval variable */
	if (set.poller_interval == 0) {
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is the system default"));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is %i seconds", set.poller_interval));
	}

	/* get the concurrent_processes variable to determine thread sleep values */
	if ((res = getsetting(&mysql, LOCAL, "concurrent_processes")) != 0) {
		set.num_parent_processes = atoi(res);
		free(res);
	} else {
		set.num_parent_processes = 1;
	}

	/* log the concurrent processes variable */
	SPINE_LOG_DEBUG(("DEBUG: The number of concurrent processes is %i", set.num_parent_processes));

	/* get the script timeout to establish timeouts */
	if ((res = getsetting(&mysql, LOCAL, "script_timeout")) != 0) {
		set.script_timeout = atoi(res);
		free(res);
		if (set.script_timeout < 5) {
			set.script_timeout = 5;
		}
	} else {
		set.script_timeout = 25;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The script timeout is %i", set.script_timeout));

	/* get selective_device_debug string */
	if ((res = getsetting(&mysql, LOCAL, "selective_device_debug")) != 0) {
		STRNCOPY(set.selective_device_debug, res);
		free(res);
	}

	/* log the selective_device_debug variable */
	SPINE_LOG_DEBUG(("DEBUG: The selective_device_debug variable is %s", set.selective_device_debug));

	/* get spine_log_level */
	if ((res = getsetting(&mysql, LOCAL, "spine_log_level")) != 0) {
		set.spine_log_level = atoi(res);
		free(res);
	}

	/* log the spine_log_level variable */
	SPINE_LOG_DEBUG(("DEBUG: The spine_log_level variable is %i", set.spine_log_level));

	/* get the number of script server processes to run */
	if ((res = getsetting(&mysql, LOCAL, "php_servers")) != 0) {
		set.php_servers = atoi(res);
		free(res);

		if (set.php_servers > MAX_PHP_SERVERS) {
			set.php_servers = MAX_PHP_SERVERS;
		}

		if (set.php_servers <= 0) {
			set.php_servers = 1;
		}
	} else {
		set.php_servers = 2;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of php script servers to run is %i", set.php_servers));

	/* get the number of active profiles on the system run */
	if ((res = getsetting(&mysql, LOCAL, "active_profiles")) != 0) {
		set.active_profiles = atoi(res);
		free(res);

		if (set.active_profiles <= 0) {
			set.active_profiles = 0;
		}
	} else {
		set.active_profiles = 0;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of active data source profiles is %i", set.active_profiles));

	/* get the number of snmp_ports in use */
	if ((res = getsetting(&mysql, LOCAL, "total_snmp_ports")) != 0) {
		set.total_snmp_ports = atoi(res);
		free(res);

		if (set.total_snmp_ports <= 0) {
			set.total_snmp_ports = 0;
		}
	} else {
		set.total_snmp_ports = 0;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of snmp ports on the system is %i", set.total_snmp_ports));

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
		remaining = sizeof(sqlbuf);
		spine_appendf(&sqlp, &remaining, "SELECT SQL_NO_CACHE action FROM poller_item");
		spine_appendf(&sqlp, &remaining, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += append_hostrange(sqlp, "host_id");
		remaining = sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf);
		spine_appendf(&sqlp, &remaining, " AND poller_id=%i", set.poller_id);
		spine_appendf(&sqlp, &remaining, " LIMIT 1");

		result = db_query(&mysql, LOCAL, sqlbuf);
		num_rows = mysql_num_rows(result);
		db_free_result(result);

		if (num_rows > 0) set.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: StartDevice='%i', EndDevice='%i', TotalPHPScripts='%i'",
			set.start_host_id,
			set.end_host_id,
			num_rows));
	} else {
		sqlp = sqlbuf;
		remaining = sizeof(sqlbuf);
		spine_appendf(&sqlp, &remaining, "SELECT SQL_NO_CACHE action FROM poller_item");
		spine_appendf(&sqlp, &remaining, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		spine_appendf(&sqlp, &remaining, " AND host_id IN(%s)", set.host_id_list);
		spine_appendf(&sqlp, &remaining, " AND poller_id=%i", set.poller_id);
		spine_appendf(&sqlp, &remaining, " LIMIT 1");

		result = db_query(&mysql, LOCAL, sqlbuf);
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
	if ((res = getsetting(&mysql, LOCAL, "max_get_size")) != 0) {
		set.snmp_max_get_size = atoi(res);
		free(res);

		if (set.snmp_max_get_size > 128) {
			set.snmp_max_get_size = 128;
		}
	} else {
		set.snmp_max_get_size = 25;
	}

	/* log the snmp_max_get_size variable */
	SPINE_LOG_DEBUG(("DEBUG: The Maximum SNMP OID Get Size is %i", set.snmp_max_get_size));

	#ifndef NETSNMP_DISABLE_MD5
	strcat(spine_auth, "MD5");
	#endif

	strcat(spine_auth, (strlen(spine_auth) > 0 ? ",SHA":"SHA"));

	#if defined(NETSNMP_USMAUTH_HMAC128SHA224)
	strcat(spine_auth, ",SHA224,SHA256");
	#endif

	#if defined(NETSNMP_USMAUTH_HMAC192SHA256)
	strcat(spine_auth, ",SHA384,SHA512");
	#endif

	#ifndef NETSNMP_DISABLE_DES
	strcat(spine_priv, "DES");
	#endif

	#ifdef HAVE_AES
	// cppcheck-suppress knownConditionTrueFalse
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES128":"AES128"));
	#endif

	#if defined(NETSNMP_DRAFT_BLUMENTHAL_AES_04)
	// cppcheck-suppress knownConditionTrueFalse
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES192":"AES192"));
	#endif

	#if defined(NETSNMP_DRAFT_BLUMENTHAL_AES_04)
	// cppcheck-suppress knownConditionTrueFalse
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES256":"AES256"));
	#endif

	snprintf(spine_capabilities, BUFSIZE, "{ authProtocols: \"%s\", privProtocols: \"%s\" }", spine_auth, spine_priv);

	if (set.poller_id == 1) {
		putsetting(&mysql, LOCAL, "spine_capabilities", spine_capabilities);
	}

	db_disconnect(&mysql);

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		db_disconnect(&mysqlr);
	}

	settings_cache_free();

	set_date_format();
}

/* An upper bound on one row of either batch below. Every column is a number or
   a db_escape() result bounded by sizeof(tmpstr), plus separators. The row
   count alone is not a size bound: 500 rows of wide escaped SNMP strings
   overrun sqlbuf, and spine_appendf() then reports a truncation nothing was
   checking, so a statement cut inside a quoted value reached the server. */
#define PUSH_ROW_MAX (24 * DBL_BUFSIZE)

/*! \fn static void push_flush_batch(MYSQL *mysqlr, char *sqlbuf, char **sqlp, const char *suffix)
 *  \brief terminate the accumulated batch and send it to the main server
 *
 *  Refuses to send a statement that did not fit rather than shipping a
 *  truncated one, and says how much was lost.
 */
static void push_flush_batch(MYSQL *mysqlr, char *sqlbuf, char **sqlp, const char *suffix) {
	size_t remaining = HUGE_BUFSIZE - (*sqlp - sqlbuf);

	if (!spine_appendf(sqlp, &remaining, "%s", suffix)) {
		SPINE_LOG(("ERROR: The remote push statement overflowed its buffer; this batch was dropped"));
		return;
	}

	db_insert(mysqlr, REMOTE, sqlbuf);
}

void poller_push_data_to_main(void) {
	MYSQL      mysql;
	MYSQL      mysqlr;
	MYSQL_RES  *result;
	MYSQL_ROW  row;
	int        num_rows;
	int        rows;
	char       sqlbuf[HUGE_BUFSIZE];
	char       *sqlp = sqlbuf;
	size_t     remaining;
	char       query[MEGA_BUFSIZE];
	char       prefix[BUFSIZE];
	char       suffix[BUFSIZE];
	// tmpstr needs to be greater than 2 * the maximum column size being processed below
	char       tmpstr[DBL_BUFSIZE];

	db_connect(LOCAL, &mysql);
	db_connect(REMOTE, &mysqlr);

	/* Since MySQL 5.7 the sql_mode defaults are too strict for cacti */
	db_insert(&mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
	db_insert(&mysql, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
	db_insert(&mysqlr, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))");
	db_insert(&mysqlr, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");

	SPINE_LOG_MEDIUM(("Pushing Host Status to Main Server"));

	if (strlen(set.host_id_list)) {
		snprintf(query, MEGA_BUFSIZE, "SELECT SQL_NO_CACHE id, snmp_sysDescr, snmp_sysObjectID, "
			"snmp_sysUpTimeInstance, snmp_sysContact, snmp_sysName, snmp_sysLocation, "
			"status, status_event_count, status_fail_date, status_rec_date, "
			"status_last_error, min_time, max_time, cur_time, avg_time, polling_time, "
			"total_polls, failed_polls, availability, last_updated "
			"FROM host "
			"WHERE poller_id = %d "
			"AND id IN (%s)", set.poller_id, set.host_id_list);
	} else {
		snprintf(query, MEGA_BUFSIZE, "SELECT SQL_NO_CACHE id, snmp_sysDescr, snmp_sysObjectID, "
			"snmp_sysUpTimeInstance, snmp_sysContact, snmp_sysName, snmp_sysLocation, "
			"status, status_event_count, status_fail_date, status_rec_date, "
			"status_last_error, min_time, max_time, cur_time, avg_time, polling_time, "
			"total_polls, failed_polls, availability, last_updated "
			"FROM host "
			"WHERE poller_id = %d", set.poller_id);
	}

	snprintf(prefix, BUFSIZE, "INSERT INTO host (id, snmp_sysDescr, snmp_sysObjectID, "
		"snmp_sysUpTimeInstance, snmp_sysContact, snmp_sysName, snmp_sysLocation, "
		"status, status_event_count, status_fail_date, status_rec_date, "
		"status_last_error, min_time, max_time, cur_time, avg_time, polling_time, "
		"total_polls, failed_polls, availability, last_updated) VALUES ");

	/* Every INSERT below goes to the main server on the REMOTE connection, and
	   spine.c only calls this function when poller_id > 1 and mode is
	   REMOTE_ONLINE. set.dbonupdate describes the LOCAL server, so branching on
	   it here picks the syntax of the wrong database: a MySQL 8 remote poller
	   would emit the row-alias form at a MariaDB main server, which rejects it,
	   losing the whole batch silently. VALUES() is deprecated on MySQL 8 but
	   accepted by both, so it stays until rdbonupdate is populated. See #590. */
	snprintf(suffix, BUFSIZE, " ON DUPLICATE KEY UPDATE "
		"snmp_sysDescr=VALUES(snmp_sysDescr), "
		"snmp_sysObjectID=VALUES(snmp_sysObjectID), "
		"snmp_sysUpTimeInstance=VALUES(snmp_sysUpTimeInstance), "
		"snmp_sysContact=VALUES(snmp_sysContact), "
		"snmp_sysName=VALUES(snmp_sysName), "
		"snmp_sysLocation=VALUES(snmp_sysLocation), "
		"status=VALUES(status), "
		"status_event_count=VALUES(status_event_count), "
		"status_fail_date=VALUES(status_fail_date), "
		"status_rec_date=VALUES(status_rec_date), "
		"status_last_error=VALUES(status_last_error), "
		"min_time=VALUES(min_time), "
		"max_time=VALUES(max_time), "
		"cur_time=VALUES(cur_time), "
		"avg_time=VALUES(avg_time), "
		"polling_time=VALUES(polling_time), "
		"total_polls=VALUES(total_polls), "
		"failed_polls=VALUES(failed_polls), "
		"availability=VALUES(availability), "
		"last_updated=VALUES(last_updated)");

	if ((result = db_query(&mysql, LOCAL, query)) != 0) {
		num_rows = mysql_num_rows(result);
		rows = 0;

		if (num_rows > 0) {
			while ((row = mysql_fetch_row(result))) {
				remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);

				/* Flush before the row, never in place of it. The old shape reset
				   the batch when it filled and dropped the row that triggered the
				   reset, so every 501th device silently missed the push. The byte
				   test is the other half: the count is not a size bound once the
				   escaped SNMP strings are wide. */
				if (rows > 0 && (rows >= 500 || remaining < PUSH_ROW_MAX)) {
					push_flush_batch(&mysqlr, sqlbuf, &sqlp, suffix);
					rows = 0;
				}

				{
					if (rows == 0) {
						sqlp  = sqlbuf;
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, "%s", prefix);
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, " (");
					} else {
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, ", (");
					}

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[0]); // id mediumint

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[1]); // snmp_sysDescr varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[2]); // snmp_sysObjectID varchar(128)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[3]); // snmp_sysUpTimeInstance bigint
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[4]); // snmp_sysContact varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[5]); // snmp_sysName varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[6]); // snmp_sysLocation varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[7]); // status tinyint
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[8]); // status_event_count mediumint

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[9]);  // status_fail_date timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[10]); // status_rec_date timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[11]); // status_last_error varchar(255)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[12]); // min_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[13]); // max_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[14]); // cur_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[15]); // avg_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[16]); // polling_time double
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[17]); // total_polls int
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[18]); // failed_polls int
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[19]); // availability decimal(8,5)

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[20]); // last_updated timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s'", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, ")");

					rows++;
				}
			}
		}

		if (rows > 0) {
			push_flush_batch(&mysqlr, sqlbuf, &sqlp, suffix);
		}
	}

	db_free_result(result);

	SPINE_LOG_MEDIUM(("Pushing Poller Item RRD Next Step to Main Server"));

	if (strlen(set.host_id_list)) {
		snprintf(query, MEGA_BUFSIZE, "SELECT SQL_NO_CACHE local_data_id, host_id, rrd_name, rrd_step, rrd_next_step "
			"FROM poller_item "
			"WHERE poller_id = %d "
			"AND host_id IN (%s)", set.poller_id, set.host_id_list);
	} else {
		snprintf(query, MEGA_BUFSIZE, "SELECT SQL_NO_CACHE local_data_id, host_id, rrd_name, rrd_step, rrd_next_step "
			"FROM poller_item "
			"WHERE poller_id = %d ",
			set.poller_id);
	}

	snprintf(prefix, BUFSIZE, "INSERT INTO poller_item (local_data_id, host_id, rrd_name, rrd_step, rrd_next_step) VALUES ");

	/* Every INSERT below goes to the main server on the REMOTE connection, and
	   spine.c only calls this function when poller_id > 1 and mode is
	   REMOTE_ONLINE. set.dbonupdate describes the LOCAL server, so branching on
	   it here picks the syntax of the wrong database: a MySQL 8 remote poller
	   would emit the row-alias form at a MariaDB main server, which rejects it,
	   losing the whole batch silently. VALUES() is deprecated on MySQL 8 but
	   accepted by both, so it stays until rdbonupdate is populated. See #590. */
	snprintf(suffix, BUFSIZE, " ON DUPLICATE KEY UPDATE "
		"rrd_next_step=VALUES(rrd_next_step)");

	if ((result = db_query(&mysql, LOCAL, query)) != 0) {
		num_rows = mysql_num_rows(result);
		rows = 0;

		if (num_rows > 0) {
			while ((row = mysql_fetch_row(result))) {
				remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);

				/* Flush before the row, never in place of it. The old shape reset
				   the batch when it filled and dropped the row that triggered the
				   reset, so every 10001th device silently missed the push. The byte
				   test is the other half: the count is not a size bound once the
				   escaped SNMP strings are wide. */
				if (rows > 0 && (rows >= 10000 || remaining < PUSH_ROW_MAX)) {
					push_flush_batch(&mysqlr, sqlbuf, &sqlp, suffix);
					rows = 0;
				}

				{
					if (rows == 0) {
						sqlp = sqlbuf;
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, "%s", prefix);
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, " (");
					} else {
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						spine_appendf(&sqlp, &remaining, ", (");
					}

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[0]); // local_data_id
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[1]); // host_id

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[2]); // rrd_name
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s, ", row[3]); // rrd_step
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, "%s",   row[4]); // rrd_next_step

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					spine_appendf(&sqlp, &remaining, ")");

					rows++;
				}
			}
		}

		if (rows > 0) {
			push_flush_batch(&mysqlr, sqlbuf, &sqlp, suffix);

			rows = 0;
		}
	}

	db_free_result(result);

	db_disconnect(&mysql);
	db_disconnect(&mysqlr);
}

/*! \fn int read_spine_config(const char *file)
 *  \brief obtain default startup variables from the spine.conf file.
 *  \param file the spine config file
 *
 *  \return 0 if successful or -1 if the file could not be opened
 */
int read_spine_config(const char *file) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];
	char *chars;

	if ((fp = fopen(file, "rb")) == NULL) {
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			if (!set.stderr_notty) {
				fprintf(stderr, "ERROR: Could not open config file [%s]\n", file);
			}
		}
		return -1;
	} else {
		if (!set.stdout_notty) {
			fprintf(stdout, "SPINE: Using spine config file [%s]\n", file);
		}

		while (!feof(fp)) {
			chars = fgets(buff, BUFSIZE, fp);

			if (chars != NULL && !feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%15s %255s", p1, p2);

				if (STRIMATCH(p1, "RDB_Host"))              STRNCOPY(set.rdb_host, p2);
				else if (STRIMATCH(p1, "RDB_Database"))     STRNCOPY(set.rdb_db, p2);
				else if (STRIMATCH(p1, "RDB_User"))         STRNCOPY(set.rdb_user, p2);
				else if (STRIMATCH(p1, "RDB_Pass"))         STRNCOPY(set.rdb_pass, p2);
				else if (STRIMATCH(p1, "RDB_Port"))         set.rdb_port    = atoi(p2);
				else if (STRIMATCH(p1, "RDB_UseSSL"))       set.rdb_ssl     = atoi(p2);
				else if (STRIMATCH(p1, "RDB_SSL_Key"))      STRNCOPY(set.rdb_ssl_key, p2);
				else if (STRIMATCH(p1, "RDB_SSL_Cert"))     STRNCOPY(set.rdb_ssl_cert, p2);
				else if (STRIMATCH(p1, "RDB_SSL_CA"))       STRNCOPY(set.rdb_ssl_ca, p2);
				else if (STRIMATCH(p1, "DB_Host"))          STRNCOPY(set.db_host, p2);
				else if (STRIMATCH(p1, "DB_Database"))      STRNCOPY(set.db_db, p2);
				else if (STRIMATCH(p1, "DB_User"))          STRNCOPY(set.db_user, p2);
				else if (STRIMATCH(p1, "DB_Pass"))          STRNCOPY(set.db_pass, p2);
				else if (STRIMATCH(p1, "DB_Port"))          set.db_port    = atoi(p2);
				else if (STRIMATCH(p1, "DB_UseSSL"))        set.db_ssl     = atoi(p2);
				else if (STRIMATCH(p1, "DB_SSL_Key"))       STRNCOPY(set.db_ssl_key, p2);
				else if (STRIMATCH(p1, "DB_SSL_Cert"))      STRNCOPY(set.db_ssl_cert, p2);
				else if (STRIMATCH(p1, "DB_SSL_CA"))        STRNCOPY(set.db_ssl_ca, p2);
				else if (STRIMATCH(p1, "Poller"))           set.poller_id = atoi(p2);
				else if (STRIMATCH(p1, "DB_PreG")) {
					if (!set.stderr_notty) {
						fprintf(stderr,"WARNING: DB_PreG is no longer supported\n");
					}
				} else if (STRIMATCH(p1, "Cacti_Log")) {
					STRNCOPY(set.path_logfile, p2);
					set.logfile_processed = 1;
					set.log_destination = LOGDEST_BOTH;
				} else if (STRIMATCH(p1, "SNMP_Clientaddr"))  STRNCOPY(set.snmp_clientaddr, p2);
				else if (!set.stderr_notty) {
					fprintf(stderr,"WARNING: Unrecognized directive: %s=%s in %s\n", p1, p2, file);
				}

				*p1 = '\0';
				*p2 = '\0';
			}
		}

		if (strlen(set.db_pass) == 0) *set.db_pass = '\0';

		fclose(fp);

		return 0;
	}
}

/*! \fn void config_defaults(void)
 *  \brief populates the global configuration structure with default spine.conf file settings
 *  \param *set global runtime parameters
 *
 */
void config_defaults(void) {
	set.threads = DEFAULT_THREADS;

	/* default server */
	set.db_port  = DEFAULT_DB_PORT;

	STRNCOPY(set.db_host, DEFAULT_DB_HOST);
	STRNCOPY(set.db_db,   DEFAULT_DB_DB  );
	STRNCOPY(set.db_user, DEFAULT_DB_USER);
	STRNCOPY(set.db_pass, DEFAULT_DB_PASS);

	/* remote default server */
	set.rdb_port  = DEFAULT_DB_PORT;

	STRNCOPY(set.rdb_host, DEFAULT_DB_HOST);
	STRNCOPY(set.rdb_db,   DEFAULT_DB_DB  );
	STRNCOPY(set.rdb_user, DEFAULT_DB_USER);
	STRNCOPY(set.rdb_pass, DEFAULT_DB_PASS);

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
	char flogmessage[DBL_BUFSIZE];
	int old_errno = errno;

	va_start(args, format);
	vsnprintf(logmessage, BUFSIZE, format, args);
	va_end(args);

	if (set.log_perror) {
		char perr[BUFSIZE];
		snprintf(perr, BUFSIZE, " [%d, %s]", old_errno, strerror(old_errno));
		strncat(logmessage, perr, BUFSIZE - strlen(logmessage) - 1);
	}

	if (set.logfile_processed) {
		if (set.parent_fork == SPINE_PARENT) {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine parent)", logmessage);
		} else {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine thread)", logmessage);
		}
	} else {
		snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine init)", logmessage);
	}

	fprintf(stderr, "%s\n", flogmessage);

	if (set.parent_fork == SPINE_PARENT) {
		if (set.php_initialized) {
			php_close(PHP_INIT);
		}
	}

	exit(set.exit_code);
}

/* The log timestamp format depends only on two settings that are read once in
 * read_config_options(), so it is built there, while spine is still single
 * threaded, and only read afterwards.  Rebuilding it per log line cost a
 * malloc/free pair and two switches on every message. */
static char log_date_format[GD_FMT_SIZE] = "%Y/%m/%d %H:%M:%S - ";

/*! \fn void set_date_format(void)
 *  \brief build the cached log timestamp format from the current settings
 *
 *  Call once the log format and separator settings are known.  Not safe to
 *  call after the poller threads have started.
 */
void set_date_format(void) {
	char log_sep = '/';

	if (set.log_datetime_separator < GDC_MIN || set.log_datetime_separator > GDC_MAX) {
		set.log_datetime_separator = GDC_DEFAULT;
	}

	if (set.log_datetime_format < GD_MIN || set.log_datetime_format > GD_MAX) {
		set.log_datetime_format = GD_DEFAULT;
	}

	switch (set.log_datetime_separator) {
		case GDC_DOT:
			log_sep = '.';
			break;
		case GDC_HYPHEN:
			log_sep = '-';
			break;
		default:
			log_sep = '/';
			break;
	}

	switch (set.log_datetime_format) {
		case GD_MO_D_Y:
			snprintf(log_date_format, GD_FMT_SIZE, "%%m%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_MN_D_Y:
			snprintf(log_date_format, GD_FMT_SIZE, "%%b%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MO_Y:
			snprintf(log_date_format, GD_FMT_SIZE, "%%d%c%%m%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MN_Y:
			snprintf(log_date_format, GD_FMT_SIZE, "%%d%c%%b%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MO_D:
			snprintf(log_date_format, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MN_D:
			snprintf(log_date_format, GD_FMT_SIZE, "%%Y%c%%b%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		default:
			snprintf(log_date_format, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
	}
}

char *get_date_format(void) {
	return log_date_format;
}

/* Serialises the log emit below.
 *
 * Not one of the locks.c mutexes, for two reasons. thread_mutex_lock() itself
 * calls SPINE_LOG_DEVDBG, which is a runtime level check rather than a compiled
 * out one, so routing the logger through it would recurse at the highest
 * verbosity. And init_mutexes() runs well into main(), after this function has
 * already been called nineteen times, so a lock that needs initialising would
 * be used uninitialised first. A static initialiser has neither problem.
 *
 * The tearing this prevents is not hypothetical: LOGSIZE is 65535 and stdio's
 * BUFSIZ is 8192, so any message over 8KB leaves fputs() as several write()
 * calls that another thread can interleave with. See #298. */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

/*! \fn void spine_log(const char *format, ...)
 *  \brief output's log information to the desired cacti logfile.
 *  \param *logmessage a pointer to the pre-formatted log message.
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

	int  of = 20;
	char logprefix[LOGSIZE];        /* Formatted Log Prefix */
	char ulogmessage[LOGSIZE];      /* Un-Formatted Log Message */
	char flogmessage[LOGSIZE];      /* Formatted Log Message */
	char stdoutmessage[LOGSIZE+of]; /* Message for stdout */

	double cur_time;
	char * log_fmt;
	int prefix_len;
	int ulog_len;
	int flog_len;

	va_start(args, format);
	vsnprintf(ulogmessage, LOGSIZE - 1, format, args);
	va_end(args);

	/* default for "console" messages to go to stdout */
	fp = stdout;

	/* log message prefix */

	snprintf(logprefix, LOGSIZE, "SPINE: Poller[%i] PID[%i] PT[%lu] ", set.poller_id, getpid(), (unsigned long int)pthread_self());

	/* get time for poller_output table */
	nowbin = time(&nowbin);

	localtime_r(&nowbin,&now_time);
	now_ptr = &now_time;

	if (IS_LOGGING_TO_STDOUT()) {
		cur_time = get_time_as_double();
		snprintf(stdoutmessage, LOGSIZE + of, "Total[%3.4f] %s", cur_time - start_time, ulogmessage);
		puts(stdoutmessage);
		return TRUE;
	}

	log_fmt = get_date_format();

	if (strlen(log_fmt) == 0) {
		#ifdef DISABLE_STDERR
		fp = stdout;
		#else
		fp = stderr;
		#endif

		if ((set.stderr_notty) && (fp == stderr)) {
			/* do nothing stderr does not exist */
		} else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		} else {
			fprintf(fp, "ERROR: Could not get format from get_date_format()\n");
		}
	}

	prefix_len = strlen(logprefix);
	ulog_len   = strlen(ulogmessage);
	flog_len   = 0;

	if ((flog_len = strftime(flogmessage, 50, log_fmt, now_ptr)) == (int) 0) {
		#ifdef DISABLE_STDERR
		fp = stdout;
		#else
		fp = stderr;
		#endif

		if ((set.stderr_notty) && (fp == stderr)) {
			/* do nothing stderr does not exist */
		} else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		} else {
			fprintf(fp, "ERROR: Could not get string from strftime()\n");
		}
	}

	/* determine how many characters to append */
	if (prefix_len > LOGSIZE - flog_len - 1) {
		prefix_len = LOGSIZE - flog_len - 1;
	}

	if (ulog_len + prefix_len > LOGSIZE - flog_len - 1) {
		ulog_len = LOGSIZE - flog_len - prefix_len - 1;
	}

	strncat(flogmessage, logprefix,   prefix_len);
	strncat(flogmessage, ulogmessage, ulog_len);

	/* output to syslog/eventlog */
	if (IS_LOGGING_TO_SYSLOG()) {
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
	}

	/* append a line feed to the log message if needed.  The two strncat()
	 * calls above are allowed to fill flogmessage exactly, so appending
	 * unconditionally would put the terminator one byte past the end. */
	if (!strstr(flogmessage, "\n")) {
		size_t flogmessage_len = strlen(flogmessage);

		if (flogmessage_len < sizeof(flogmessage) - 1) {
			flogmessage[flogmessage_len]     = '\n';
			flogmessage[flogmessage_len + 1] = '\0';
		}
	}

	if ((IS_LOGGING_TO_FILE() &&
		(set.log_level != POLLER_VERBOSITY_NONE) &&
		(strlen(set.path_logfile) != 0))) {
		if (set.logfile_processed) {
			int oldstate;

			/* a cancel delivered here would leave every other thread's logging
			   blocked on a mutex nothing will release */
			pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
			pthread_mutex_lock(&log_mutex);

			/* "a" creates the file when it is absent, which is all the
			   file_exists() test and the "w" mode were doing, minus a stat and
			   the window between the two. Reopening per message is deliberate:
			   it is what lets an operator rotate the log out from under a
			   running poller. */
			log_file = fopen(set.path_logfile, "a");

			if (log_file) {
				fputs(flogmessage, log_file);
				fclose(log_file);
			} else {
				if (!log_error) {
					printf("ERROR: Spine Log File Could Not Be Opened/Created\n");
					log_error = TRUE;
				}
			}

			pthread_mutex_unlock(&log_mutex);
			pthread_setcancelstate(oldstate, NULL);
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
		} else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		} else {
			fprintf(fp, "%s", flogmessage);
		}
	}


	return TRUE;
}

/*! \fn int file_exists(const char *filename)
 *  \brief checks for the existence of a file.
 *  \param *filename the name of the file to check for.
 *
 *  \return TRUE if found FALSE if not.
 *
 */
int file_exists(const char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return FALSE;
	} else {
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
	char *end_ptr_long, *end_ptr_double;
	int conv_base=10;
	int length;

	length = strlen(trim(string));

	if (!length) {
		return FALSE;
	}

 	/* check for an integer */
	errno = 0;
	strtol(string, &end_ptr_long, conv_base);

	if (errno != ERANGE) {
		if (end_ptr_long == string + length) { /* integer string */
			return TRUE;
		} else if (end_ptr_long == string) {
			if (*end_ptr_long != '\0' &&
				*end_ptr_long != '.' &&
				*end_ptr_long != '-' &&
				*end_ptr_long != '+') { /* ignore partial string matches but doubles can begin with '+', '-', '.' */
				return FALSE;
			}
		}
	} else {
		end_ptr_long = NULL;
	}

 	/* check for a float */
	errno = 0;
	strtod(string, &end_ptr_double);
	if (errno != ERANGE) {
		if (end_ptr_double == string + length) { /* floating point string */
			return TRUE;
		}
	} else {
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
 *  The function is modified where the string needs to include
 *  at least one of the following string ' ', '-', or ':'
 *
 */
int is_hexadecimal(const char * str, const short ignore_special) {
	int i = 0;
	int delim_found = FALSE;

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
			case '-': case ':': case ' ':
				delim_found = TRUE;
				break;
			case '\t':
				if (ignore_special) {
					break;
				}
			default:
				return FALSE;
		}

		str++;
		i++;
	}

	if ((i < 3) || delim_found == FALSE) {
		return FALSE;
	}

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
	int j;

	i = strlen(string);
	j = 0;

	/* trim trailing characters */
	while (i >= 0) {
		if (isdigit((int)string[i])) {
			break;
		} else {
			string[i] = '\0';
		}
		i--;
	}

	/* trim leading characters */
	while (j < i) {
		if (isdigit((int)string[j])) {
			break;
		} else if (string[j] == '-') {
			break;
		} else if (string[j] == '+') {
			j++;
		} else {
			j++;
		}
	}

	string = &string[j];

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

	length       = strlen(string);

	if (!(return_str = (char *) malloc(length * 2 + 1))) {
		die("ERROR: Fatal malloc error: util.c add_slashes!");
	}
	return_str[0] = '\0';
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
		} else {
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
	size_t copy_len;

	assert(dst != 0);
	assert(src != 0);

	if (obuf == 0) return dst;

	/* Cap the scan at obuf-1: no need to walk past the usable copy capacity,
	 * and avoids a full strlen when src is large or unterminated near obuf. */
	copy_len = strnlen(src, obuf - 1);

	if (copy_len) {
		/* copy_len is the exact byte count and dst is terminated below, so
		 * memcpy avoids the strncpy truncation diagnostic. */
		memcpy(dst, src, copy_len);
	}

	dst[copy_len] = '\0';
	return dst;
}

/*! \fn double get_time_as_double()
 *  \brief fetches system time as a double-precision value
 *
 *  \return system time (at microsecond resolution) as a double
 */
double get_time_as_double(void) {
	struct timeval now;

	gettimeofday(&now, NULL);

	return (now).tv_sec + ((double) (now).tv_usec / 1000000);
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
	const char *trim = " \"\'\\\t\n\r";

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
	const char *trim = " \"\'\\\t\n\r";

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

/*! \fn strpos()
 *  \brief looks for the position of needle in haystack
 *
 *  \return the position of -1 if not found
 */
int strpos(const char *haystack, const char *needle) {
	const char *p = strstr(haystack, needle);

	if (p) {
		return p - haystack;
	}

	return -1;
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
		/* separators. is_hexadecimal() accepts '-' and ':' as well as space,
		 * so anything it lets through has to be convertible here; skipping
		 * only space meant a dash-separated octet string validated and then
		 * converted to zero. */
		case '"': case ' ': case '\t': case '-': case ':':
			break;
		default:
			return 0;
		}

		str++;
	}

	return number;
}

int hasCaps(void) {
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

void checkAsRoot(void) {
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

	/* Add privilege to send/receive ICMP packets */
	if (priv_addset(privset, PRIV_NET_ICMPACCESS) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Addition of PRIV_NET_ICMPACCESS to privset failed: '%s'.", strerror(errno)));
	}

	/* Compute the set of privileges that are never needed */
	priv_inverse(privset);

	/* Remove the set of unneeded privs from Permitted (and by
	 * implication from Effective) */
	if (setppriv(PRIV_OFF, PRIV_PERMITTED, privset) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Dropping privileges from PRIV_PERMITTED failed: '%s'.", strerror(errno)));
	}

	/* Remove unneeded priv set from Limit to be safe */
	if (setppriv(PRIV_OFF, PRIV_LIMIT, privset) < 0) {
		SPINE_LOG_DEBUG(("WARNING: Dropping privileges from PRIV_LIMIT failed: '%s'.", strerror(errno)));
	}

	boolean_t pe = priv_ineffect(PRIV_NET_ICMPACCESS);
	SPINE_LOG_DEBUG(("DEBUG: Privilege PRIV_NET_ICMPACCESS is: '%s'.", pe != 0 ? "Enabled" : "Disabled"));

	set.icmp_avail = pe;

	/* Free the privset */
	priv_freeset(privset);
	free(p);
	#else
	if (hasCaps() != TRUE) {
		int ret;
		SPINE_LOG_DEBUG(("DEBUG: Spine running as %d UID, %d EUID", getuid(), geteuid()));
		ret = seteuid(0);
		if (ret != 0) {
			SPINE_LOG_DEBUG(("WARNING: Spine NOT able to set effective UID to 0"));
		}

		if (geteuid() != 0) {
			SPINE_LOG_DEBUG(("WARNING: Spine NOT running as root.  This is required if using ICMP.  Please run \"chown root:root spine;chmod u+s spine\" to resolve."));
			set.icmp_avail = FALSE;
		} else {
			SPINE_LOG_DEBUG(("DEBUG: Spine is running as root."));
			set.icmp_avail = TRUE;

			if (seteuid(getuid()) == -1) {
				SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
			}
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Spine has cap_net_raw capability."));
		set.icmp_avail = TRUE;
	}
	SPINE_LOG_DEBUG(("DEBUG: Spine has %sgot ICMP", set.icmp_avail?"":"not "));
	#endif
	#endif
}

/*! \fn int get_cacti_version(MYSQL *psql, int mode, const char *setting)
 *  \brief Returns the version of Cacti as a decimal
 *
 *  Given a pointer to a database get the version of Cacti and convert
 *  to an integer.
 *
 *  \return the cacti version
 *
 */
int get_cacti_version(MYSQL *psql, int mode) {
	char      qstring[BUFSIZE];
	char      *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int       major, minor, point;
	int       cacti_version;

	assert(psql != 0);

	snprintf(qstring, sizeof(qstring), "SELECT cacti FROM version LIMIT 1");

	result = db_query(psql, mode, qstring);

	if (result != 0) {
		if (mysql_num_rows(result) > 0) {
			mysql_row = mysql_fetch_row(result);

			if (mysql_row != NULL) {
				retval = strdup(mysql_row[0]);
				db_free_result(result);

				if (STRIMATCH(retval, "new_install")) {
					SPINE_FREE(retval);

					return 0;
				} else {
					sscanf(retval, "%d.%d.%d", &major, &minor, &point);
					cacti_version = (major * 1000) + (minor * 100) + (point * 1);

					SPINE_FREE(retval);

					return cacti_version;
				}
			}else{
				db_free_result(result);
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

const char *regex_replace(const char *exp, const char *value) {
	regex_t regex;
	int reti;
	/* Thread-local storage: each polling thread gets its own buffer, so
	 * concurrent callers do not race.  Callers must consume the result before
	 * making another call on the same thread (all current call sites do this).
	 * C11 _Thread_local is equivalent; __thread is used here since GCC/Clang
	 * (the only supported compilers for this codebase) treat them identically. */
	static __thread char msgbuf[SMALL_BUFSIZE];
	regmatch_t matches[MAX_MATCHES];
	size_t match_len;

	/* Compile regular expression */
	/* REGEX_NUMBER is an extended regex: without REG_EXTENDED the parens and
	   the + are literals and it never matches. */
	reti = regcomp(&regex, exp, REG_EXTENDED);
	if (reti) {
		return value;
	}

	/* Execute regular expression */
	reti = regexec(&regex, value, MAX_MATCHES, matches, 0);
	if (!reti) {
		match_len = (size_t)(matches[0].rm_eo - matches[0].rm_so);
		if (match_len >= SMALL_BUFSIZE) {
			match_len = SMALL_BUFSIZE - 1;
		}
		memcpy(msgbuf, value + matches[0].rm_so, match_len);
		msgbuf[match_len] = '\0';
	}

	/* Free memory allocated to the pattern buffer by regcomp() */
	regfree(&regex);

	return (reti) ? value : msgbuf;
}

/*! \fn int spine_appendf(char **cursor, size_t *remaining, const char *fmt, ...)
 *  \brief append to a bounded buffer without walking off the end
 *
 *  See util.h for why the `p += snprintf(...)` idiom this replaces is unsafe.
 *
 *  \return TRUE when the whole string was appended, FALSE otherwise
 */
int spine_appendf(char **cursor, size_t *remaining, const char *fmt, ...) {
	va_list args;
	int written;

	if (cursor == NULL || *cursor == NULL || remaining == NULL || *remaining == 0) {
		return FALSE;
	}

	va_start(args, fmt);
	written = vsnprintf(*cursor, *remaining, fmt, args);
	va_end(args);

	if (written < 0) {
		/* the buffer is untouched on an encoding error, but vsnprintf may have
		   written a partial result, so re-terminate where the cursor stands */
		**cursor = '\0';
		return FALSE;
	}

	if ((size_t) written >= *remaining) {
		/* Truncated. Leave the cursor on the terminator vsnprintf wrote, so
		   the buffer stays a valid string and every later append fails here
		   rather than running past the end. */
		*cursor += *remaining - 1;
		*remaining = 1;
		return FALSE;
	}

	*cursor    += written;
	*remaining -= (size_t) written;

	return TRUE;
}
