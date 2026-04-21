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
#include "config_apply.h"
#include "config_builder.h"
#include "config_repository.h"
#include "log_formatter.h"
#include "log_sink.h"
#include "systemd_notify.h"
#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "uthash.h"
#include <pthread.h>
#endif

#include "regex.h"

#include <fcntl.h>
#include <limits.h>

static int nopts = 0;

/* Range-safe int parser for config-setting values. Replaces atoi() at
 * every config call site so bad input produces a bounded value rather
 * than undefined behaviour or a silent zero-reset.
 *
 * - NULL input returns 0 (atoi is UB here).
 * - Non-numeric input returns 0, matching atoi's "0 means default" for
 *   existing callers.
 * - Positive overflow clamps to INT_MAX.
 * - Negative overflow clamps to INT_MIN (a prior version returned
 *   INT_MAX on large negatives - sign-flip data corruption).
 */
int spine_parse_int(const char *s) {
	if (s == NULL) return 0;
	char *end = NULL;
	errno = 0;
	long v = strtol(s, &end, 10);
	if (end == s) return 0;                /* no digits consumed */
	if (errno == ERANGE) return v < 0 ? INT_MIN : INT_MAX;
	if (v > INT_MAX)     return INT_MAX;
	if (v < INT_MIN)     return INT_MIN;
	return (int)v;
}

/* EUID the process booted with, captured before any privilege drop.
 * Sentinel (uid_t)-1 means "not yet captured"; once populated the value
 * is read-only for the rest of the process. The spine.conf owner check
 * consults this so a root-owned config file stays valid after spine
 * drops to its service account. */
static uid_t spine_startup_euid = (uid_t)-1;

void spine_capture_startup_euid(void) {
	if (spine_startup_euid == (uid_t)-1) {
		spine_startup_euid = geteuid();
	}
}

/* Forward declaration so spine_log() can reach the JSON escaper defined
 * further down alongside the other --check / --dump-config helpers. */
/* Exposed for the JSON-escape unit test. Treat as internal; do not call
 * from code outside util.c / the unit test harness. */
char *spine_json_escape(char *dst, size_t dst_len, const char *src);

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

	return result;
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

/*! \fn void read_config_options(void)
 *  \brief Reads the default Spine runtime parameters from the database and set's the global array
 *
 *  load default values from the database for poller processing
 *
 */
static void read_config_options_legacy(void);

void read_config_options(void) {
	MYSQL mysql;
	ConfigRepositoryData raw;
	RuntimeConfigDraft draft;

	db_connect(LOCAL, &mysql);
	config_repository_fetch(&mysql, &raw);
	config_builder_build(&set, &raw, &draft);
	config_apply_runtime(&set, &draft);
	db_disconnect(&mysql);

	read_config_options_legacy();
}

static void read_config_options_legacy(void) {
	MYSQL      mysql;
	MYSQL      mysqlr;
	MYSQL_RES  *result;
	int        num_rows;
	int        mode;
	char       web_root[BUFSIZE];
	char       sqlbuf[HUGE_BUFSIZE];
	char       *sqlp = sqlbuf;
	char       *res;
	char       spine_priv[BUFSIZE];
	char       spine_auth[BUFSIZE];
	char       spine_capabilities[BUFSIZE];

	/* publish spine snmpv3 capabilities to the database */
	memset(spine_capabilities, 0, sizeof(spine_capabilities));
	memset(spine_priv, 0, sizeof(spine_priv));
	memset(spine_auth, 0, sizeof(spine_auth));

	db_connect(LOCAL, &mysql);

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

	/* get logging level from database - overrides spine.conf */
	if ((res = getsetting(&mysql, LOCAL, "log_verbosity")) != 0) {
		const int n = spine_parse_int(res);
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
		set.log_datetime_separator = spine_parse_int(res);
		free(res);

		if (set.log_datetime_separator < GDC_MIN || set.log_datetime_separator > GDC_MAX) {
			set.log_datetime_separator = GDC_DEFAULT;
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

	/* set availability_method */
	if ((res = getsetting(&mysql, LOCAL, "availability_method")) != 0) {
		set.availability_method = spine_parse_int(res);
		free(res);
	}

	/* log the availability_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The availability_method variable is %i", set.availability_method));

	/* set ping_recovery_count */
	if ((res = getsetting(&mysql, LOCAL, "ping_recovery_count")) != 0) {
		set.ping_recovery_count = spine_parse_int(res);
		free(res);
	}

	/* log the ping_recovery_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_recovery_count variable is %i", set.ping_recovery_count));

	/* set ping_failure_count */
	if ((res = getsetting(&mysql, LOCAL, "ping_failure_count")) != 0) {
		set.ping_failure_count = spine_parse_int(res);
		free(res);
	}

	/* log the ping_failure_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_failure_count variable is %i", set.ping_failure_count));

	/* set ping_method */
	if ((res = getsetting(&mysql, LOCAL, "ping_method")) != 0) {
		set.ping_method = spine_parse_int(res);
		free(res);
	}

	/* log the ping_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_method variable is %i", set.ping_method));

	/* set ping_retries */
	if ((res = getsetting(&mysql, LOCAL, "ping_retries")) != 0) {
		set.ping_retries = spine_parse_int(res);
		free(res);
	}

	/* log the ping_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_retries variable is %i", set.ping_retries));

	/* set ping_timeout */
	if ((res = getsetting(&mysql, LOCAL, "ping_timeout")) != 0) {
		set.ping_timeout = spine_parse_int(res);
		free(res);
	} else {
		set.ping_timeout = 400;
	}

	/* log the ping_timeout variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_timeout variable is %i", set.ping_timeout));

	/* set snmp_retries */
	if ((res = getsetting(&mysql, LOCAL, "snmp_retries")) != 0) {
		set.snmp_retries = spine_parse_int(res);
		free(res);
	} else {
		set.snmp_retries = 3;
	}

	/* log the snmp_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The snmp_retries variable is %i", set.snmp_retries));

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
			set.threads = spine_parse_int(res);
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
		set.poller_interval = spine_parse_int(res);
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
		set.num_parent_processes = spine_parse_int(res);
		free(res);
	} else {
		set.num_parent_processes = 1;
	}

	/* log the concurrent processes variable */
	SPINE_LOG_DEBUG(("DEBUG: The number of concurrent processes is %i", set.num_parent_processes));

	/* get the script timeout to establish timeouts */
	if ((res = getsetting(&mysql, LOCAL, "script_timeout")) != 0) {
		set.script_timeout = spine_parse_int(res);
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
		set.spine_log_level = spine_parse_int(res);
		free(res);
	}

	/* log the spine_log_level variable */
	SPINE_LOG_DEBUG(("DEBUG: The spine_log_level variable is %i", set.spine_log_level));

	/* get the number of script server processes to run */
	if ((res = getsetting(&mysql, LOCAL, "php_servers")) != 0) {
		set.php_servers = spine_parse_int(res);
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
		set.active_profiles = spine_parse_int(res);
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
		set.total_snmp_ports = spine_parse_int(res);
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
		sqlp += snprintf(sqlp, BUFSIZE, "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += snprintf(sqlp, BUFSIZE, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += append_hostrange(sqlp, "host_id");
		sqlp += snprintf(sqlp, BUFSIZE, " AND poller_id=%i", set.poller_id);
		sqlp += snprintf(sqlp, BUFSIZE, " LIMIT 1");

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
		sqlp += snprintf(sqlp, BUFSIZE, "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += snprintf(sqlp, BUFSIZE, " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += snprintf(sqlp, BUFSIZE, " AND host_id IN(%s)", set.host_id_list);
		sqlp += snprintf(sqlp, BUFSIZE, " AND poller_id=%i", set.poller_id);
		sqlp += snprintf(sqlp, BUFSIZE, " LIMIT 1");

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
		set.snmp_max_get_size = spine_parse_int(res);
		free(res);

		if (set.snmp_max_get_size > 128) {
			set.snmp_max_get_size = 128;
		}
	} else {
		set.snmp_max_get_size = 25;
	}

	/* log the snmp_max_get_size variable */
	SPINE_LOG_DEBUG(("DEBUG: The Maximum SNMP OID Get Size is %i", set.snmp_max_get_size));

	/*
	 * append_csv_token: bounded append of token to buf, prepending ','
	 * if buf is non-empty. Silently truncates on overflow rather than
	 * running off the end of the fixed BUFSIZE array.
	 */
	#define APPEND_CSV_TOKEN(buf, tok) do {                                    \
		size_t _used = strlen(buf);                                            \
		if (_used < BUFSIZE - 1) {                                             \
			snprintf((buf) + _used, BUFSIZE - _used, "%s%s",                   \
				_used > 0 ? "," : "", (tok));                                  \
		}                                                                      \
	} while (0)

	#ifndef NETSNMP_DISABLE_MD5
	APPEND_CSV_TOKEN(spine_auth, "MD5");
	#endif

	APPEND_CSV_TOKEN(spine_auth, "SHA");

	#if defined(NETSNMP_USMAUTH_HMAC128SHA224)
	APPEND_CSV_TOKEN(spine_auth, "SHA224");
	APPEND_CSV_TOKEN(spine_auth, "SHA256");
	#endif

	#if defined(NETSNMP_USMAUTH_HMAC192SHA256)
	APPEND_CSV_TOKEN(spine_auth, "SHA384");
	APPEND_CSV_TOKEN(spine_auth, "SHA512");
	#endif

	#ifndef NETSNMP_DISABLE_DES
	APPEND_CSV_TOKEN(spine_priv, "DES");
	#endif

	#ifdef HAVE_AES
	APPEND_CSV_TOKEN(spine_priv, "AES128");
	#endif

	#if defined(NETSNMP_DRAFT_BLUMENTHAL_AES_04)
	APPEND_CSV_TOKEN(spine_priv, "AES192");
	APPEND_CSV_TOKEN(spine_priv, "AES256");
	#endif

	#undef APPEND_CSV_TOKEN

	snprintf(spine_capabilities, BUFSIZE, "{ authProtocols: \"%s\", privProtocols: \"%s\" }", spine_auth, spine_priv);

	if (set.poller_id == 1) {
		putsetting(&mysql, LOCAL, "spine_capabilities", spine_capabilities);
	}

	db_disconnect(&mysql);

	if (set.poller_id > 1 && set.mode == REMOTE_ONLINE) {
		db_disconnect(&mysqlr);
	}
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
	int        remaining;
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

	if (set.dbonupdate == 0) {
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
	} else {
		snprintf(suffix, BUFSIZE, " AS rs ON DUPLICATE KEY UPDATE "
			"snmp_sysDescr=rs.snmp_sysDescr, "
			"snmp_sysObjectID=rs.snmp_sysObjectID, "
			"snmp_sysUpTimeInstance=rs.snmp_sysUpTimeInstance, "
			"snmp_sysContact=rs.snmp_sysContact, "
			"snmp_sysName=rs.snmp_sysName, "
			"snmp_sysLocation=rs.snmp_sysLocation, "
			"status=rs.status, "
			"status_event_count=rs.status_event_count, "
			"status_fail_date=rs.status_fail_date, "
			"status_rec_date=rs.status_rec_date, "
			"status_last_error=rs.status_last_error, "
			"min_time=rs.min_time, "
			"max_time=rs.max_time, "
			"cur_time=rs.cur_time, "
			"avg_time=rs.avg_time, "
			"polling_time=rs.polling_time, "
			"total_polls=rs.total_polls, "
			"failed_polls=rs.failed_polls, "
			"availability=rs.availability, "
			"last_updated=rs.last_updated");
	}

	if ((result = db_query(&mysql, LOCAL, query)) != 0) {
		num_rows = mysql_num_rows(result);
		rows = 0;

		if (num_rows > 0) {
			while ((row = mysql_fetch_row(result))) {
				if (rows < 500) {
					if (rows == 0) {
						sqlp  = sqlbuf;
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, "%s", prefix);
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, " (");
					} else {
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, ", (");
					}

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[0]); // id mediumint

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[1]); // snmp_sysDescr varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[2]); // snmp_sysObjectID varchar(128)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[3]); // snmp_sysUpTimeInstance bigint
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[4]); // snmp_sysContact varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[5]); // snmp_sysName varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[6]); // snmp_sysLocation varchar(300)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[7]); // status tinyint
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[8]); // status_event_count mediumint

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[9]);  // status_fail_date timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[10]); // status_rec_date timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);
					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[11]); // status_last_error varchar(255)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[12]); // min_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[13]); // max_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[14]); // cur_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[15]); // avg_time decimal(10,5)
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[16]); // polling_time double
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[17]); // total_polls int
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[18]); // failed_polls int
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[19]); // availability decimal(8,5)

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[20]); // last_updated timestamp
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s'", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, ")");

					rows++;
				} else {
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s", suffix);
					db_insert(&mysqlr, REMOTE, sqlbuf);

					rows = 0;
				}
			}
		}

		if (rows > 0) {
			remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
			sqlp += snprintf(sqlp, remaining, "%s", suffix);
			db_insert(&mysqlr, REMOTE, sqlbuf);
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

	if (set.dbonupdate == 0) {
		snprintf(suffix, BUFSIZE, " ON DUPLICATE KEY UPDATE "
			"rrd_next_step=VALUES(rrd_next_step)");
	} else {
		snprintf(suffix, BUFSIZE, " AS rs ON DUPLICATE KEY UPDATE "
			"rrd_next_step=rs.rrd_next_step");
	}

	if ((result = db_query(&mysql, LOCAL, query)) != 0) {
		num_rows = mysql_num_rows(result);
		rows = 0;

		if (num_rows > 0) {
			while ((row = mysql_fetch_row(result))) {
				if (rows < 10000) {
					if (rows == 0) {
						sqlp = sqlbuf;
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, "%s", prefix);
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, " (");
					} else {
						remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
						sqlp += snprintf(sqlp, remaining, ", (");
					}

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[0]); // local_data_id
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[1]); // host_id

					db_escape(&mysql, tmpstr, sizeof(tmpstr), row[2]); // rrd_name
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "'%s', ", tmpstr);

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s, ", row[3]); // rrd_step
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s",   row[4]); // rrd_next_step

					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, ")");

					rows++;
				} else {
					remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
					sqlp += snprintf(sqlp, remaining, "%s", suffix);
					db_insert(&mysqlr, REMOTE, sqlbuf);

					rows = 0;
				}
			}
		}

		if (rows > 0) {
			remaining = HUGE_BUFSIZE - (sqlp - sqlbuf);
			sqlp += snprintf(sqlp, remaining, "%s", suffix);
			db_insert(&mysqlr, REMOTE, sqlbuf);

			rows = 0;
		}
	}

	db_free_result(result);

	db_disconnect(&mysql);
	db_disconnect(&mysqlr);
}

/* Security-relevant config warnings must surface even when stderr is not a
 * tty (systemd captures them into the journal). Range errors, truncation,
 * and unknown directives all indicate either misconfiguration or tampering
 * and are cheap to emit. */
static void spine_config_warn(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static void spine_config_warn(const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

/* Parse an unsigned integer directive within [lo, hi]. Returns 1 on success
 * and writes to *out; returns 0 and leaves *out untouched on range error or
 * trailing garbage. Accepts leading whitespace only; a leading '-' or '+' is
 * rejected because spine never uses negative or explicitly-positive values
 * for these fields. */
static int spine_parse_bounded_ulong(const char *key, const char *val,
                                     unsigned long lo, unsigned long hi,
                                     unsigned long *out) {
	if (val == NULL || *val == '\0' || *val == '-' || *val == '+') {
		spine_config_warn("WARNING: %s=%s rejected: not a non-negative integer\n",
			key, val ? val : "(null)");
		return 0;
	}
	errno = 0;
	char *end = NULL;
	unsigned long v = strtoul(val, &end, 10);
	if (errno != 0 || end == val || (end && *end != '\0')) {
		spine_config_warn("WARNING: %s=%s rejected: not a valid integer\n", key, val);
		return 0;
	}
	if (v < lo || v > hi) {
		spine_config_warn("WARNING: %s=%s rejected: out of range [%lu, %lu]\n",
			key, val, lo, hi);
		return 0;
	}
	*out = v;
	return 1;
}

/* Split buff into keyword (p1) and value (p2). Preserves embedded whitespace
 * in the value so passwords containing spaces round-trip. Returns 1 on a
 * parseable directive, 0 on blank/comment lines, -1 on a hard parse error
 * (keyword too long, embedded NUL, overlong line). Trailing CR/LF are
 * stripped. The caller must zero buff before fgets so this function can
 * detect embedded NUL bytes: fgets writes through a NUL in the input, so
 * the buffer tail past strlen stays zero only when no NUL was embedded.
 * fp is used to drain the rest of an over-length line so the next fgets
 * starts on the following line. */
static int spine_config_tokenize(char *buff, size_t buff_len,
                                 char *p1, size_t p1_cap,
                                 char *p2, size_t p2_cap,
                                 const char *file, int lineno, FILE *fp) {
	size_t read_len = strnlen(buff, buff_len);
	int has_newline = (read_len > 0 && buff[read_len - 1] == '\n');

	/* Overlong line: fgets filled buff_len-1 without '\n'. */
	if (!has_newline && read_len == buff_len - 1) {
		spine_config_warn("WARNING: %s:%d line exceeds %zu bytes; rejected\n",
			file, lineno, buff_len - 1);
		int ch;
		while ((ch = fgetc(fp)) != EOF && ch != '\n') { /* drain */ }
		return -1;
	}
	/* Embedded NUL: the buffer was pre-zeroed, so any non-zero byte beyond
	 * read_len implies fgets wrote through a NUL byte in the input. */
	if (read_len < buff_len - 1) {
		for (size_t i = read_len + 1; i < buff_len; i++) {
			if (buff[i] != '\0') {
				spine_config_warn("WARNING: %s:%d embedded NUL byte rejected\n",
					file, lineno);
				return -1;
			}
		}
	}
	size_t len = read_len;
	/* Strip trailing CR/LF (handles both LF and CRLF line endings). */
	while (len > 0 && (buff[len - 1] == '\n' || buff[len - 1] == '\r')) {
		buff[--len] = '\0';
	}
	/* Blank line or comment. */
	if (len == 0 || buff[0] == '#') {
		return 0;
	}

	/* Locate the first whitespace run that separates keyword from value. */
	size_t ks = 0;
	while (ks < len && (buff[ks] == ' ' || buff[ks] == '\t')) ks++;
	if (ks == len) return 0;
	size_t ke = ks;
	while (ke < len && buff[ke] != ' ' && buff[ke] != '\t') ke++;

	size_t klen = ke - ks;
	if (klen >= p1_cap) {
		spine_config_warn("WARNING: %s:%d keyword exceeds %zu bytes; rejected\n",
			file, lineno, p1_cap - 1);
		return -1;
	}
	memcpy(p1, buff + ks, klen);
	p1[klen] = '\0';

	/* Skip the whitespace run between keyword and value. */
	size_t vs = ke;
	while (vs < len && (buff[vs] == ' ' || buff[vs] == '\t')) vs++;

	/* Value runs to end-of-line; trailing whitespace is trimmed so
	 * "DB_Port  123   " parses as "123". Interior whitespace is kept
	 * so passwords with spaces (rare, but valid) survive. */
	size_t ve = len;
	while (ve > vs && (buff[ve - 1] == ' ' || buff[ve - 1] == '\t')) ve--;

	size_t vlen = ve - vs;
	if (vlen >= p2_cap) {
		spine_config_warn("WARNING: %s:%d value for %s exceeds %zu bytes; rejected\n",
			file, lineno, p1, p2_cap - 1);
		return -1;
	}
	if (vlen > 0) {
		memcpy(p2, buff + vs, vlen);
	}
	p2[vlen] = '\0';
	return 1;
}

/*! \fn int read_spine_config(const char *file)
 *  \brief obtain default startup variables from the spine.conf file.
 *  \param file the spine config file
 *
 *  \return 0 if successful or -1 if the file could not be opened
 */
int read_spine_config(const char *file) {
	FILE *fp;
	int fd;
	char buff[BUFSIZE];
	/* Keyword cap of 64 bytes accommodates every current directive with
	 * room for future additions; anything longer is almost certainly a
	 * malformed or truncated line. Value cap matches the struct member
	 * sizes in spine.h (BUFSIZE). */
	char p1[64];
	char p2[BUFSIZE];
	int  lineno = 0;

	/* O_NOFOLLOW refuses to traverse a symlink at the final component so an
	 * attacker who can plant a symlink at /etc/spine.conf cannot redirect
	 * credential loading to a file they control. O_CLOEXEC keeps the fd
	 * out of child processes spawned via posix_spawn or nft_popen. */
	fd = open(file, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		int open_errno = errno;
		if (open_errno == ELOOP) {
			if (!set.stderr_notty) {
				fprintf(stderr, "FATAL: spine config [%s] is a symlink; refusing to start\n", file);
			}
			return -1;
		}
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			if (!set.stderr_notty) {
				fprintf(stderr, "ERROR: Could not open config file [%s]: %s\n", file, strerror(open_errno));
			}
		}
		return -1;
	}

	if ((fp = fdopen(fd, "rb")) == NULL) {
		close(fd);
		if (set.log_level == POLLER_VERBOSITY_DEBUG) {
			if (!set.stderr_notty) {
				fprintf(stderr, "ERROR: Could not open config file [%s]\n", file);
			}
		}
		return -1;
	} else {
		/* spine.conf carries DB credentials. Hard-fail only on the bits that
		 * actually leak or corrupt them: world-readable (password exfil) or
		 * group/world-writable (tamper). Soft-warn on owner mismatch because
		 * many deployments ship spine under a service account distinct from
		 * the user invoking it, and on fstat errors (unusual filesystems). */
		struct stat conf_stat;
		if (fstat(fileno(fp), &conf_stat) == 0) {
			mode_t perms = conf_stat.st_mode & 0777;
			if (conf_stat.st_mode & S_IROTH) {
				if (!set.stderr_notty) {
					fprintf(stderr,
						"WARNING: spine config [%s] is world-readable (mode 0%o); tighten to 0600 to protect DB credentials\n",
						file, perms);
				}
			}
			if (conf_stat.st_mode & (S_IWGRP | S_IWOTH)) {
				if (!set.stderr_notty) {
					fprintf(stderr,
						"FATAL: spine config [%s] is group/world-writable (mode 0%o); refusing to start\n",
						file, perms);
				}
				fclose(fp);
				return -1;
			}
			/* Accept the file if it is owned by root, by the euid spine
			 * booted with (captured before drop_root), by the current
			 * euid, or by the real uid. Comparing against the live euid
			 * alone trips once spine hands off to its service account
			 * on a root-owned /etc/spine.conf. */
			uid_t cur_euid = geteuid();
			uid_t cur_ruid = getuid();
			uid_t owner    = conf_stat.st_uid;
			int owner_ok   = (owner == 0)
				|| (owner == cur_euid)
				|| (owner == cur_ruid)
				|| (spine_startup_euid != (uid_t)-1 && owner == spine_startup_euid);
			if (!owner_ok) {
				if (!set.stderr_notty) {
					fprintf(stderr,
						"WARNING: spine config [%s] owner uid %d is not root, the startup euid, or the running user\n",
						file, (int)owner);
				}
			}
		}

		if (!set.stdout_notty) {
			fprintf(stdout, "SPINE: Using spine config file [%s]\n", file);
		}

		for (;;) {
			memset(buff, 0, sizeof(buff));
			if (fgets(buff, BUFSIZE, fp) == NULL) break;
			lineno++;
			p1[0] = '\0';
			p2[0] = '\0';
			int t = spine_config_tokenize(buff, sizeof(buff),
			                              p1, sizeof(p1),
			                              p2, sizeof(p2),
			                              file, lineno, fp);
			if (t <= 0) {
				/* blank, comment, or rejected line; carry on */
				continue;
			}

			if (STRIMATCH(p1, "RDB_Host"))              STRNCOPY(set.rdb_host, p2);
			else if (STRIMATCH(p1, "RDB_Database"))     STRNCOPY(set.rdb_db, p2);
			else if (STRIMATCH(p1, "RDB_User"))         STRNCOPY(set.rdb_user, p2);
			else if (STRIMATCH(p1, "RDB_Pass"))         STRNCOPY(set.rdb_pass, p2);
			else if (STRIMATCH(p1, "RDB_Port")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("RDB_Port", p2, 1, 65535, &v)) {
					set.rdb_port = (int)v;
				}
			}
			else if (STRIMATCH(p1, "RDB_UseSSL")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("RDB_UseSSL", p2, 0, 1, &v)) {
					set.rdb_ssl = (int)v;
				}
			}
			else if (STRIMATCH(p1, "RDB_SSL_Key"))      STRNCOPY(set.rdb_ssl_key, p2);
			else if (STRIMATCH(p1, "RDB_SSL_Cert"))     STRNCOPY(set.rdb_ssl_cert, p2);
			else if (STRIMATCH(p1, "RDB_SSL_CA"))       STRNCOPY(set.rdb_ssl_ca, p2);
			else if (STRIMATCH(p1, "DB_Host"))          STRNCOPY(set.db_host, p2);
			else if (STRIMATCH(p1, "DB_Database"))      STRNCOPY(set.db_db, p2);
			else if (STRIMATCH(p1, "DB_User"))          STRNCOPY(set.db_user, p2);
			else if (STRIMATCH(p1, "DB_Pass"))          STRNCOPY(set.db_pass, p2);
			else if (STRIMATCH(p1, "DB_Port")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("DB_Port", p2, 1, 65535, &v)) {
					set.db_port = (int)v;
				}
			}
			else if (STRIMATCH(p1, "DB_UseSSL")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("DB_UseSSL", p2, 0, 1, &v)) {
					set.db_ssl = (int)v;
				}
			}
			else if (STRIMATCH(p1, "DB_SSL_Key"))       STRNCOPY(set.db_ssl_key, p2);
			else if (STRIMATCH(p1, "DB_SSL_Cert"))      STRNCOPY(set.db_ssl_cert, p2);
			else if (STRIMATCH(p1, "DB_SSL_CA"))        STRNCOPY(set.db_ssl_ca, p2);
			else if (STRIMATCH(p1, "Poller")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("Poller", p2, 0, INT_MAX, &v)) {
					set.poller_id = (int)v;
				}
			}
			else if (STRIMATCH(p1, "DB_PreG")) {
				spine_config_warn("WARNING: DB_PreG is no longer supported\n");
			} else if (STRIMATCH(p1, "Cacti_Log")) {
				STRNCOPY(set.path_logfile, p2);
				set.logfile_processed = 1;
				set.log_destination = LOGDEST_BOTH;
			} else if (STRIMATCH(p1, "SNMP_Clientaddr"))  STRNCOPY(set.snmp_clientaddr, p2);
			else if (STRIMATCH(p1, "CircuitBreakerThreshold")) {
				unsigned long v;
				if (spine_parse_bounded_ulong("CircuitBreakerThreshold", p2,
				                              1, 1000000, &v)) {
					set.circuit_breaker_threshold = (int)v;
				}
			}
			else {
				spine_config_warn("WARNING: Unrecognized directive: %s=%s in %s\n",
					p1, p2, file);
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

/* Volatile-pointer memset that the compiler is forbidden from optimizing
 * out. Used as the portable fallback when explicit_bzero is unavailable. */
static void spine_volatile_bzero(void *p, size_t n) {
	volatile unsigned char *vp = (volatile unsigned char *)p;
	while (n--) *vp++ = 0;
}

/*! \fn void spine_scrub_secrets(void)
 *  \brief zero credential fields in the `set` struct before process exit.
 *
 * Covers DB / RDB passwords and usernames. SSL key paths are filesystem
 * references, not secret material, so they stay. Signal handlers must
 * remain async-signal-safe; this helper is therefore only safe to call
 * from main() and die() on the normal exit path.
 */
/* Single scrub primitive. Compiler-elidable memset is prevented by
 * explicit_bzero when available; falls back to a volatile-pointer loop
 * in spine_volatile_bzero otherwise. One call site, one #ifdef, every
 * caller above routes through this helper. */
static inline void spine_bzero(void *p, size_t n) {
	if (p == NULL || n == 0) return;
#ifdef HAVE_EXPLICIT_BZERO
	explicit_bzero(p, n);
#else
	spine_volatile_bzero(p, n);
#endif
}

void spine_scrub_secrets(void) {
	spine_bzero(set.db_pass,  sizeof(set.db_pass));
	spine_bzero(set.rdb_pass, sizeof(set.rdb_pass));
	spine_bzero(set.db_user,  sizeof(set.db_user));
	spine_bzero(set.rdb_user, sizeof(set.rdb_user));
}

void spine_scrub_target_secrets(struct target_struct *items, int count) {
	if (items == NULL || count <= 0) return;

	for (int i = 0; i < count; i++) {
		target_t *t = &items[i];
		spine_bzero(t->snmp_community,       sizeof(t->snmp_community));
		spine_bzero(t->snmp_username,        sizeof(t->snmp_username));
		spine_bzero(t->snmp_password,        sizeof(t->snmp_password));
		spine_bzero(t->snmp_priv_passphrase, sizeof(t->snmp_priv_passphrase));
		spine_bzero(t->snmp_engine_id,       sizeof(t->snmp_engine_id));
		spine_bzero(t->snmp_context,         sizeof(t->snmp_context));
	}
}

void spine_scrub_host_secrets(struct host_struct *host) {
	if (host == NULL) return;
	spine_bzero(host->snmp_community,       sizeof(host->snmp_community));
	spine_bzero(host->snmp_password,        sizeof(host->snmp_password));
	spine_bzero(host->snmp_priv_passphrase, sizeof(host->snmp_priv_passphrase));
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
		size_t msg_len, perr_len, avail;
		snprintf(perr, BUFSIZE, " [%d, %s]", old_errno, strerror(old_errno));
		msg_len  = strlen(logmessage);
		perr_len = strlen(perr);
		avail    = (BUFSIZE - 1) - msg_len;
		if (avail > 0) {
			size_t copy_n = (perr_len < avail) ? perr_len : avail;
			memcpy(logmessage + msg_len, perr, copy_n);
			logmessage[msg_len + copy_n] = '\0';
		}
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

	fprintf(stderr, "%s", flogmessage);

	if (set.parent_fork == SPINE_PARENT) {
		if (set.php_initialized) {
			php_close(PHP_INIT);
		}
	}

	/* Scrub credentials before the process image disappears so a core
	 * dump or last-moment memory scan cannot recover them. */
	spine_scrub_secrets();

	exit(set.exit_code);
}

char *get_date_format(void) {
	char *log_fmt;
	char log_sep = '/';

	if (!(log_fmt = (char *) malloc(GD_FMT_SIZE))) {
		die("ERROR: Fatal malloc error: util.c get_date_format!");
	}

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
			snprintf(log_fmt, GD_FMT_SIZE, "%%m%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_MN_D_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%b%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MO_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%d%c%%m%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MN_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%d%c%%b%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MO_D:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MN_D:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%b%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		default:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
	}

	return (log_fmt);
}

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

	char logprefix[LOGSIZE];        /* Formatted Log Prefix */
	char ulogmessage[LOGSIZE];      /* Un-Formatted Log Message */
	char flogmessage[LOGSIZE];      /* Formatted Log Message */
	char stdoutmessage[LOGSIZE + 20]; /* Message for stdout */

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

	spine_log_formatter_prefix(logprefix, sizeof(logprefix), set.poller_id);

	/* get time for poller_output table */
	nowbin = time(&nowbin);

	spine_platform_localtime(&nowbin, &now_time);
	now_ptr = &now_time;

	if (IS_LOGGING_TO_STDOUT()) {
		cur_time = get_time_as_double();
		snprintf(stdoutmessage, sizeof(stdoutmessage), "Total[%3.4f] %s", cur_time - start_time, ulogmessage);
		spine_log_sink_stdout(stdoutmessage);
		return TRUE;
	}

	log_fmt = get_date_format();

	if (strlen(log_fmt) == 0) {
		fp = stderr;

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
		fp = stderr;

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

	memcpy(flogmessage + flog_len,              logprefix,   prefix_len);
	memcpy(flogmessage + flog_len + prefix_len, ulogmessage, ulog_len);
	flogmessage[flog_len + prefix_len + ulog_len] = '\0';

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

	/* append a line feed to the log message if needed */
	if (!strstr(flogmessage, "\n")) {
		strcat(flogmessage, "\n");
	}

	if ((IS_LOGGING_TO_FILE() &&
		(set.log_level != POLLER_VERBOSITY_NONE) &&
		(strlen(set.path_logfile) != 0))) {
		if (set.logfile_processed) {
			/* Refuse to follow symlinks: an attacker with write access to the
			 * log directory could otherwise redirect spine's appends into a
			 * sensitive file. O_NOFOLLOW fails the open if the final component
			 * is a symlink; O_APPEND|O_CREAT handles first-write creation. */
			int log_fd = open(set.path_logfile,
				O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW,
				S_IRUSR | S_IWUSR | S_IRGRP);
			if (log_fd >= 0) {
				log_file = fdopen(log_fd, "a");
				if (log_file == NULL) {
					close(log_fd);
				}
			} else {
				log_file = NULL;
			}

			if (log_file) {
				fputs(flogmessage, log_file);
				fclose(log_file);
			} else {
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
			fp = stderr;
		}

		if ((set.stderr_notty) && (fp == stderr)) {
			/* do nothing stderr does not exist */
		} else if ((set.stdout_notty) && (fp == stdout)) {
			/* do nothing stdout does not exist */
		} else {
			/* Format selection. AUTO resolves to JSON when stderr is not a TTY
			 * (systemd-journald, docker logs, k8s stdout collection) so log
			 * collectors get structured fields without regex scraping. TEXT
			 * and JSON force the mode regardless of TTY state. */
			int use_json = 0;
			if (set.log_format == LOGFMT_JSON) {
				use_json = 1;
			} else if (set.log_format == LOGFMT_AUTO && set.stderr_notty && fp == stderr) {
				use_json = 1;
			}

			if (use_json) {
				const char *level = "INFO";
				unsigned long pid_ul = (unsigned long)spine_platform_process_id();
				unsigned long tid_ul = (unsigned long)pthread_self();
				if      (strstr(ulogmessage, "FATAL"))   level = "FATAL";
				else if (strstr(ulogmessage, "ERROR"))   level = "ERROR";
				else if (strstr(ulogmessage, "WARNING")) level = "WARN";
				else if (strstr(ulogmessage, "DEBUG"))   level = "DEBUG";

				char ts[64];
				struct tm utc;
#ifdef _WIN32
				gmtime_s(&utc, &nowbin);
#else
				gmtime_r(&nowbin, &utc);
#endif
				strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &utc);

				char msg_esc[LOGSIZE * 2];
				spine_json_escape(msg_esc, sizeof(msg_esc), ulogmessage);

				fprintf(fp,
					"{\"ts\":\"%s\",\"level\":\"%s\",\"poller\":%d,\"pid\":%lu,\"tid\":%lu,\"msg\":\"%s\"}\n",
					ts, level, set.poller_id,
					pid_ul,
					tid_ul,
					msg_esc);
				spine_sd_journal_log(level, ulogmessage, set.poller_id, pid_ul, tid_ul);
			} else {
				fprintf(fp, "%s", flogmessage);
				{
					const char *level = "INFO";
					unsigned long pid_ul = (unsigned long)spine_platform_process_id();
					unsigned long tid_ul = (unsigned long)pthread_self();

					if      (strstr(ulogmessage, "FATAL"))   level = "FATAL";
					else if (strstr(ulogmessage, "ERROR"))   level = "ERROR";
					else if (strstr(ulogmessage, "WARNING")) level = "WARN";
					else if (strstr(ulogmessage, "DEBUG"))   level = "DEBUG";

					spine_sd_journal_log(level, ulogmessage, set.poller_id, pid_ul, tid_ul);
				}
			}
		}
	}

	free(log_fmt);

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
				if (!ignore_special) {
					return FALSE;
				}
				break;
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
#if defined(CLOCK_MONOTONIC_FAST)
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC_FAST, &now) == 0) {
		return (double) now.tv_sec + ((double) now.tv_nsec / 1000000000.0);
	}
#elif defined(CLOCK_MONOTONIC)
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
		return (double) now.tv_sec + ((double) now.tv_nsec / 1000000000.0);
	}
#endif

	struct timeval fallback_now;

	gettimeofday(&fallback_now, NULL);

	return (fallback_now).tv_sec + ((double) (fallback_now).tv_usec / 1000000);
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
		case '"': case ' ': case '\t':
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
#ifdef HAVE_PCRE2
	static __thread char msgbuf[SMALL_BUFSIZE];
	static __thread pcre2_match_data *match_data = NULL;
	
	typedef struct {
		char id[SMALL_BUFSIZE];
		pcre2_code *re;
		UT_hash_handle hh;
	} regex_cache_entry_t;
	
	static regex_cache_entry_t *regex_cache = NULL;
	static pthread_mutex_t regex_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
	
	pcre2_code *re = NULL;
	
	pthread_mutex_lock(&regex_cache_mutex);
	regex_cache_entry_t *entry = NULL;
	HASH_FIND_STR(regex_cache, exp, entry);
	if (!entry) {
		int errornumber;
		PCRE2_SIZE erroroffset;
		re = pcre2_compile((PCRE2_SPTR)exp, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
		if (re) {
			pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);
			entry = calloc(1, sizeof(regex_cache_entry_t));
			strlcpy(entry->id, exp, sizeof(entry->id));
			entry->re = re;
			HASH_ADD_STR(regex_cache, id, entry);
		}
	} else {
		re = entry->re;
	}
	pthread_mutex_unlock(&regex_cache_mutex);
	
	if (!re) return value;
	
	if (!match_data) match_data = pcre2_match_data_create(MAX_MATCHES, NULL);
	
	int rc = pcre2_match(re, (PCRE2_SPTR)value, PCRE2_ZERO_TERMINATED, 0, 0, match_data, NULL);
	if (rc < 0) return value;
	
	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
	size_t match_len = ovector[1] - ovector[0];
	if (match_len >= SMALL_BUFSIZE) {
		match_len = SMALL_BUFSIZE - 1;
	}
	
	memcpy(msgbuf, value + ovector[0], match_len);
	msgbuf[match_len] = '\0';
	
	return msgbuf;
#else
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
	reti = regcomp(&regex, exp, 0);
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
#endif
}

/* JSON-escape src into dst. Writes at most dst_len-1 bytes then NUL. Returns
 * dst. Caller sizes dst to at least 6*strlen(src)+1 to survive worst-case
 * \uXXXX expansion of control characters. */
char *spine_json_escape(char *dst, size_t dst_len, const char *src) {
	size_t i = 0;
	if (dst_len == 0) return dst;
	if (!src) { dst[0] = '\0'; return dst; }

	while (*src && i + 7 < dst_len) {
		unsigned char c = (unsigned char)*src++;
		if (c == '"' || c == '\\') {
			dst[i++] = '\\';
			dst[i++] = (char)c;
		} else if (c == '\n') {
			dst[i++] = '\\'; dst[i++] = 'n';
		} else if (c == '\r') {
			dst[i++] = '\\'; dst[i++] = 'r';
		} else if (c == '\t') {
			dst[i++] = '\\'; dst[i++] = 't';
		} else if (c < 0x20) {
			i += (size_t)snprintf(dst + i, dst_len - i, "\\u%04x", c);
		} else {
			dst[i++] = (char)c;
		}
	}
	dst[i] = '\0';
	return dst;
}

/*! \fn int spine_health_check(void)
 *  \brief Probe DB reachability and raw ICMP availability, print JSON, exit.
 *
 *  Returns TRUE (1) on success, FALSE (0) on failure. Caller is responsible
 *  for translating to exit codes. Intended to back `spine --check`, which
 *  systemd / k8s / nagios wrappers can parse: success prints
 *    {"status":"ok","db":"connected","icmp":"available|unavailable"}
 *  failure prints
 *    {"status":"failed","error":"..."}
 *  with a non-empty human-readable error message.
 */
int spine_health_check(void) {
	MYSQL mysql;
	MYSQL *conn;
	int   icmp_ok = 0;

	mysql_init(&mysql);
	/* 3s timeout keeps the probe fast enough for readiness checks. */
	unsigned int t = 3;
	mysql_options(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, (const char *)&t);

	conn = mysql_real_connect(&mysql,
		strlen(set.db_host) ? set.db_host : "localhost",
		set.db_user,
		set.db_pass,
		set.db_db,
		set.db_port,
		NULL, 0);

	if (!conn) {
		char err[512];
		char esc[2048];
		snprintf(err, sizeof(err), "db connect: %s", mysql_error(&mysql));
		spine_json_escape(esc, sizeof(esc), err);
		printf("{\"status\":\"failed\",\"error\":\"%s\"}\n", esc);
		mysql_close(&mysql);
		return 0;
	}

	/* Raw ICMP socket test. IPPROTO_ICMP on a SOCK_RAW fd needs CAP_NET_RAW
	 * or uid 0 on Linux, privilege on *BSD, and Administrator on Windows.
	 * A failure here is informational, not fatal: Cacti deployments that
	 * only rely on TCP/SNMP availability still want a passing --check. */
#ifdef _WIN32
	icmp_ok = 0;
#else
	{
		int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		if (s >= 0) {
			icmp_ok = 1;
			close(s);
		}
	}
#endif

	printf("{\"status\":\"ok\",\"db\":\"connected\",\"icmp\":\"%s\"}\n",
		icmp_ok ? "available" : "unavailable");

	mysql_close(&mysql);
	return 1;
}

/*! \fn void spine_dump_config(void)
 *  \brief Print every effective setting read from spine.conf as key=value.
 *
 *  Passwords are redacted. Caller is responsible for exiting. Output is
 *  intentionally plain key=value so operators can pipe through grep, diff
 *  two hosts, or pin into a golden-config baseline.
 */
void spine_dump_config(void) {
	printf("# spine effective configuration\n");
	printf("DB_Host = %s\n",     set.db_host);
	printf("DB_Database = %s\n", set.db_db);
	printf("DB_User = %s\n",     set.db_user);
	printf("DB_Pass = %s\n",     strlen(set.db_pass) ? "[REDACTED]" : "");
	printf("DB_Port = %u\n",     set.db_port);
	printf("DB_UseSSL = %d\n",   set.db_ssl);
	printf("DB_SSL_Key = %s\n",  set.db_ssl_key);
	printf("DB_SSL_Cert = %s\n", set.db_ssl_cert);
	printf("DB_SSL_CA = %s\n",   set.db_ssl_ca);

	printf("RDB_Host = %s\n",     set.rdb_host);
	printf("RDB_Database = %s\n", set.rdb_db);
	printf("RDB_User = %s\n",     set.rdb_user);
	printf("RDB_Pass = %s\n",     strlen(set.rdb_pass) ? "[REDACTED]" : "");
	printf("RDB_Port = %u\n",     set.rdb_port);
	printf("RDB_UseSSL = %d\n",   set.rdb_ssl);

	printf("Poller = %d\n",          set.poller_id);
	printf("Threads = %d\n",         set.threads);
	printf("Cacti_Log = %s\n",       set.path_logfile);
	printf("SNMP_Clientaddr = %s\n", set.snmp_clientaddr);
	printf("Mode = %d\n",            set.mode);
	printf("PingMethod = %d\n",      set.ping_method);
	printf("PingRetries = %d\n",     set.ping_retries);
	printf("PingTimeout = %d\n",     set.ping_timeout);
	printf("LogVerbosity = %d\n",    set.log_level);
	printf("LogFormat = %d\n",       set.log_format);
	printf("DryRun = %d\n",          set.dry_run);
	printf("CircuitBreakerThreshold = %d\n", set.circuit_breaker_threshold);
}

/* Flags whose value is credential material. Short flags match a single
 * character (e.g. "c" matches "-c"), long flags match a whole word
 * (e.g. "community" matches "--community"). The short list is case-
 * sensitive: -A / -X / -E / -Z (SNMPv3 auth/priv passphrases, auth/priv
 * passwords for some backends) are distinct from -a / -x and must all
 * be redacted. The earlier revision of this patch missed -A and -X,
 * which left SNMPv3 passphrases in the clear when a poll logged a
 * failed command; both are included here. */
/* Short flags carrying a credential VALUE in the next token (or in
 * =VAL form). -c is SNMPv1/v2c community. -u is v3 security name.
 * -a is v3 auth protocol. -x is v3 priv protocol. -p is some
 * client-tool passwords. -A/-X are the v3 auth/priv passphrases.
 * -E/-Z are engine identifiers. -C is the net-snmp context file path
 * (leaks path to key material). -3m/-3M are master auth/priv keys,
 * -3k/-3K are localized auth/priv keys (net-snmp snmp.conf(5)).
 *
 * If upstream net-snmp adds further short flags that carry key or
 * passphrase material, add them here; never guess. */
static const char *const cred_short_flags[] = {
	"c", "u", "a", "x", "p", "A", "X", "E", "Z", "C",
	"3m", "3M", "3k", "3K",        /* v3 master / localized keys */
	NULL
};

static const char *const cred_long_flags[] = {
	"community", "password", "secret",
	"authPassphrase", "privPassphrase",
	"authKey", "privKey",          /* pre-computed v3 keys */
	NULL
};

static int is_space_byte(char c) {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

/* Append a single char; silently truncates and keeps out NUL-terminated. */
static void redact_putc(char *out, size_t outsz, size_t *pos, char c) {
	if (*pos + 1 < outsz) {
		out[*pos] = c;
		(*pos)++;
	}
	out[(*pos < outsz) ? *pos : (outsz ? outsz - 1 : 0)] = '\0';
}

static void redact_puts(char *out, size_t outsz, size_t *pos, const char *s) {
	while (*s) {
		redact_putc(out, outsz, pos, *s++);
	}
}

/* Emit the mask value. The "=" form keeps the equals sign; the bare form
 * inserts a single space so the redacted VAL stays tokenised. */
static void emit_mask(char *out, size_t outsz, size_t *pos) {
	redact_puts(out, outsz, pos, "***");
}

static int short_flag_is_cred(const char *flag, size_t flag_len) {
	int i;
	size_t n;
	for (i = 0; cred_short_flags[i] != NULL; i++) {
		n = strlen(cred_short_flags[i]);
		if (flag_len == n && strncmp(flag, cred_short_flags[i], n) == 0) {
			return 1;
		}
	}
	return 0;
}

static int long_flag_is_cred(const char *flag, size_t flag_len) {
	int i;
	size_t n;
	for (i = 0; cred_long_flags[i] != NULL; i++) {
		n = strlen(cred_long_flags[i]);
		if (flag_len == n && strncmp(flag, cred_long_flags[i], n) == 0) {
			return 1;
		}
	}
	return 0;
}

void spine_redact_args(const char *cmd, char *out, size_t outsz) {
	size_t pos = 0;
	const char *p;

	if (out == NULL || outsz == 0) return;
	out[0] = '\0';
	if (cmd == NULL) return;

	p = cmd;
	while (*p) {
		/* Copy runs of whitespace verbatim. */
		if (is_space_byte(*p)) {
			redact_putc(out, outsz, &pos, *p);
			p++;
			continue;
		}

		/* Token starts. Detect flag shape. */
		if (*p == '-') {
			int is_long = 0;
			const char *flag_start;
			const char *eq;
			const char *token_start = p;
			size_t flag_len;

			redact_putc(out, outsz, &pos, *p);
			p++;
			if (*p == '-') {
				is_long = 1;
				redact_putc(out, outsz, &pos, *p);
				p++;
			}

			flag_start = p;
			while (*p && !is_space_byte(*p) && *p != '=') {
				p++;
			}
			flag_len = (size_t)(p - flag_start);
			eq = (*p == '=') ? p : NULL;

			/* Copy the flag name verbatim. */
			{
				const char *q;
				for (q = flag_start; q < flag_start + flag_len; q++) {
					redact_putc(out, outsz, &pos, *q);
				}
			}

			int redact = is_long ? long_flag_is_cred(flag_start, flag_len)
			                     : short_flag_is_cred(flag_start, flag_len);

			if (eq != NULL) {
				/* --flag=VAL or -c=VAL */
				redact_putc(out, outsz, &pos, '=');
				p++;
				if (redact) {
					/* Mask to end of token. */
					while (*p && !is_space_byte(*p)) p++;
					emit_mask(out, outsz, &pos);
				} else {
					while (*p && !is_space_byte(*p)) {
						redact_putc(out, outsz, &pos, *p);
						p++;
					}
				}
				continue;
			}

			if (!redact) {
				(void)token_start;
				continue;
			}

			/* Flag takes next token as value. Preserve spacing, mask value. */
			while (*p && is_space_byte(*p)) {
				redact_putc(out, outsz, &pos, *p);
				p++;
			}
			if (*p == '\0') break;
			while (*p && !is_space_byte(*p)) p++;
			emit_mask(out, outsz, &pos);
			continue;
		}

		/* Non-flag token: copy verbatim. */
		while (*p && !is_space_byte(*p)) {
			redact_putc(out, outsz, &pos, *p);
			p++;
		}
	}

	if (outsz > 0) {
		out[(pos < outsz) ? pos : outsz - 1] = '\0';
	}
}
