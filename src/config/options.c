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

#include "internal/common.h"
#include "app/spine.h"
#include "settings_internal.h"
#include <limits.h>

static void read_logging_options(MYSQL *mysql) {
	char *res;
	char web_root[BUFSIZE] = {0};
	/* get logging level from database - overrides spine.conf */
	if ((res = getsetting(mysql, LOCAL, "log_verbosity")) != 0) {
		const int n = atoi(res);
		free(res);
		if (n != 0) set.logging.log_level = n;
	}

	/* determine script server path operation and default log file processing */
	if ((res = getsetting(mysql, LOCAL, "path_webroot")) != 0) {
		snprintf(set.php.path_php_server, BUFSIZE, "%s/script_server.php", res);
		snprintf(web_root, BUFSIZE, "%s", res);
		free(res);
	}

	/* determine logfile path */
	if ((res = getsetting(mysql, LOCAL, "path_cactilog")) != 0) {
		if (strlen(res) != 0) {
			snprintf(set.logging.path_logfile, DBL_BUFSIZE, "%s", res);
		} else {
			if (strlen(web_root) != 0) {
				snprintf(set.logging.path_logfile, DBL_BUFSIZE, "%s/log/cacti.log", web_root);
			} else {
				set.logging.path_logfile[0] = '\0';
			}
		}
		free(res);
	} else {
		snprintf(set.logging.path_logfile, DBL_BUFSIZE, "%s/log/cacti.log", web_root);
	}

	/* get log separator */
	if ((res = getsetting(mysql, LOCAL, "default_datechar")) != 0) {
		set.logging.log_datetime_separator = atoi(res);
		free(res);

		if (set.logging.log_datetime_separator < GDC_MIN || set.logging.log_datetime_separator > GDC_MAX) {
			set.logging.log_datetime_separator = GDC_DEFAULT;
		}
	}

	/* get log date format */
	if ((res = getsetting(mysql, LOCAL, "default_date_format")) != 0) {
		set.logging.log_datetime_format = atoi(res);
		free(res);

		if (set.logging.log_datetime_format < GD_MIN || set.logging.log_datetime_format > GD_MAX) {
			set.logging.log_datetime_format = GD_DEFAULT;
		}
	}

	/* The remaining option reads can log at debug verbosity. Refresh the
	 * cached format before any of those messages are emitted. */
	set_date_format();

	/* determine log file, syslog or both, default is 1 or log file only */
	if ((res = getsetting(mysql, LOCAL, "log_destination")) != 0) {
		set.logging.log_destination = parse_logdest(res, LOGDEST_FILE);
		free(res);
	} else {
		set.logging.log_destination = LOGDEST_FILE;
	}

	/* log the path_webroot variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php_server variable is %s", set.php.path_php_server));

	/* log the path_cactilog variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_cactilog variable is %s", set.logging.path_logfile));

	/* the version variable */
	SPINE_LOG_DEBUG(("DEBUG: The version variable is %s", set.database.version));

	/* log the log_destination variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_destination variable is %i (%s)",
		set.logging.log_destination,
		printable_logdest(set.logging.log_destination)));

	set.logging.logfile_processed = TRUE;
}

static void read_ping_options(MYSQL *mysql) {
	char *res;
	/* set availability_method */
	if ((res = getsetting(mysql, LOCAL, "availability_method")) != 0) {
		set.availability.availability_method = atoi(res);
		free(res);
	}

	/* log the availability_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The availability_method variable is %i", set.availability.availability_method));

	/* set ping_recovery_count */
	if ((res = getsetting(mysql, LOCAL, "ping_recovery_count")) != 0) {
		set.availability.ping_recovery_count = atoi(res);
		free(res);
	}

	/* log the ping_recovery_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_recovery_count variable is %i", set.availability.ping_recovery_count));

	/* set ping_failure_count */
	if ((res = getsetting(mysql, LOCAL, "ping_failure_count")) != 0) {
		set.availability.ping_failure_count = atoi(res);
		free(res);
	}

	/* log the ping_failure_count variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_failure_count variable is %i", set.availability.ping_failure_count));

	/* set ping_method */
	if ((res = getsetting(mysql, LOCAL, "ping_method")) != 0) {
		set.availability.ping_method = atoi(res);
		free(res);
	}

	/* log the ping_method variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_method variable is %i", set.availability.ping_method));

	/* set ping_retries */
	if ((res = getsetting(mysql, LOCAL, "ping_retries")) != 0) {
		set.availability.ping_retries = atoi(res);
		free(res);
	}

	/* log the ping_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_retries variable is %i", set.availability.ping_retries));

	/* set ping_timeout */
	if ((res = getsetting(mysql, LOCAL, "ping_timeout")) != 0) {
		set.availability.ping_timeout = atoi(res);
		free(res);
	} else {
		set.availability.ping_timeout = 400;
	}

	/* log the ping_timeout variable */
	SPINE_LOG_DEBUG(("DEBUG: The ping_timeout variable is %i", set.availability.ping_timeout));

	/* set snmp_retries */
	if ((res = getsetting(mysql, LOCAL, "snmp_retries")) != 0) {
		set.snmp.snmp_retries = atoi(res);
		free(res);
	} else {
		set.snmp.snmp_retries = 3;
	}

	/* log the snmp_retries variable */
	SPINE_LOG_DEBUG(("DEBUG: The snmp_retries variable is %i", set.snmp.snmp_retries));
}

static void read_process_options(MYSQL *mysql, int mode) {
	char *res;
	/* get Cacti defined max threads override spine.conf */
	res = set.poller.threads_set == FALSE ? getpsetting(mysql, mode, "threads") : NULL;
	if (res != NULL) {
		set.poller.threads = atoi(res);
		free(res);
		if (set.poller.threads > MAX_THREADS) {
			set.poller.threads = MAX_THREADS;
		}
	}

	/* log the threads variable */
	SPINE_LOG_DEBUG(("DEBUG: The threads variable is %i", set.poller.threads));

	/* get the poller_interval for those who have elected to go with a 1 minute polling interval */
	if ((res = getsetting(mysql, LOCAL, "poller_interval")) != 0) {
		set.poller.poller_interval = atoi(res);
		free(res);
	} else {
		set.poller.poller_interval = 0;
	}

	/* log the poller_interval variable */
	if (set.poller.poller_interval == 0) {
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is the system default"));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: The polling interval is %i seconds", set.poller.poller_interval));
	}

	/* get the concurrent_processes variable to determine thread sleep values */
	if ((res = getsetting(mysql, LOCAL, "concurrent_processes")) != 0) {
		set.poller.num_parent_processes = atoi(res);
		free(res);
	} else {
		set.poller.num_parent_processes = 1;
	}

	/* log the concurrent processes variable */
	SPINE_LOG_DEBUG(("DEBUG: The number of concurrent processes is %i", set.poller.num_parent_processes));

	/* get the script timeout to establish timeouts */
	if ((res = getsetting(mysql, LOCAL, "script_timeout")) != 0) {
		set.php.script_timeout = atoi(res);
		free(res);
		if (set.php.script_timeout < 5) {
			set.php.script_timeout = 5;
		}
	} else {
		set.php.script_timeout = 25;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The script timeout is %i", set.php.script_timeout));
}

static void read_script_options(MYSQL *mysql) {
	char *res;
	/* get selective_device_debug string */
	if ((res = getsetting(mysql, LOCAL, "selective_device_debug")) != 0) {
		STRNCOPY(set.logging.selective_device_debug, res);
		free(res);
	}

	/* log the selective_device_debug variable */
	SPINE_LOG_DEBUG(("DEBUG: The selective_device_debug variable is %s", set.logging.selective_device_debug));

	/* get spine_log_level */
	if ((res = getsetting(mysql, LOCAL, "spine_log_level")) != 0) {
		set.logging.spine_log_level = atoi(res);
		free(res);
	}

	/* log the spine_log_level variable */
	SPINE_LOG_DEBUG(("DEBUG: The spine_log_level variable is %i", set.logging.spine_log_level));

	/* get the number of script server processes to run */
	if ((res = getsetting(mysql, LOCAL, "php_servers")) != 0) {
		set.php.php_servers = atoi(res);
		free(res);

		if (set.php.php_servers > MAX_PHP_SERVERS) {
			set.php.php_servers = MAX_PHP_SERVERS;
		}

		if (set.php.php_servers <= 0) {
			set.php.php_servers = 1;
		}
	} else {
		set.php.php_servers = 2;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of php script servers to run is %i", set.php.php_servers));

	/* get the number of active profiles on the system run */
	if ((res = getsetting(mysql, LOCAL, "active_profiles")) != 0) {
		set.poller.active_profiles = atoi(res);
		free(res);

		if (set.poller.active_profiles <= 0) {
			set.poller.active_profiles = 0;
		}
	} else {
		set.poller.active_profiles = 0;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of active data source profiles is %i", set.poller.active_profiles));

	/* get the number of snmp_ports in use */
	if ((res = getsetting(mysql, LOCAL, "total_snmp_ports")) != 0) {
		set.snmp.total_snmp_ports = atoi(res);
		free(res);

		if (set.snmp.total_snmp_ports <= 0) {
			set.snmp.total_snmp_ports = 0;
		}
	} else {
		set.snmp.total_snmp_ports = 0;
	}

	/* log the script timeout value */
	SPINE_LOG_DEBUG(("DEBUG: The number of snmp ports on the system is %i", set.snmp.total_snmp_ports));
}

static void read_php_requirement(MYSQL *mysql) {
	MYSQL_RES *result;
	int num_rows;
	char sqlbuf[HUGE_BUFSIZE];
	char *sqlp;
	/*----------------------------------------------------------------
	 * determine if the php script server is required by searching for
	 * all the host records for an action of POLLER_ACTION_PHP_SCRIPT_SERVER.
	 * If we get even one, it means we have to deal with the PHP script
	 * server.
	 *
	 */
	set.php.php_required = FALSE; /* assume no */

	/* log the requirement for the script server */
	if (!strlen(set.hosts.host_id_list)) {
		sqlp = sqlbuf;
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += append_hostrange(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), "host_id");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " AND poller_id=%i", set.poller.poller_id);
		spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " LIMIT 1");

		result = config_query(mysql, LOCAL, sqlbuf);
		num_rows = result != NULL ? spine_count_to_int(mysql_num_rows(result)) : 0;
		db_free_result(result);

		if (num_rows > 0) set.php.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: StartDevice='%i', EndDevice='%i', TotalPHPScripts='%i'",
			set.hosts.start_host_id,
			set.hosts.end_host_id,
			num_rows));
	} else {
		sqlp = sqlbuf;
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " AND host_id IN(%s)", set.hosts.host_id_list);
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " AND poller_id=%i", set.poller.poller_id);
		spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t) (sqlp - sqlbuf), " LIMIT 1");

		result = config_query(mysql, LOCAL, sqlbuf);
		num_rows = result != NULL ? spine_count_to_int(mysql_num_rows(result)) : 0;
		db_free_result(result);

		if (num_rows > 0) set.php.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: Device List to be polled='%s', TotalPHPScripts='%i'",
			set.hosts.host_id_list,
			num_rows));
	}

	SPINE_LOG_DEBUG(("DEBUG: The PHP Script Server is %sRequired",
		set.php.php_required
			? ""
			: "Not "));
}

static void read_snmp_batch_size(MYSQL *mysql) {
	char *res;
	/* determine the maximum oid's to obtain in a single get request */
	if ((res = getsetting(mysql, LOCAL, "max_get_size")) != 0) {
		set.snmp.snmp_max_get_size = atoi(res);
		free(res);

		if (set.snmp.snmp_max_get_size > 128) {
			set.snmp.snmp_max_get_size = 128;
		}
	} else {
		set.snmp.snmp_max_get_size = 25;
	}

	/* log the snmp_max_get_size variable */
	SPINE_LOG_DEBUG(("DEBUG: The Maximum SNMP OID Get Size is %i", set.snmp.snmp_max_get_size));
}

static void publish_snmp_capabilities(MYSQL *mysql) {
	char spine_auth[BUFSIZE] = {0};
	char spine_priv[BUFSIZE] = {0};
	char spine_capabilities[BUFSIZE] = {0};

#ifndef NETSNMP_DISABLE_MD5
	strcat(spine_auth, "MD5");
#endif

	strcat(spine_auth, (strlen(spine_auth) > 0 ? ",SHA" : "SHA"));

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
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES128" : "AES128"));
#endif

#if defined(NETSNMP_DRAFT_BLUMENTHAL_AES_04)
	// cppcheck-suppress knownConditionTrueFalse
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES192" : "AES192"));
#endif

#if defined(NETSNMP_DRAFT_BLUMENTHAL_AES_04)
	// cppcheck-suppress knownConditionTrueFalse
	strcat(spine_priv, (strlen(spine_priv) > 0 ? ",AES256" : "AES256"));
#endif

	/* Each source buffer can be BUFSIZE bytes. Bound both fields so the
	 * combined capability document always fits in its destination. */
	if (!format_spine_capabilities(spine_capabilities,
			sizeof(spine_capabilities), spine_auth, spine_priv)) {
		SPINE_LOG(("ERROR: Unable to format Spine SNMP capabilities"));
		spine_capabilities[0] = '\0';
	}

	if (set.poller.poller_id == 1 && spine_capabilities[0] != '\0') {
		putsetting(mysql, LOCAL, "spine_capabilities", spine_capabilities);
	}
}

/*! \fn void read_config_options(void)
 *  \brief Reads the default Spine runtime parameters from the database and set's the global array
 *
 *  load default values from the database for poller processing
 *
 */
/*! \fn int db_row_alias_upsert_supported(const char *version, unsigned long version_number)
 *  \brief whether the server accepts INSERT ... AS alias ON DUPLICATE KEY UPDATE
 */
int db_row_alias_upsert_supported(const char *version, unsigned long version_number) {
	if (version == NULL) {
		return FALSE;
	}

	for (const char *p = version; *p != '\0'; p++) {
		if (strncasecmp(p, "mariadb", 7) == 0) {
			return FALSE;
		}
	}

	return version_number >= 80020 && version_number < 100000;
}

void read_config_options() {
	MYSQL mysql;
	MYSQL mysqlr;
	int mode;
	char *res;

	if (!db_connect(LOCAL, &mysql)) die("FATAL: Unable to connect to the local database");

	/* one round trip instead of one per setting */
	settings_cache_load(&mysql, LOCAL);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		if (!db_connect(REMOTE, &mysqlr)) die("FATAL: Unable to connect to the remote database");
		mode = REMOTE;
	} else {
		mode = LOCAL;
	}

	/* get the mysql server version */
	if ((res = getglobalvariable(&mysql, LOCAL, "version")) != 0) {
		snprintf(set.database.version, BUFSIZE, "%s", res);
		free(res);
	}

	/* The row alias form, INSERT ... AS rs, is a syntax error before
	   MySQL 8.0.20 and is not MariaDB syntax. */
	set.database.onupdate = db_row_alias_upsert_supported(set.database.version, mysql_get_server_version(&mysql));

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

	read_logging_options(&mysql);

	/* get PHP Path Information for Scripting */
	if ((res = getsetting(&mysql, LOCAL, "path_php_binary")) != 0) {
		STRNCOPY(set.php.path_php, res);
		free(res);
	}

	/* log the path_php variable */
	SPINE_LOG_DEBUG(("DEBUG: The path_php variable is %s", set.php.path_php));

	read_ping_options(&mysql);

	/* set logging option for errors */
	set.logging.log_perror = getboolsetting(&mysql, LOCAL, "log_perror", FALSE);

	/* log the log_perror variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_perror variable is %i", set.logging.log_perror));

	/* set logging option for errors */
	set.logging.log_pwarn = getboolsetting(&mysql, LOCAL, "log_pwarn", FALSE);

	/* log the log_pwarn variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pwarn variable is %i", set.logging.log_pwarn));

	/* set option to increase insert performance */
	set.boost.boost_redirect = getboolsetting(&mysql, LOCAL, "boost_redirect", FALSE);

	/* log the boost_redirect variable */
	SPINE_LOG_DEBUG(("DEBUG: The boost_redirect variable is %i", set.boost.boost_redirect));

	/* set option for determining if boost is enabled */
	set.boost.boost_enabled = getboolsetting(&mysql, LOCAL, "boost_rrd_update_enable", FALSE);

	/* log the boost_rrd_update_enable variable */
	SPINE_LOG_DEBUG(("DEBUG: The boost_rrd_update_enable variable is %i", set.boost.boost_enabled));

	/* set logging option for statistics */
	set.logging.log_pstats = getboolsetting(&mysql, LOCAL, "log_pstats", FALSE);

	/* log the log_pstats variable */
	SPINE_LOG_DEBUG(("DEBUG: The log_pstats variable is %i", set.logging.log_pstats));

	read_process_options(&mysql, mode);

	read_script_options(&mysql);

	read_php_requirement(&mysql);

	read_snmp_batch_size(&mysql);

	publish_snmp_capabilities(&mysql);

	db_disconnect(&mysql);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		db_disconnect(&mysqlr);
	}

	settings_cache_free();
}
