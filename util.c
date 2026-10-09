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
#include <stddef.h>
#include <limits.h>

#define SPINE_STRINGIFY_INNER(value) #value
#define SPINE_STRINGIFY(value) SPINE_STRINGIFY_INNER(value)

/* Bounded formatting must reject truncation before a partial SQL statement or
 * command can be used. Return the number actually written, never the size that
 * would have been needed, so append callers cannot advance past the buffer. */
int spine_snprintf(char *output, size_t capacity, const char *format, ...) {
	va_list args;
	int length;

	va_start(args, format);
	length = vsnprintf(output, capacity, format, args);
	va_end(args);
	if (length < 0 || (size_t) length >= capacity) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Formatted output exceeds its destination buffer");
	}
	return length;
}

int spine_count_to_int(unsigned long long count) {
	if (count > INT_MAX) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Result count exceeds supported integer range");
	}
	return (int)count;
}

void spine_sleep_usec(unsigned int microseconds) {
	struct timespec requested = {
		(time_t)(microseconds / 1000000), (long)(microseconds % 1000000) * 1000
	};
	while (nanosleep(&requested, &requested) != 0) {
		if (errno != EINTR) {
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Unable to wait for retry delay");
		}
	}
}

double spine_monotonic_time(void) {
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to read monotonic clock");
	}
	return (double)now.tv_sec + (double)now.tv_nsec / 1000000000;
}

static int spine_wait_fd(int fd, double deadline, bool writable) {
	if (fd < 0 || fd >= FD_SETSIZE) {
		errno = EBADF;
		return -1;
	}
	if (!isfinite(deadline)) {
		errno = EINVAL;
		return -1;
	}
	for (;;) {
		double remaining = deadline - spine_monotonic_time();
		if (remaining <= 0) return 0;
		if (remaining > INT_MAX) {
			errno = EINVAL;
			return -1;
		}
		struct timeval timeout;
		timeout.tv_sec = (time_t)remaining;
		timeout.tv_usec = (suseconds_t)((remaining - (double)timeout.tv_sec) * 1000000);
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		int status = select(fd + 1, writable ? NULL : &fds, writable ? &fds : NULL, NULL, &timeout);
		if (status < 0 && errno == EINTR) continue;
		return status;
	}
}

int spine_wait_readable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, FALSE);
}

int spine_wait_writable(int fd, double deadline) {
	return spine_wait_fd(fd, deadline, TRUE);
}


int spine_permits_init(spine_permits_t *permits, int count) {
	if (count < 0) return EINVAL;
	int status = pthread_mutex_init(&permits->mutex, NULL);
	if (status == 0) permits->available = count;
	return status;
}

int spine_permits_destroy(spine_permits_t *permits) {
	return pthread_mutex_destroy(&permits->mutex);
}

static void spine_permits_lock(spine_permits_t *permits) {
	if (pthread_mutex_lock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to lock process permits");
	}
}

static void spine_permits_unlock(spine_permits_t *permits) {
	if (pthread_mutex_unlock(&permits->mutex) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to unlock process permits");
	}
}

int spine_permits_try_acquire(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EAGAIN;
	if (permits->available > 0) {
		permits->available--;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_release(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int status = EOVERFLOW;
	if (permits->available < INT_MAX) {
		permits->available++;
		status = 0;
	}
	spine_permits_unlock(permits);
	return status;
}

int spine_permits_available(spine_permits_t *permits) {
	spine_permits_lock(permits);
	int available = permits->available;
	spine_permits_unlock(permits);
	return available;
}

void spine_clear_sensitive(void *buffer, size_t length) {
	volatile unsigned char *bytes = buffer;
	while (length > 0) {
		*bytes++ = 0;
		length--;
	}
}

/* Preserve printable device output while keeping each log record on one line.
 * Also remove terminal controls and Unicode line/paragraph separators. */
void spine_sanitize_log_message(char *message) {
	for (unsigned char *p = (unsigned char *)message; *p != 0; p++) {
		if (*p < 0x20 || *p == 0x7f) {
			*p = ' ';
		} else if (p[0] == 0xc2 && p[1] == 0x85) {
			p[0] = ' ';
			p[1] = ' ';
		} else if (p[0] == 0xe2 && p[1] == 0x80 && (p[2] == 0xa8 || p[2] == 0xa9)) {
			p[0] = ' ';
			p[1] = ' ';
			p[2] = ' ';
		}
	}
}

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
	if (option == NULL || value == NULL || nopts >= (int)(sizeof(opttable) / sizeof(opttable[0]))) {
		die("ERROR: Invalid or excessive command-line setting overrides");
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

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (int i = 0; i < nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			retval = strdup(opttable[i].val);
			return retval;
		}
	}

	/* served from the bulk-loaded table when read_config_options() is running */
	if (settings_cache != NULL) {
		for (int i = 0; i < settings_cache_count; i++) {
			if (STRIMATCH(setting, settings_cache[i].name)) {
				return strdup(settings_cache[i].value);
			}
		}

		return strdup("");
	}

	spine_snprintf(qstring, sizeof(qstring), "SELECT SQL_NO_CACHE value FROM settings WHERE name = '%s'", setting);

	result = db_query(psql, mode, qstring);
	if (result == NULL) return strdup("");
	mysql_row = mysql_num_rows(result) > 0 ? mysql_fetch_row(result) : NULL;
	retval = mysql_row != NULL && mysql_row[0] != NULL ? strdup(mysql_row[0]) : strdup("");
	db_free_result(result);
	return retval;
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
int putsetting(MYSQL *psql, int mode, const char *mysetting, const char *myvalue) {
	char  qstring[BUFSIZE];
	int   result = 0;

	assert(psql    != 0);
	assert(mysetting != 0);
	assert(myvalue   != 0);

	if (set.database.onupdate == 0) {
		spine_snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
			"VALUES ('%s', '%s') "
			"ON DUPLICATE KEY UPDATE value = VALUES(value)", mysetting, myvalue);
	} else {
		spine_snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
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

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (int i = 0; i < nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			retval = strdup(opttable[i].val);
			return retval;
		}
	}

	spine_snprintf(qstring, sizeof(qstring), "SELECT SQL_NO_CACHE %s FROM poller WHERE id = '%d'", setting, set.poller.poller_id);

	result = db_query(psql, mode, qstring);
	if (result == NULL) return NULL;
	mysql_row = mysql_num_rows(result) > 0 ? mysql_fetch_row(result) : NULL;
	retval = mysql_row != NULL && mysql_row[0] != NULL ? strdup(mysql_row[0]) : NULL;
	db_free_result(result);
	return retval;
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

	assert(psql    != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (int i = 0; i < nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			return strdup(opttable[i].val);
		}
	}

	spine_snprintf(qstring, sizeof(qstring), "SHOW GLOBAL VARIABLES LIKE '%s'", setting);

	result = db_query(psql, mode, qstring);
	if (result == NULL) return NULL;
	mysql_row = mysql_num_rows(result) > 0 ? mysql_fetch_row(result) : NULL;
	retval = mysql_row != NULL && mysql_row[1] != NULL ? strdup(mysql_row[1]) : NULL;
	db_free_result(result);
	return retval;
}

/*! \fn int is_debug_device(int device_id)
 *  \brief Determine if a device is a debug device
 *
 */
int is_debug_device(int device_id) {
	extern int *debug_devices;
	int i = 0;

	/* main() releases the list during shutdown; later logging must not read it. */
	if (debug_devices == NULL) return FALSE;

	while (i < MAX_DEBUG_DEVICES) {
		if (debug_devices[i] == '\0') break;
		if (debug_devices[i] == device_id) {
			return TRUE;
		}

		i++;
	}

	return FALSE;
}

void parse_debug_devices(char *device_list, int *devices, size_t capacity) {
	if (capacity == 0) return;
	devices[0] = 0;
	char *saveptr = NULL;
	const char *token = strtok_r(device_list, ",", &saveptr);
	for (size_t i = 0; token != NULL && i < capacity - 1; i++, token = strtok_r(NULL, ",", &saveptr)) {
		devices[i] = atoi(token);
		devices[i + 1] = 0;
	}
}

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
				set.logging.path_logfile[0] ='\0';
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
	set.php.php_required = FALSE;		/* assume no */

	/* log the requirement for the script server */
	if (!strlen(set.hosts.host_id_list)) {
		sqlp = sqlbuf;
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += append_hostrange(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), "host_id");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " AND poller_id=%i", set.poller.poller_id);
		spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " LIMIT 1");

		result = db_query(mysql, LOCAL, sqlbuf);
		num_rows = spine_count_to_int(mysql_num_rows(result));
		db_free_result(result);

		if (num_rows > 0) set.php.php_required = TRUE;

		SPINE_LOG_DEBUG(("DEBUG: StartDevice='%i', EndDevice='%i', TotalPHPScripts='%i'",
			set.hosts.start_host_id,
			set.hosts.end_host_id,
			num_rows));
	} else {
		sqlp = sqlbuf;
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), "SELECT SQL_NO_CACHE action FROM poller_item");
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " WHERE action=%d", POLLER_ACTION_PHP_SCRIPT_SERVER);
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " AND host_id IN(%s)", set.hosts.host_id_list);
		sqlp += spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " AND poller_id=%i", set.poller.poller_id);
		spine_snprintf(sqlp, sizeof(sqlbuf) - (size_t)(sqlp - sqlbuf), " LIMIT 1");

		result = db_query(mysql, LOCAL, sqlbuf);
		num_rows = spine_count_to_int(mysql_num_rows(result));
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

	db_connect(LOCAL, &mysql);

	/* one round trip instead of one per setting */
	settings_cache_load(&mysql, LOCAL);

	if (set.poller.poller_id > 1 && set.poller.mode == REMOTE_ONLINE) {
		db_connect(REMOTE, &mysqlr);
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

typedef struct {
	const char *table;
	const char *columns;
	const char *filter_column;
	const char *order_column;
	const char *const *updates;
	size_t update_count;
	size_t field_count;
	size_t row_limit;
} poller_transfer_t;

static void transfer_queries(const poller_transfer_t *plan, char *query, size_t query_capacity, char *prefix, size_t prefix_capacity, char *suffix, size_t suffix_capacity) {
	size_t used = (size_t)spine_snprintf(query, query_capacity, "SELECT SQL_NO_CACHE %s FROM %s WHERE poller_id = %d", plan->columns, plan->table, set.poller.poller_id);
	if (set.hosts.host_id_list[0] != '\0') used += (size_t)spine_snprintf(query + used, query_capacity - used, " AND %s IN (%s)", plan->filter_column, set.hosts.host_id_list);
	spine_snprintf(query + used, query_capacity - used, " ORDER BY %s", plan->order_column);
	spine_snprintf(prefix, prefix_capacity, "INSERT INTO %s (%s) VALUES ", plan->table, plan->columns);
	/* These rows go to the main server. The cached upsert capability describes the
	 * local server, so the row-alias form could reach a MariaDB main server
	 * that rejects it. VALUES() is accepted by both (#590). */
	used = (size_t)spine_snprintf(suffix, suffix_capacity, " ON DUPLICATE KEY UPDATE ");
	for (size_t index = 0; index < plan->update_count; index++) {
		const char *column = plan->updates[index];
		used += (size_t)spine_snprintf(suffix + used, suffix_capacity - used, "%s%s=VALUES(%s)", index == 0 ? "" : ", ", column, column);
	}
}

static size_t transfer_row(MYSQL *destination, MYSQL_ROW row, size_t field_count, char *output, size_t capacity) {
	/* The selected columns are at most 300 UTF-8 characters: allow 4 bytes per
	 * character and doubling for SQL escaping. Preserve SQL NULL explicitly. */
	char escaped[DBL_BUFSIZE * 2];
	size_t used = (size_t)spine_snprintf(output, capacity, "(");
	for (size_t index = 0; index < field_count; index++) {
		if (row[index] == NULL) {
			used += (size_t)spine_snprintf(output + used, capacity - used, "%sNULL", index == 0 ? "" : ", ");
		} else {
			db_escape(destination, escaped, sizeof(escaped), row[index]);
			used += (size_t)spine_snprintf(output + used, capacity - used, "%s'%s'", index == 0 ? "" : ", ", escaped);
		}
	}
	used += (size_t)spine_snprintf(output + used, capacity - used, ")");
	return used;
}

static bool transfer_batch(MYSQL *destination, char *buffer, size_t used, const char *suffix) {
	spine_snprintf(buffer + used, HUGE_BUFSIZE - used, "%s", suffix);
	return db_insert(destination, REMOTE, buffer);
}

static bool transfer_table(MYSQL *source, MYSQL *destination, const poller_transfer_t *plan) {
	char query[MEGA_BUFSIZE];
	char prefix[BUFSIZE];
	char suffix[BUFSIZE];
	transfer_queries(plan, query, sizeof(query), prefix, sizeof(prefix), suffix, sizeof(suffix));
	MYSQL_RES *result = db_query(source, LOCAL, query);
	if (result == NULL) return FALSE;
	if (mysql_num_fields(result) != plan->field_count) {
		db_free_result(result);
		return FALSE;
	}
	/* Size one row for every column at its escaped maximum plus separators;
	 * a fixed few kilobytes could not hold a host row with wide SNMP strings. */
	size_t row_capacity = plan->field_count * (DBL_BUFSIZE * 2 + 4) + 2;
	char *row_sql = malloc(row_capacity);
	char *buffer = malloc(HUGE_BUFSIZE);
	if (buffer == NULL || row_sql == NULL) {
		free(row_sql);
		free(buffer);
		db_free_result(result);
		return FALSE;
	}
	size_t used = 0;
	size_t rows = 0;
	size_t suffix_length = strlen(suffix);
	MYSQL_ROW row;
	bool success = TRUE;
	while ((row = mysql_fetch_row(result)) != NULL) {
		size_t length = transfer_row(destination, row, plan->field_count, row_sql, row_capacity);
		if (rows > 0 && (rows == plan->row_limit || length + suffix_length + 3 > HUGE_BUFSIZE - used)) {
			if (!transfer_batch(destination, buffer, used, suffix)) {
				success = FALSE;
				break;
			}
			rows = 0;
		}
		if (rows == 0) used = (size_t)spine_snprintf(buffer, HUGE_BUFSIZE, "%s", prefix);
		else used += (size_t)spine_snprintf(buffer + used, HUGE_BUFSIZE - used, ", ");
		used += (size_t)spine_snprintf(buffer + used, HUGE_BUFSIZE - used, "%s", row_sql);
		rows++;
	}
	if (mysql_errno(source) != 0) success = FALSE;
	if (success && rows > 0) success = transfer_batch(destination, buffer, used, suffix);
	free(row_sql);
	free(buffer);
	db_free_result(result);
	return success;
}

bool poller_transfer_status(MYSQL *source, MYSQL *destination) {
	static const char *const host_updates[] = {
		"snmp_sysDescr", "snmp_sysObjectID", "snmp_sysUpTimeInstance", "snmp_sysContact", "snmp_sysName", "snmp_sysLocation",
		"status", "status_event_count", "status_fail_date", "status_rec_date", "status_last_error", "min_time", "max_time",
		"cur_time", "avg_time", "polling_time", "total_polls", "failed_polls", "availability", "last_updated"
	};
	static const char *const item_updates[] = {"rrd_next_step"};
	static const poller_transfer_t host_plan = {
		"host", "id, snmp_sysDescr, snmp_sysObjectID, snmp_sysUpTimeInstance, snmp_sysContact, snmp_sysName, snmp_sysLocation, status, status_event_count, status_fail_date, status_rec_date, status_last_error, min_time, max_time, cur_time, avg_time, polling_time, total_polls, failed_polls, availability, last_updated",
		"id", "id", host_updates, sizeof(host_updates) / sizeof(host_updates[0]), 21, 500
	};
	static const poller_transfer_t item_plan = {
		"poller_item", "local_data_id, host_id, rrd_name, rrd_step, rrd_next_step",
		"host_id", "local_data_id, rrd_name", item_updates, sizeof(item_updates) / sizeof(item_updates[0]), 5, 10000
	};
	SPINE_LOG_MEDIUM(("Pushing Host Status to Main Server"));
	if (!transfer_table(source, destination, &host_plan)) return FALSE;
	SPINE_LOG_MEDIUM(("Pushing Poller Item RRD Next Step to Main Server"));
	return transfer_table(source, destination, &item_plan);
}

void poller_push_data_to_main(void) {
	MYSQL source;
	MYSQL destination;
	db_connect(LOCAL, &source);
	db_connect(REMOTE, &destination);
	/* Preserve the supported zero-date and GROUP BY session policies. */
	bool configured = db_insert(&source, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))") &&
		db_insert(&source, LOCAL, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))") &&
		db_insert(&destination, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'NO_ZERO_DATE', ''))") &&
		db_insert(&destination, REMOTE, "SET SESSION sql_mode = (SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY', ''))");
	if (!configured || !poller_transfer_status(&source, &destination)) {
		SPINE_LOG(("ERROR: Collector synchronization incomplete; earlier batches may have reached the main server. Local rows are retained for retry."));
		set.exit.exit_code = EXIT_FAILURE;
	}
	db_disconnect(&source);
	db_disconnect(&destination);
}

/*! \fn int read_spine_config(const char *file)
 *  \brief obtain default startup variables from the spine.conf file.
 *  \param file the spine config file
 *
 *  \return 0 if successful or -1 if the file could not be opened
 */
static int apply_config_directive(const char *name, const char *value) {
	/* Immutable metadata cannot be changed by configuration values written
	 * into set. Offsets and capacities describe the actual destination fields. */
	static const struct {
		const char *name;
		size_t offset;
		size_t capacity;
	} strings[] = {
		{"RDB_Host", offsetof(config_t, remote_database.host), sizeof(set.remote_database.host)},
		{"RDB_Database", offsetof(config_t, remote_database.database), sizeof(set.remote_database.database)},
		{"RDB_User", offsetof(config_t, remote_database.user), sizeof(set.remote_database.user)},
		{"RDB_Pass", offsetof(config_t, remote_database.password), sizeof(set.remote_database.password)},
		{"RDB_SSL_Key", offsetof(config_t, remote_database.ssl_key), sizeof(set.remote_database.ssl_key)},
		{"RDB_SSL_Cert", offsetof(config_t, remote_database.ssl_cert), sizeof(set.remote_database.ssl_cert)},
		{"RDB_SSL_CA", offsetof(config_t, remote_database.ssl_ca), sizeof(set.remote_database.ssl_ca)},
		{"DB_Host", offsetof(config_t, database.host), sizeof(set.database.host)},
		{"DB_Database", offsetof(config_t, database.database), sizeof(set.database.database)},
		{"DB_User", offsetof(config_t, database.user), sizeof(set.database.user)},
		{"DB_Pass", offsetof(config_t, database.password), sizeof(set.database.password)},
		{"DB_SSL_Key", offsetof(config_t, database.ssl_key), sizeof(set.database.ssl_key)},
		{"DB_SSL_Cert", offsetof(config_t, database.ssl_cert), sizeof(set.database.ssl_cert)},
		{"DB_SSL_CA", offsetof(config_t, database.ssl_ca), sizeof(set.database.ssl_ca)},
		{"SNMP_Clientaddr", offsetof(config_t, snmp.snmp_clientaddr), sizeof(set.snmp.snmp_clientaddr)},
	};
	for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); i++) {
		if (STRIMATCH(name, strings[i].name)) {
			strncopy((char *)&set + strings[i].offset, value, strings[i].capacity);
			return TRUE;
		}
	}
	if (STRIMATCH(name, "RDB_Port")) set.remote_database.port = atoi(value);
	else if (STRIMATCH(name, "RDB_UseSSL")) set.remote_database.ssl = atoi(value);
	else if (STRIMATCH(name, "DB_Port")) set.database.port = atoi(value);
	else if (STRIMATCH(name, "DB_UseSSL")) set.database.ssl = atoi(value);
	else if (STRIMATCH(name, "Poller")) set.poller.poller_id = atoi(value);
	else if (STRIMATCH(name, "DB_PreG")) {
		if (!set.console.stderr_notty) fprintf(stderr, "WARNING: DB_PreG is no longer supported\n");
	} else if (STRIMATCH(name, "Cacti_Log")) {
		STRNCOPY(set.logging.path_logfile, value);
		set.logging.logfile_processed = 1;
		set.logging.log_destination = LOGDEST_BOTH;
	} else {
		return FALSE;
	}
	return TRUE;
}

int read_spine_config(const char *file) {
	FILE *fp = fopen(file, "rb");
	char buff[BUFSIZE];
	char name[BUFSIZE];
	char value[BUFSIZE];
	char display_file[BUFSIZE];
	int line = 0;
	bool line_start = TRUE;
	strncopy(display_file, file, sizeof(display_file));
	spine_sanitize_log_message(display_file);

	if (fp == NULL) {
		if (set.logging.log_level == POLLER_VERBOSITY_DEBUG && !set.console.stderr_notty) {
			fprintf(stderr, "ERROR: Could not open config file [%s]\n", display_file);
		}
		return -1;
	}
	if (!set.console.stdout_notty) {
		fprintf(stdout, "SPINE: Using spine config file [%s]\n", display_file);
	}
	while (fgets(buff, sizeof(buff), fp) != NULL) {
		/* A line longer than buff arrives in several pieces; count it once. */
		if (line_start) line++;
		line_start = strchr(buff, '\n') != NULL;
		if (buff[0] == '#' || buff[0] == ' ' || buff[0] == '\n') continue;
		if (sscanf(buff, "%15s %255s", name, value) != 2) continue;
		/* -C accepts any path, so report where the line is, never what it holds. */
		if (!apply_config_directive(name, value) && !set.console.stderr_notty) {
			fprintf(stderr, "WARNING: Unrecognized directive on line %d of %s\n", line, display_file);
		}
	}
	int failed = ferror(fp);
	if (fclose(fp) != 0) failed = TRUE;
	return failed ? -1 : 0;
}

/*! \fn void config_defaults(void)
 *  \brief populates the global configuration structure with default spine.conf file settings
 *  \param *set global runtime parameters
 *
 */
void config_defaults() {
	set.poller.threads = DEFAULT_THREADS;

	/* default server */
	set.database.port  = DEFAULT_DB_PORT;

	STRNCOPY(set.database.host, DEFAULT_DB_HOST);
	STRNCOPY(set.database.database,   DEFAULT_DB_DB  );
	STRNCOPY(set.database.user, DEFAULT_DB_USER);
	STRNCOPY(set.database.password, DEFAULT_DB_PASS);

	/* remote default server */
	set.remote_database.port  = DEFAULT_DB_PORT;

	STRNCOPY(set.remote_database.host, DEFAULT_DB_HOST);
	STRNCOPY(set.remote_database.database,   DEFAULT_DB_DB  );
	STRNCOPY(set.remote_database.user, DEFAULT_DB_USER);
	STRNCOPY(set.remote_database.password, DEFAULT_DB_PASS);

	STRNCOPY(config_paths[0], CONFIG_PATH_1);
	STRNCOPY(config_paths[1], CONFIG_PATH_2);
	STRNCOPY(config_paths[2], CONFIG_PATH_3);
	STRNCOPY(config_paths[3], CONFIG_PATH_4);

	set.logging.log_destination = LOGDEST_FILE;
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
	vsnprintf(logmessage, sizeof(logmessage), format, args);
	va_end(args);

	if (set.logging.log_perror) {
		char perr[BUFSIZE];
		snprintf(perr, BUFSIZE, " [%d, %s]", old_errno, strerror(old_errno));
		size_t used = strlen(logmessage);
		snprintf(logmessage + used, sizeof(logmessage) - used, "%s", perr);
	}
	spine_sanitize_log_message(logmessage);

	if (set.logging.logfile_processed) {
		if (set.poller.parent_fork == SPINE_PARENT) {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine parent)", logmessage);
		} else {
			snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine thread)", logmessage);
		}
	} else {
		snprintf(flogmessage, DBL_BUFSIZE, "%s (Spine init)", logmessage);
	}

	fprintf(stderr, "%s\n", flogmessage);

	if ((set.poller.parent_fork == SPINE_PARENT) && (set.php.php_initialized)) {
		php_close(PHP_INIT);
	}

	exit(set.exit.exit_code == EXIT_SUCCESS ? EXIT_FAILURE : set.exit.exit_code);
}

/* The log timestamp format depends only on two settings read once in
 * read_config_options(), so it is built there, while spine is still single
 * threaded, and only read afterwards. Rebuilding it per log line cost a
 * malloc/free pair on every message. */
static char log_date_format[GD_FMT_SIZE] = "%Y/%b/%d %H:%M:%S - ";

/*! \fn void set_date_format(void)
 *  \brief build the cached log timestamp format from the current settings
 *
 *  Not safe to call after the poller threads have started.
 */
void set_date_format(void) {
	static const char separators[] = {'-', '/', '.'};
	static const char *const formats[][3] = {
		{"%m", "%d", "%Y"}, {"%b", "%d", "%Y"},
		{"%d", "%m", "%Y"}, {"%d", "%b", "%Y"},
		{"%Y", "%m", "%d"}, {"%Y", "%b", "%d"}
	};
	if (set.logging.log_datetime_separator < GDC_MIN || set.logging.log_datetime_separator > GDC_MAX) {
		set.logging.log_datetime_separator = GDC_DEFAULT;
	}
	if (set.logging.log_datetime_format < GD_MIN || set.logging.log_datetime_format > GD_MAX) {
		set.logging.log_datetime_format = GD_DEFAULT;
	}
	char separator = separators[set.logging.log_datetime_separator];
	const char *const *parts = formats[set.logging.log_datetime_format];
	spine_snprintf(log_date_format, sizeof(log_date_format), "%s%c%s%c%s %%H:%%M:%%S - ",
		parts[0], separator, parts[1], separator, parts[2]);
}

char *get_date_format(void) {
	return log_date_format;
}

/*! \fn void spine_log(const char *format, ...)
 *  \brief output's log information to the desired cacti logfile.
 *  \param *logmessage a pointer to the pre-formatted log message.
 *
 */
bool spine_should_log_device(int host_id, int verbosity) {
	return is_debug_device(host_id) || set.logging.log_level >= verbosity;
}

static FILE *log_error_stream(void) {
	#ifdef DISABLE_STDERR
	return stdout;
	#else
	return stderr;
	#endif
}

static bool log_stream_available(const FILE *stream) {
	return (stream == stdout && !set.console.stdout_notty) || (stream == stderr && !set.console.stderr_notty);
}

static void log_format_error(const char *message) {
	FILE *stream = log_error_stream();
	if (log_stream_available(stream)) fprintf(stream, "%s\n", message);
}

static bool log_format_message(char *output, const char *message) {
	char prefix[LOGSIZE];
	snprintf(prefix, sizeof(prefix), "SPINE: Poller[%i] PID[%i] PT[%lu] ", set.poller.poller_id, getpid(), (unsigned long int)pthread_self());
	time_t now = time(NULL);
	struct tm local;
	const char *date_format = get_date_format();
	size_t date_length = 0;
	if (localtime_r(&now, &local) != NULL) date_length = strftime(output, 50, date_format, &local);
	if (date_length == 0) {
		output[0] = '\0';
		log_format_error("ERROR: Could not get string from strftime()");
	}
	int prefix_length = spine_count_to_int(strlen(prefix));
	int message_length = spine_count_to_int(strlen(message));
	int available = LOGSIZE - spine_count_to_int(date_length) - 2;
	if (prefix_length > available) prefix_length = available;
	if (message_length > available - prefix_length) message_length = available - prefix_length;
	snprintf(output + date_length, LOGSIZE - date_length, "%.*s%.*s", prefix_length, prefix, message_length, message);
	return date_length != 0;
}

static void log_to_syslog(const char *message) {
	if (!IS_LOGGING_TO_SYSLOG()) return;
	openlog("Cacti", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
	if ((strstr(message, "ERROR") || strstr(message, "FATAL")) && set.logging.log_perror) syslog(LOG_CRIT, "%s\n", message);
	if (strstr(message, "WARNING") && set.logging.log_pwarn) syslog(LOG_WARNING, "%s\n", message);
	if (strstr(message, "STATS") && set.logging.log_pstats) syslog(LOG_NOTICE, "%s\n", message);
	closelog();
}

static bool log_to_file(const char *message) {
	if (!IS_LOGGING_TO_FILE() || set.logging.log_level == POLLER_VERBOSITY_NONE || !set.logging.path_logfile[0] || !set.logging.logfile_processed) return TRUE;
	/* Serialize complete records and the once-only diagnostic. Append mode
	 * creates missing files without a stat/open race that can truncate them. */
	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	static bool reported_error = FALSE;
	if (pthread_mutex_lock(&mutex) != 0) return FALSE;
	/* O_APPEND selects the end atomically and one write() keeps another
	 * process sharing the log from splicing into a record. Reopening per
	 * message preserves log rotation. */
	int oldstate;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
	int fd = open(set.logging.path_logfile, O_WRONLY | O_CREAT | O_APPEND, 0666);
	bool success = FALSE;
	if (fd >= 0) {
		size_t length = strlen(message);
		ssize_t written = write(fd, message, length);
		success = written >= 0 && (size_t) written == length;
		if (close(fd) != 0) success = FALSE;
	}
	pthread_setcancelstate(oldstate, NULL);
	if (!success && !reported_error) {
		printf("ERROR: Spine Log File Could Not Be Opened/Created or Written\n");
		reported_error = TRUE;
	}
	if (pthread_mutex_unlock(&mutex) != 0) return FALSE;
	return success;
}

int spine_log(const char *format, ...) {
	char message[LOGSIZE];
	va_list args;
	va_start(args, format);
	vsnprintf(message, LOGSIZE - 1, format, args);
	va_end(args);
	spine_sanitize_log_message(message);
	if (IS_LOGGING_TO_STDOUT()) {
		char console[LOGSIZE + 20];
		snprintf(console, sizeof(console), "Total[%3.4f] %s", get_time_as_double() - start_time, message);
		return puts(console) == EOF ? FALSE : TRUE;
	}
	char formatted[LOGSIZE];
	bool date_valid = log_format_message(formatted, message);
	log_to_syslog(formatted);
	if (strchr(formatted, '\n') == NULL) {
		size_t used = strlen(formatted);
		snprintf(formatted + used, sizeof(formatted) - used, "\n");
	}
	bool success = log_to_file(formatted);
	if (set.logging.log_level >= POLLER_VERBOSITY_NONE) {
		FILE *stream = stdout;
		if (!date_valid || strstr(formatted, "ERROR") || strstr(formatted, "WARNING") || strstr(formatted, "FATAL")) stream = log_error_stream();
		if (log_stream_available(stream) && fprintf(stream, "%s", formatted) < 0) success = FALSE;
	}
	return success;
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
	char *end_ptr_long;
	char *end_ptr_double;
	int conv_base=10;
	size_t length;

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
		} else if ((end_ptr_long == string) && (*end_ptr_long != '\0' &&
				*end_ptr_long != '.' &&
				*end_ptr_long != '-' &&
				*end_ptr_long != '+')) { /* ignore partial string matches but doubles can begin with '+', '-', '.' */
			return FALSE;
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
				if (!ignore_special) return FALSE;
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
	size_t end = strlen(string);
	while (end > 0 && !isdigit((unsigned char)string[end - 1])) string[--end] = '\0';
	size_t start = 0;
	while (start < end && !isdigit((unsigned char)string[start]) && string[start] != '-') start++;
	return string + start;
}

/*! \fn char *add_slashes(const char *string)
 *  \brief add escaping to back slashes on for Windows type commands.
 *  \param string the string to replace slashes
 *
 *  \return a pointer to the modified string. Variable must be freed by parent.
 *
 */
char *add_slashes(const char *string) {
	size_t length = strlen(string);
	if (length > (SIZE_MAX - 1) / 2) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Escaped command exceeds addressable memory");
	}
	char *result = malloc(length * 2 + 1);
	if (result == NULL) die("ERROR: Fatal malloc error: util.c add_slashes!");
	size_t used = 0;
	for (size_t i = 0; i < length; i++) {
		if (string[i] == '\\') result[used++] = '\\';
		result[used++] = string[i];
	}
	result[used] = '\0';
	return result;
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

	if (obuf == 0) return dst;
	/* Bound the scan by the usable capacity; src may be large or unterminated. */
	len = strnlen(src, obuf - 1);
	if (len) {
		memcpy(dst, src, len);
	}

	dst[len] = '\0';
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

	return (double)now.tv_sec + (double)now.tv_usec / 1000000;
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
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	end = str + strlen(str);

	while (end-- > str) {
		if (!strchr(trim_chars, *end)) return str;

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
	const char *trim_chars = " \"\'\\\t\n\r";

	if (!str) return NULL;

	while (*str) {
		if (!strchr(trim_chars, *str)) return str;

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
	size_t start = 0;
	size_t end = strlen(str);
	while (start < end) {
		end--;
		if (start >= end) break;
		char byte = str[start];
		str[start++] = str[end];
		str[end] = byte;
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
		return p - haystack <= INT_MAX ? (int)(p - haystack) : -1;
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
	const unsigned char my_chr = (unsigned char)chr;
	int count = 0;

	if (!my_chr) return 1;

	while (*my_str) {
		if (*my_str++ == my_chr) {
			count++;
		}
	}
	return count;
}

int hex2dec(const char *str, unsigned long long *result) {
	unsigned long long number = 0;
	unsigned int digit;
	int saw_digit = FALSE;

	if (str == NULL || result == NULL) return FALSE;

	while (*str) {
		switch (*str) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			digit = (unsigned int) (*str - '0');
			break;
		case 'a': case 'A':
		case 'b': case 'B':
		case 'c': case 'C':
		case 'd': case 'D':
		case 'e': case 'E':
		case 'f': case 'F':
			digit = (unsigned int) (tolower((unsigned char) *str) - 'a' + 10);
			break;
		/* separators. is_hexadecimal() accepts '-' and ':' as well as space,
		 * so anything it lets through has to be convertible here; skipping
		 * only space meant a dash-separated octet string validated and then
		 * converted to zero. */
		case '"': case ' ': case '\t': case '-': case ':':
			str++;
			continue;
		default:
			return FALSE;
		}

		/* A device can return an arbitrarily long string. Refuse overflow
		 * before multiplying rather than converting an out-of-range double. */
		if (number > (ULLONG_MAX - digit) / 16) {
			return FALSE;
		}

		number = (number * 16) + digit;
		saw_digit = TRUE;
		str++;
	}

	if (!saw_digit) return FALSE;

	*result = number;
	return TRUE;
}

#ifdef HAVE_LCAP
/* This patch is adapted (copied) patch for ntpd from Jarno Huuskonen and
 * Pekka Savola that was adapted (copied) from a patch by Chris Wings to drop
 * root for xntpd.
 */
/* Returns TRUE if CAP_NET_RAW was kept.  Exits if the ids cannot be changed. */
static int drop_root(uid_t server_uid, gid_t server_gid) {
	cap_t caps;
	int   kept;

	/* Runs before logging is configured, so failures go to stderr via die(). */
	if (prctl(PR_SET_KEEPCAPS, 1)) {
		die("ERROR: prctl(PR_SET_KEEPCAPS, 1) failed; refusing to run");
	}

	if (setgroups(0, NULL) == -1) {
		die("ERROR: setgroups failed; refusing to run");
	}

	if (setegid(server_gid) == -1 || seteuid(server_uid) == -1) {
		die("ERROR: setegid/seteuid to uid=%d/gid=%d failed; refusing to run", server_uid, server_gid);
	}

	caps = cap_from_text("cap_net_raw=eip");
	kept = caps != NULL && cap_set_proc(caps) == 0;

	if (caps != NULL) {
		cap_free(caps);
	}

	/* Without the narrowed set, PR_SET_KEEPCAPS would carry every one of
	 * root's permitted capabilities across the uid change below.  Clearing
	 * it lets the kernel empty the set, and spine continues without ICMP
	 * unless datagram ICMP is allowed. */
	if (!kept && prctl(PR_SET_KEEPCAPS, 0)) {
		die("ERROR: prctl(PR_SET_KEEPCAPS, 0) failed; refusing to run");
	}

	if ( setregid(server_gid, server_gid) == -1 ||
		setreuid(server_uid, server_uid) == -1 ) {
		die("ERROR: setregid/setreuid to uid=%d/gid=%d failed; refusing to run",
			server_uid, server_gid);
	}

	SPINE_LOG_LOW(("running as uid(%d)/gid(%d) euid(%d)/egid(%d)%s.",
		getuid(), getgid(), geteuid(), getegid(), kept ? " with cap_net_raw=eip" : ""));

	return kept;
}
#endif /* HAVE_LCAP */

/* Set when a setuid root start could not get raw ICMP before dropping root,
 * so checkAsRoot() can say so once logging is configured. */
static int setuid_icmp_lost = FALSE;

/*! \fn int privileges_dropped(uid_t uid, gid_t gid)
 *  \brief confirms root is gone for good rather than set aside
 *
 *  seteuid(0) succeeds while the real or saved uid is still 0, and setegid(0)
 *  while a group id is, so a failed attempt is the proof.
 *
 *  \return TRUE if every id is the invoking user's and root cannot come back
 */
int privileges_dropped(uid_t uid, gid_t gid) {
	#ifdef HAVE_LCAP
	cap_t caps;
	cap_flag_value_t flag;
	cap_value_t value;
	int only_net_raw = TRUE;
	#endif

	if (uid == 0 || getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
		return FALSE;
	}

	#ifdef HAVE_LCAP
	/* A permitted capability could be raised again without any uid change,
	 * so anything beyond CAP_NET_RAW means root was not given up. */
	caps = cap_get_proc();
	if (caps == NULL) {
		return FALSE;
	}

	for (value = 0; value < 64; value++) {
		if (cap_get_flag(caps, value, CAP_PERMITTED, &flag) == 0 && flag == CAP_SET && value != CAP_NET_RAW) {
			only_net_raw = FALSE;
		}
	}

	cap_free(caps);

	if (!only_net_raw) {
		return FALSE;
	}
	#endif

	if (seteuid(0) == 0) {
		return FALSE;
	}

	if (gid != 0 && setegid(0) == 0) {
		return FALSE;
	}

	return TRUE;
}

/*! \fn void drop_privileges(void)
 *  \brief gives up setuid root before spine reads any input
 *
 *  Spine is installed setuid root only to open raw ICMP sockets.  Options and
 *  the config file can name files that spine then creates or writes, so all
 *  input is handled as the invoking user.  This runs first in main(), opens
 *  what ICMP needs while still root, then drops root permanently.  A real root user
 *  (uid 0, for example from cron) keeps running as root, as before; with
 *  libcap it is narrowed to CAP_NET_RAW, also as before.
 *
 *  Never returns while spine is setuid root: it drops or exits.
 */
void drop_privileges(void) {
	uid_t uid = getuid();
	gid_t gid = getgid();
	int   icmp_ready;

	if (geteuid() != 0 || uid == 0) {
		#ifdef HAVE_LCAP
		/* --enable-lcap confines a root run to CAP_NET_RAW.  Running on with
		 * all of root's capabilities would silently undo that, so refuse. */
		if (geteuid() == 0 && !drop_root(uid, gid)) {
			die("ERROR: Spine runs as root but could not confine itself to CAP_NET_RAW; refusing to run");
		}
		#endif
		return;
	}

	#ifdef HAVE_LCAP
	icmp_ready = drop_root(uid, gid);
	#else
	icmp_ready = ping_icmp_open_shared();

	/* With an effective uid of 0, POSIX setgid() and setuid() replace the
	 * real, effective and saved ids; seteuid() would keep root in reserve.
	 * Unlike drop_root(), this keeps the supplementary groups: a setuid exec
	 * does not change them, so they are the caller's own. */
	if (setgid(gid) != 0 || setuid(uid) != 0) {
		die("ERROR: Spine is setuid root and could not drop to uid %d/gid %d; refusing to run", (int) uid, (int) gid);
	}
	#endif

	/* The one case that stops spine: running on with root still reachable. */
	if (!privileges_dropped(uid, gid)) {
		die("ERROR: Spine is setuid root and could not drop root permanently; refusing to run");
	}

	/* Missing ICMP is not a reason to stop polling: checkAsRoot() tries
	 * datagram ICMP and otherwise warns, and ICMP pings fall back to UDP. */
	setuid_icmp_lost = !icmp_ready;
}

int hasCaps(void) {
	#ifdef HAVE_LCAP
	cap_t caps;
	cap_flag_value_t capflag;

	/* Recommended caps: cap_net_raw=eip */
	caps = cap_get_proc();
	if (caps == NULL) {
		SPINE_LOG(("ERROR: cap_get_proc failed."));
		return FALSE;
	}

	/* check if cap_net_raw is in effective set */
	if (cap_get_flag(caps, CAP_NET_RAW, CAP_EFFECTIVE, &capflag)) {
		SPINE_LOG(("ERROR: cap_get_flag for CAP_NET_RAW failed. Falling back to unprivileged ICMP where available."));
		cap_free(caps);
		return FALSE;
	}

	if (capflag != CAP_SET) {
		SPINE_LOG_MEDIUM(("WARNING: Capability CAP_NET_RAW is not set. Falling back to unprivileged ICMP where available."));
		cap_free(caps);
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
	set.availability.icmp_uses_caps = FALSE;
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

	set.availability.icmp_avail = pe || ping_icmp_shared_available();

	/* Free the privset */
	priv_freeset(privset);
	free(p);
	#else
	/* Never regains root here: a setuid install gave it up in drop_privileges(). */
	if (hasCaps() != TRUE) {
		SPINE_LOG_DEBUG(("DEBUG: Spine running as %d UID, %d EUID", getuid(), geteuid()));

		if (ping_icmp_shared_available()) {
			SPINE_LOG_DEBUG(("DEBUG: Spine uses the raw ICMP sockets it opened before dropping root."));
			set.availability.icmp_avail = TRUE;
		} else if (geteuid() != 0) {
			int probe;

			/* A file capability (setcap cap_net_raw+ep) works without libcap
			 * support too, so ask the kernel rather than hasCaps().  Root is
			 * not the only way in either: net.ipv4.ping_group_range lists the
			 * groups allowed to open datagram ICMP sockets. */
			probe = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

			if (probe != -1) {
				close(probe);
				SPINE_LOG_DEBUG(("DEBUG: Spine may open raw ICMP sockets."));
				set.availability.icmp_avail = TRUE;
			} else if ((probe = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)) != -1) {
				close(probe);
				SPINE_LOG_DEBUG(("DEBUG: Spine may use unprivileged ICMP sockets."));
				set.availability.icmp_avail = TRUE;
			} else if (setuid_icmp_lost) {
				SPINE_LOG(("WARNING: Spine is setuid root but could not get raw ICMP access before dropping root, and net.ipv4.ping_group_range does not cover this user.  ICMP pings fall back to UDP; SNMP polling continues."));
				set.availability.icmp_avail = FALSE;
			} else {
				SPINE_LOG_DEBUG(("WARNING: Spine has no ICMP access.  Install it setuid root (chown root:root spine; chmod u+s spine), grant it CAP_NET_RAW (setcap cap_net_raw+ep spine), or widen net.ipv4.ping_group_range to cover this user."));
				set.availability.icmp_avail = FALSE;
			}
		} else {
			SPINE_LOG_DEBUG(("DEBUG: Spine is running as root."));
			set.availability.icmp_avail = TRUE;
		}
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Spine has cap_net_raw capability."));
		set.availability.icmp_avail = TRUE;
		set.availability.icmp_uses_caps = TRUE;
	}
	SPINE_LOG_DEBUG(("DEBUG: Spine has %sgot ICMP", set.availability.icmp_avail?"":"not "));
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
static int parse_cacti_version(const char *value) {
	const unsigned long weights[] = {1000, 100, 1};
	unsigned long version = 0;
	for (size_t index = 0; index < sizeof(weights) / sizeof(weights[0]); index++) {
		if (*value < '0' || *value > '9') return 0;
		errno = 0;
		char *end;
		unsigned long component = strtoul(value, &end, 10);
		if (errno == ERANGE || component > ((unsigned long)INT_MAX - version) / weights[index]) return 0;
		version += component * weights[index];
		if (index < 2 && *end != '.') return 0;
		value = end + (index < 2 ? 1 : 0);
	}
	/* Preserve suffixes such as develop/beta accepted by the previous three-component scan. */
	return (int)version;
}

int get_cacti_version(MYSQL *psql, int mode) {
	assert(psql != NULL);
	MYSQL_RES *result = db_query(psql, mode, "SELECT cacti FROM version LIMIT 1");
	if (result == NULL) return 0;
	MYSQL_ROW row = mysql_fetch_row(result);
	int version = row != NULL && row[0] != NULL ? parse_cacti_version(row[0]) : 0;
	db_free_result(result);
	return version;
}

/* pthread storage keeps the borrowed match valid without requiring C11 TLS.
 * Each polling thread owns its buffer, which is freed when the thread exits. */
static pthread_key_t regex_result_key;
static pthread_once_t regex_result_once = PTHREAD_ONCE_INIT;

static void initialize_regex_result_key(void) {
	if (pthread_key_create(&regex_result_key, free) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to create thread-local regex storage");
	}
}

static char *regex_result_buffer(void) {
	if (pthread_once(&regex_result_once, initialize_regex_result_key) != 0) {
		set.exit.exit_code = EXIT_FAILURE;
		die("ERROR: Unable to initialize thread-local regex storage");
	}
	char *buffer = pthread_getspecific(regex_result_key);
	if (buffer == NULL) {
		buffer = malloc(RESULTS_BUFFER);
		if (buffer == NULL) die("ERROR: Fatal malloc error: regex result buffer!");
		if (pthread_setspecific(regex_result_key, buffer) != 0) {
			free(buffer);
			set.exit.exit_code = EXIT_FAILURE;
			die("ERROR: Unable to retain thread-local regex storage");
		}
	}
	return buffer;
}

char *regex_replace(const char *exp, char *value) {
	regex_t regex;
	int reti;
	char *msgbuf = NULL;

	/* Stored output_regex values use the historical basic-regex dialect. */
	reti = regcomp(&regex, exp, 0);
	if (reti) {
		return value;
	}

	/* Execute regular expression */
	regmatch_t matches[MAX_MATCHES];
	reti = regexec(&regex, value, MAX_MATCHES, matches, 0);
	if (!reti) {
		// regex matched
		size_t length = (size_t) (matches[0].rm_eo - matches[0].rm_so);
		if (length >= RESULTS_BUFFER) {
			regfree(&regex);
			return value;
		}
		msgbuf = regex_result_buffer();
		memcpy(msgbuf, value + matches[0].rm_so, length);
		msgbuf[length] = '\0';
	}

	/* Free memory allocated to the pattern buffer by regcomp() */
	regfree(&regex);

	return reti ? value : msgbuf;
}

int format_spine_capabilities(char *output, size_t output_size,
		const char *auth_protocols, const char *priv_protocols) {
	int written;

	if (output == NULL || output_size == 0 ||
	    auth_protocols == NULL || priv_protocols == NULL) {
		return FALSE;
	}

	written = snprintf(output, output_size,
		"{ authProtocols: \"%." SPINE_STRINGIFY(CAPABILITY_PROTOCOL_LIST_MAX)
		"s\", privProtocols: \"%." SPINE_STRINGIFY(CAPABILITY_PROTOCOL_LIST_MAX) "s\" }",
		auth_protocols, priv_protocols);

	return written >= 0 && (size_t)written < output_size;
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
