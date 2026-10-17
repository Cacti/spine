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
#include "settings_internal.h"
#include <limits.h>

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
	if (option == NULL || value == NULL || nopts >= (int) (sizeof(opttable) / sizeof(opttable[0]))) {
		die("ERROR: Invalid or excessive command-line setting overrides");
	}
	opttable[nopts].opt = option;
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

static setting_cache_t *settings_cache = NULL;
static int settings_cache_count = 0;

/* Settings are read in the main thread before polling starts, so a database
 * error here is a configuration failure and ends the process, as it did when
 * db_query() exited on its own. An empty or missing result is not an error. */
MYSQL_RES *config_query(MYSQL *psql, int mode, const char *query) {
	MYSQL_RES *result = db_query(psql, mode, query);

	if (result == NULL && mysql_errno(psql) != 0) {
		die("FATAL: Unable to read the Cacti configuration from the database");
	}

	return result;
}

void settings_cache_free(void) {
	int i;

	if (settings_cache == NULL) return;

	for (i = 0; i < settings_cache_count; i++) {
		free(settings_cache[i].name);
		free(settings_cache[i].value);
	}

	free(settings_cache);
	settings_cache = NULL;
	settings_cache_count = 0;
}

void settings_cache_load(MYSQL *psql, int mode) {
	MYSQL_RES *result;
	MYSQL_ROW row;
	my_ulonglong rows;
	setting_cache_t *table;
	int i = 0;

	assert(psql != 0);

	settings_cache_free();

	result = config_query(psql, mode, "SELECT SQL_NO_CACHE name, value FROM settings");

	if (result == NULL) return;

	rows = mysql_num_rows(result);

	if (rows == 0 || rows > (my_ulonglong) INT_MAX) {
		db_free_result(result);
		return;
	}

	table = calloc((size_t) rows, sizeof(*table));

	if (table == NULL) {
		db_free_result(result);
		return;
	}

	while ((row = mysql_fetch_row(result)) != NULL && i < (int) rows) {
		if (row[0] == NULL) continue;

		table[i].name = strdup(row[0]);
		table[i].value = strdup(row[1] != NULL ? row[1] : "");

		if (table[i].name == NULL || table[i].value == NULL) {
			free(table[i].name);
			free(table[i].value);
			break;
		}

		i++;
	}

	db_free_result(result);

	settings_cache = table;
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
char *getsetting(MYSQL *psql, int mode, const char *setting) {
	char qstring[BUFSIZE];
	char *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;

	assert(psql != 0);
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

	result = config_query(psql, mode, qstring);
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
	char qstring[BUFSIZE];
	int result = 0;

	assert(psql != 0);
	assert(mysetting != 0);
	assert(myvalue != 0);

	if (set.database.onupdate == 0) {
		spine_snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
												 "VALUES ('%s', '%s') "
												 "ON DUPLICATE KEY UPDATE value = VALUES(value)",
			mysetting, myvalue);
	} else {
		spine_snprintf(qstring, sizeof(qstring), "INSERT INTO settings (name, value) "
												 "VALUES ('%s', '%s') AS rs "
												 "ON DUPLICATE KEY UPDATE value = rs.value",
			mysetting, myvalue);
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
char *getpsetting(MYSQL *psql, int mode, const char *setting) {
	char qstring[BUFSIZE];
	char *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;

	assert(psql != 0);
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

	result = config_query(psql, mode, qstring);
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
int getboolsetting(MYSQL *psql, int mode, const char *setting, int dflt) {
	char *rc;

	assert(psql != 0);
	assert(setting != 0);

	rc = getsetting(psql, mode, setting);

	if (rc == 0) return dflt;

	if (STRIMATCH(rc, "on") ||
		STRIMATCH(rc, "yes") ||
		STRIMATCH(rc, "true") ||
		STRIMATCH(rc, "1")) {
		free(rc);
		return TRUE;
	}

	if (STRIMATCH(rc, "off") ||
		STRIMATCH(rc, "no") ||
		STRIMATCH(rc, "false") ||
		STRIMATCH(rc, "0")) {
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
char *getglobalvariable(MYSQL *psql, int mode, const char *setting) {
	char qstring[BUFSIZE];
	char *retval;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;

	assert(psql != 0);
	assert(setting != 0);

	/* see if it's in the option table */
	for (int i = 0; i < nopts; i++) {
		if (STRIMATCH(setting, opttable[i].opt)) {
			/* FOUND IT! */
			return strdup(opttable[i].val);
		}
	}

	spine_snprintf(qstring, sizeof(qstring), "SHOW GLOBAL VARIABLES LIKE '%s'", setting);

	result = config_query(psql, mode, qstring);
	if (result == NULL) return NULL;
	mysql_row = mysql_num_rows(result) > 0 ? mysql_fetch_row(result) : NULL;
	retval = mysql_row != NULL && mysql_row[1] != NULL ? strdup(mysql_row[1]) : NULL;
	db_free_result(result);
	return retval;
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
		if (errno == ERANGE || component > ((unsigned long) INT_MAX - version) / weights[index]) return 0;
		version += component * weights[index];
		if (index < 2 && *end != '.') return 0;
		value = end + (index < 2 ? 1 : 0);
	}
	/* Preserve suffixes such as develop/beta accepted by the previous three-component scan. */
	return (int) version;
}

int get_cacti_version(MYSQL *psql, int mode) {
	assert(psql != NULL);
	MYSQL_RES *result = config_query(psql, mode, "SELECT cacti FROM version LIMIT 1");
	if (result == NULL) return 0;
	MYSQL_ROW row = mysql_fetch_row(result);
	int version = row != NULL && row[0] != NULL ? parse_cacti_version(row[0]) : 0;
	db_free_result(result);
	return version;
}
