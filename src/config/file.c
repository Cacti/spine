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
#define SPINE_STRINGIFY_INNER(value) #value
#define SPINE_STRINGIFY(value) SPINE_STRINGIFY_INNER(value)

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
			strncopy((char *) &set + strings[i].offset, value, strings[i].capacity);
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

/* fgets() returns a line longer than its buffer in pieces, and each piece
 * would be parsed as a directive of its own.  Report whether the line just
 * read was whole, consuming the remainder when it was not.  The caller sets
 * the last byte nonzero before reading: fgets() only clears it when it filled
 * the buffer, which a string search cannot tell once the line holds a NUL. */
static bool config_line_complete(FILE *fp, const char *line, size_t capacity) {
	if (line[capacity - 1] != '\0' || line[capacity - 2] == '\n') return TRUE;
	int next = getc(fp);
	if (next == EOF || next == '\n') return TRUE;
	while (next != EOF && next != '\n') next = getc(fp);
	return FALSE;
}

int read_spine_config(const char *file) {
	FILE *fp = fopen(file, "rb");
	char buff[BUFSIZE];
	char name[BUFSIZE];
	char value[BUFSIZE];
	char display_file[BUFSIZE];
	int line = 0;
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
	for (;;) {
		buff[sizeof(buff) - 1] = 1;
		if (fgets(buff, sizeof(buff), fp) == NULL) break;
		/* config_line_complete() consumes an overlong line whole, so each
		 * pass is exactly one line */
		line++;
		if (!config_line_complete(fp, buff, sizeof(buff))) {
			if (!set.console.stderr_notty) {
				fprintf(stderr, "WARNING: Ignoring line %d of %s, longer than %d characters\n", line, display_file, BUFSIZE - 2);
			}
			continue;
		}
		if (buff[0] == '#' || buff[0] == ' ' || buff[0] == '\n') continue;
		/* Field widths match the line buffer, so no token is ever cut; the old
		 * %15s handed the tail of a long key over as its value. */
		int fields = sscanf(buff, "%1023s %1023s", name, value);
		if (fields < 1) continue;
		/* -C accepts any path, so report where the line is, never what it holds.
		 * A lone token is a key without a value, or a line that is no
		 * directive at all; the old %15s split such a line in two. */
		if (fields == 1) {
			if (!set.console.stderr_notty) {
				fprintf(stderr, "WARNING: Directive without a value on line %d of %s\n", line, display_file);
			}
		} else if (!apply_config_directive(name, value) && !set.console.stderr_notty) {
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
	set.database.port = DEFAULT_DB_PORT;

	STRNCOPY(set.database.host, DEFAULT_DB_HOST);
	STRNCOPY(set.database.database, DEFAULT_DB_DB);
	STRNCOPY(set.database.user, DEFAULT_DB_USER);
	STRNCOPY(set.database.password, DEFAULT_DB_PASS);

	/* remote default server */
	set.remote_database.port = DEFAULT_DB_PORT;

	STRNCOPY(set.remote_database.host, DEFAULT_DB_HOST);
	STRNCOPY(set.remote_database.database, DEFAULT_DB_DB);
	STRNCOPY(set.remote_database.user, DEFAULT_DB_USER);
	STRNCOPY(set.remote_database.password, DEFAULT_DB_PASS);

	STRNCOPY(config_paths[0], CONFIG_PATH_1);
	STRNCOPY(config_paths[1], CONFIG_PATH_2);
	STRNCOPY(config_paths[2], CONFIG_PATH_3);
	STRNCOPY(config_paths[3], CONFIG_PATH_4);

	set.logging.log_destination = LOGDEST_FILE;
}
