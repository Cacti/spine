#include "common.h"
#include "spine.h"
#include "config_repository.h"

static char *repository_fetch_single_value(MYSQL *mysql, int mode, const char *query, int value_col) {
	MYSQL_RES *result;
	MYSQL_ROW row;
	char *value = NULL;

	result = db_query(mysql, mode, query);
	if (result == NULL) {
		return NULL;
	}

	if (mysql_num_rows(result) > 0) {
		row = mysql_fetch_row(result);
		if (row != NULL && row[value_col] != NULL) {
			value = strdup(row[value_col]);
		}
	}

	db_free_result(result);
	return value;
}

static char *repository_getglobalvariable(MYSQL *mysql, int mode, const char *setting) {
	char query[SMALL_BUFSIZE];
	snprintf(query, sizeof(query), "SHOW GLOBAL VARIABLES LIKE '%s'", setting);
	return repository_fetch_single_value(mysql, mode, query, 1);
}

static char *repository_getsetting(MYSQL *mysql, int mode, const char *setting) {
	char query[BUFSIZE];
	snprintf(query, sizeof(query), "SELECT value FROM settings WHERE name='%s'", setting);
	return repository_fetch_single_value(mysql, mode, query, 0);
}

void config_repository_fetch(MYSQL *mysql, ConfigRepositoryData *raw) {
	char *res;

	memset(raw, 0, sizeof(*raw));

	/* repository phase fetches raw values from DB without mutating globals */
	if ((res = repository_getglobalvariable(mysql, LOCAL, "version")) != 0) {
		snprintf(raw->dbversion, sizeof(raw->dbversion), "%s", res);
		free(res);
	}

	raw->cacti_version = get_cacti_version(mysql, LOCAL);

	if ((res = repository_getsetting(mysql, LOCAL, "path_webroot")) != 0) {
		snprintf(raw->path_webroot, sizeof(raw->path_webroot), "%s", res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "path_cactilog")) != 0) {
		snprintf(raw->path_cactilog, sizeof(raw->path_cactilog), "%s", res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "path_php_binary")) != 0) {
		snprintf(raw->path_php_binary, sizeof(raw->path_php_binary), "%s", res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "log_verbosity")) != 0) {
		raw->log_verbosity = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "log_destination")) != 0) {
		raw->log_destination = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "default_datechar")) != 0) {
		raw->default_datechar = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "availability_method")) != 0) {
		raw->availability_method = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "ping_recovery_count")) != 0) {
		raw->ping_recovery_count = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "ping_failure_count")) != 0) {
		raw->ping_failure_count = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "ping_method")) != 0) {
		raw->ping_method = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "ping_retries")) != 0) {
		raw->ping_retries = atoi(res);
		free(res);
	}

	if ((res = repository_getsetting(mysql, LOCAL, "ping_timeout")) != 0) {
		raw->ping_timeout = atoi(res);
		free(res);
	}
}
