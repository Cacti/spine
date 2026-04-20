#ifndef SPINE_CONFIG_REPOSITORY_H
#define SPINE_CONFIG_REPOSITORY_H

#include "common.h"
#include "spine.h"

typedef struct ConfigRepositoryData {
	int mode;
	char dbversion[BUFSIZE];
	int cacti_version;
	char path_webroot[BUFSIZE];
	char path_cactilog[DBL_BUFSIZE];
	char path_php_binary[BUFSIZE];
	int log_verbosity;
	int log_destination;
	int default_datechar;
	int availability_method;
	int ping_recovery_count;
	int ping_failure_count;
	int ping_method;
	int ping_retries;
	int ping_timeout;
} ConfigRepositoryData;

void config_repository_fetch(MYSQL *mysql, ConfigRepositoryData *raw);

#endif
