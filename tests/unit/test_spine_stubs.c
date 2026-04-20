/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Minimal stubs for dump_config / check_mode unit tests that link
 | src/util.c directly. The real definitions live in sql.c, php.c,
 | keywords.c, locks.c, and spine.c. Linking them pulls in the full
 | poller runtime. Every stub here is a deliberate no-op; behavioural
 | testing belongs in an integration suite, not ctest.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Global storage normally provided by spine.c. */
double start_time         = 0.0;
double total_time         = 0.0;
char   start_datetime[20] = {0};
char   config_paths[CONFIG_PATHS][BUFSIZE] = {{0}};
int    entries            = 0;
int    num_hosts          = 0;

config_t set;

int    *debug_devices  = NULL;
php_t  *php_processes  = NULL;
pool_t *db_pool_local  = NULL;
pool_t *db_pool_remote = NULL;

/* locks.c stubs. */
void thread_mutex_lock(int mutex)   { (void) mutex; }
void thread_mutex_unlock(int mutex) { (void) mutex; }

/* php.c stub reached only from die(). */
void php_close(int php_process)     { (void) php_process; }

/* keywords.c stubs. Not reached from dump_config or health_check. */
int parse_logdest(const char *word, int dflt) { (void) word; return dflt; }
const char *printable_logdest(int token) {
	(void) token;
	return "none";
}

/* sql.c stubs. dump_config + health_check do not hit the DB pool.
 * health_check's success path calls mysql_real_connect directly, which
 * does not route through any of these. */
void db_connect(int type, MYSQL *mysql)    { (void) type; (void) mysql; }
void db_disconnect(MYSQL *mysql)           { (void) mysql; }
void db_escape(MYSQL *mysql, char *out, int max_size, const char *in) {
	(void) mysql;
	if (out == NULL || max_size <= 0) return;
	if (in == NULL) { out[0] = '\0'; return; }
	snprintf(out, (size_t) max_size, "%s", in);
}
void db_free_result(MYSQL_RES *res) { (void) res; }

MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql; (void) type; (void) query;
	return NULL;
}

int db_insert(MYSQL *mysql, int type, const char *query) {
	(void) mysql; (void) type; (void) query;
	return TRUE;
}

int append_hostrange(char *obuf, const char *colname) {
	(void) obuf; (void) colname;
	return 0;
}

__attribute__((weak)) int spine_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    printf("\n");
    va_end(args);
    return 0;
}

char **spine_build_child_env(void) {
    return NULL;
}
