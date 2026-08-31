/* Spine runtime for the fuzz targets.
 *
 * Every translation unit except spine.c is linked as built, so the code under
 * test is the code that ships.  This file supplies only the globals that
 * spine.c would define, plus php_close, which lives beside main().
 */
#include "common.h"
#include "spine.h"
#include "php.h"

spine_sem_t available_threads;
spine_sem_t available_scripts;
double      start_time;
double      total_time;
config_t    set;
char        config_paths[CONFIG_PATHS][BUFSIZE];
int        *debug_devices;
pool_t     *db_pool_local;
pool_t     *db_pool_remote;
php_t      *php_processes;
poller_thread_t *details;
