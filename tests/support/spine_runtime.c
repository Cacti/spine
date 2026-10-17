/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* Spine runtime for the fuzz targets.
 *
 * Production helper objects are linked as built. This supplies process-wide
 * globals in place of app/runtime.c for unit tests and fuzz targets; the
 * production-linked regression/fault binaries use the real runtime objects.
 */
#include "internal/common.h"
#include "app/spine.h"
#include "script/server.h"

spine_permits_t available_threads;
spine_permits_t available_scripts;
double start_time;
double total_time;
config_t set;
char config_paths[CONFIG_PATHS][BUFSIZE];
int *debug_devices;
pool_t *db_pool_local;
pool_t *db_pool_remote;
php_t *php_processes;
poller_thread_t **details;
