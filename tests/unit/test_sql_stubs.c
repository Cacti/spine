/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Stubs for test_dry_run, which links the real src/sql.c. We only need
 | to satisfy the symbols sql.c references besides its own definitions:
 | the pool globals, thread_mutex_lock/unlock, and `set` (already
 | defined in the test TU itself). Keeping this separate from
 | test_spine_stubs.c avoids a duplicate-db_insert link error.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

config_t set;

pool_t *db_pool_local  = NULL;
pool_t *db_pool_remote = NULL;

void thread_mutex_lock(int mutex)   { (void) mutex; }
void thread_mutex_unlock(int mutex) { (void) mutex; }
