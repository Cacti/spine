/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include <pthread.h>
#include "common.h"
#include "cactid.h"
#include "locks.h"

static pthread_mutex_t snmp_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t threads_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t mysql_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rrdtool_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pipe_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t* get_lock(int lock) {
	pthread_mutex_t *ret_val;

	switch (lock) {
	case LOCK_SNMP:
		ret_val = &snmp_lock;
		break;
	case LOCK_THREAD:
                ret_val = &threads_lock;
                break;
	case LOCK_MYSQL:
                ret_val = &mysql_lock;
                break;
	case LOCK_RRDTOOL:
                ret_val = &rrdtool_lock;
                break;
	case LOCK_PIPE:
                ret_val = &pipe_lock;
                break;
	}
	
	return ret_val;
}

void thread_mutex_lock(int mutex) {
	pthread_mutex_lock(get_lock(mutex));
}

void thread_mutex_unlock(int mutex) {
	pthread_mutex_unlock(get_lock(mutex));
}

int thread_mutex_trylock(int mutex) {
	return pthread_mutex_trylock(get_lock(mutex));
}


