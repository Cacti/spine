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

pthread_mutex_t snmp_lock;
pthread_mutex_t threads_lock;
pthread_mutex_t mysql_lock;
pthread_mutex_t rrdtool_lock;
pthread_mutex_t pipe_lock;
pthread_mutex_t syslog_lock;

pthread_once_t snmp_lock_o = PTHREAD_ONCE_INIT;
pthread_once_t threads_lock_o = PTHREAD_ONCE_INIT;
pthread_once_t mysql_lock_o = PTHREAD_ONCE_INIT;
pthread_once_t rrdtool_lock_o = PTHREAD_ONCE_INIT;
pthread_once_t pipe_lock_o = PTHREAD_ONCE_INIT;
pthread_once_t syslog_lock_o = PTHREAD_ONCE_INIT;

static void init_snmp_lock(void) {
    pthread_mutex_init(&snmp_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

static void init_thread_lock(void) {
    pthread_mutex_init(&threads_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

static void init_mysql_lock(void) {
    pthread_mutex_init(&mysql_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

static void init_rrdtool_lock(void) {
    pthread_mutex_init(&rrdtool_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

static void init_pipe_lock(void) {
    pthread_mutex_init(&pipe_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

static void init_syslog_lock(void) {
    pthread_mutex_init(&syslog_lock, PTHREAD_MUTEXATTR_DEFAULT);
}

void init_mutexes() {
    pthread_once((pthread_once_t*) get_attr(LOCK_SNMP_O), init_snmp_lock);
    pthread_once((pthread_once_t*) get_attr(LOCK_THREAD_O), init_thread_lock);
    pthread_once((pthread_once_t*) get_attr(LOCK_MYSQL_O), init_mysql_lock);
    pthread_once((pthread_once_t*) get_attr(LOCK_RRDTOOL_O), init_rrdtool_lock);
    pthread_once((pthread_once_t*) get_attr(LOCK_PIPE_O), init_pipe_lock);
    pthread_once((pthread_once_t*) get_attr(LOCK_SYSLOG_O), init_syslog_lock);
}

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
	case LOCK_SYSLOG:
        ret_val = &syslog_lock;
        break;
	}
	
	return ret_val;
}

pthread_once_t* get_attr(int locko) {
	pthread_once_t *ret_val;

	switch (locko) {
	case LOCK_SNMP_O:
		ret_val = &snmp_lock_o;
		break;
	case LOCK_THREAD_O:
 		ret_val = &threads_lock_o;
        break;
	case LOCK_MYSQL_O:
        ret_val = &mysql_lock_o;
        break;
	case LOCK_RRDTOOL_O:
        ret_val = &rrdtool_lock_o;
        break;
	case LOCK_PIPE_O:
        ret_val = &pipe_lock_o;
        break;
	case LOCK_SYSLOG_O:
        ret_val = &syslog_lock_o;
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
