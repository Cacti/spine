/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

/*
 * each lock requires a handful of parts: a mutex, an init structure, and an
 * init helper function. We are NOT allowed to use these in an array (doesn
 * not work with pthreads), so we are stuck setting these up individually.
 * This macro defines these helpers in a single step.
 */

#define DEFINE_SPINE_LOCK(name)	\
	static pthread_mutex_t name ## _lock; \
	static pthread_once_t name ## _lock_o = PTHREAD_ONCE_INIT; \
	static void init_ ## name ## _lock(void) { \
	    pthread_mutex_init(&name ## _lock, PTHREAD_MUTEXATTR_DEFAULT); \
	}

DEFINE_SPINE_LOCK(snmp)
DEFINE_SPINE_LOCK(seteuid)
DEFINE_SPINE_LOCK(ghbn)
DEFINE_SPINE_LOCK(syslog)
DEFINE_SPINE_LOCK(php)
DEFINE_SPINE_LOCK(pend)
DEFINE_SPINE_LOCK(php_proc_0)
DEFINE_SPINE_LOCK(php_proc_1)
DEFINE_SPINE_LOCK(php_proc_2)
DEFINE_SPINE_LOCK(php_proc_3)
DEFINE_SPINE_LOCK(php_proc_4)
DEFINE_SPINE_LOCK(php_proc_5)
DEFINE_SPINE_LOCK(php_proc_6)
DEFINE_SPINE_LOCK(php_proc_7)
DEFINE_SPINE_LOCK(php_proc_8)
DEFINE_SPINE_LOCK(php_proc_9)

void init_mutexes() {
	pthread_once((pthread_once_t*) get_attr(LOCK_SNMP_O),       init_snmp_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_SETEUID_O),    init_seteuid_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_GHBN_O),       init_ghbn_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_SYSLOG_O),     init_syslog_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_O),        init_php_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PEND_O),       init_pend_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_0_O), init_php_proc_0_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_1_O), init_php_proc_1_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_2_O), init_php_proc_2_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_3_O), init_php_proc_3_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_4_O), init_php_proc_4_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_5_O), init_php_proc_5_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_6_O), init_php_proc_6_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_7_O), init_php_proc_7_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_8_O), init_php_proc_8_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_9_O), init_php_proc_9_lock);
}

pthread_mutex_t* get_lock(int lock) {
	pthread_mutex_t *ret_val = NULL;

	switch (lock) {
	case LOCK_SNMP:       ret_val = &snmp_lock;       break;
	case LOCK_SETEUID:    ret_val = &seteuid_lock;    break;
	case LOCK_GHBN:       ret_val = &ghbn_lock;       break;
	case LOCK_SYSLOG:     ret_val = &syslog_lock;     break;
	case LOCK_PHP:        ret_val = &php_lock;        break;
	case LOCK_PHP_PROC_0: ret_val = &php_proc_0_lock; break;
	case LOCK_PHP_PROC_1: ret_val = &php_proc_1_lock; break;
	case LOCK_PHP_PROC_2: ret_val = &php_proc_2_lock; break;
	case LOCK_PHP_PROC_3: ret_val = &php_proc_3_lock; break;
	case LOCK_PHP_PROC_4: ret_val = &php_proc_4_lock; break;
	case LOCK_PHP_PROC_5: ret_val = &php_proc_5_lock; break;
	case LOCK_PHP_PROC_6: ret_val = &php_proc_6_lock; break;
	case LOCK_PHP_PROC_7: ret_val = &php_proc_7_lock; break;
	case LOCK_PHP_PROC_8: ret_val = &php_proc_8_lock; break;
	case LOCK_PHP_PROC_9: ret_val = &php_proc_9_lock; break;
	case LOCK_PEND:       ret_val = &pend_lock;       break;
	}

	return ret_val;
}

pthread_once_t* get_attr(int locko) {
	pthread_once_t *ret_val = NULL;

	switch (locko) {
	case LOCK_SNMP_O:       ret_val = &snmp_lock_o;       break;
	case LOCK_SETEUID_O:    ret_val = &seteuid_lock_o;    break;
	case LOCK_GHBN_O:       ret_val = &ghbn_lock_o;       break;
	case LOCK_SYSLOG_O:     ret_val = &syslog_lock_o;     break;
	case LOCK_PHP_O:        ret_val = &php_lock_o;        break;
	case LOCK_PHP_PROC_0_O: ret_val = &php_proc_0_lock_o; break;
	case LOCK_PHP_PROC_1_O: ret_val = &php_proc_1_lock_o; break;
	case LOCK_PHP_PROC_2_O: ret_val = &php_proc_2_lock_o; break;
	case LOCK_PHP_PROC_3_O: ret_val = &php_proc_3_lock_o; break;
	case LOCK_PHP_PROC_4_O: ret_val = &php_proc_4_lock_o; break;
	case LOCK_PHP_PROC_5_O: ret_val = &php_proc_5_lock_o; break;
	case LOCK_PHP_PROC_6_O: ret_val = &php_proc_6_lock_o; break;
	case LOCK_PHP_PROC_7_O: ret_val = &php_proc_7_lock_o; break;
	case LOCK_PHP_PROC_8_O: ret_val = &php_proc_8_lock_o; break;
	case LOCK_PHP_PROC_9_O: ret_val = &php_proc_9_lock_o; break;
	case LOCK_PEND_O:       ret_val = &pend_lock_o;       break;
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

