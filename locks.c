/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2021 The Cacti Group                                 |
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
	static pthread_cond_t name ## _cond = PTHREAD_COND_INITIALIZER; \
	static void init_ ## name ## _lock(void) { \
	    pthread_mutex_init(&name ## _lock, PTHREAD_MUTEXATTR_DEFAULT); \
	}

DEFINE_SPINE_LOCK(snmp)
DEFINE_SPINE_LOCK(seteuid)
DEFINE_SPINE_LOCK(ghbn)
DEFINE_SPINE_LOCK(pool)
DEFINE_SPINE_LOCK(syslog)
DEFINE_SPINE_LOCK(php)
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
DEFINE_SPINE_LOCK(php_proc_10)
DEFINE_SPINE_LOCK(php_proc_11)
DEFINE_SPINE_LOCK(php_proc_12)
DEFINE_SPINE_LOCK(php_proc_13)
DEFINE_SPINE_LOCK(php_proc_14)
DEFINE_SPINE_LOCK(thdet)
DEFINE_SPINE_LOCK(host_time)

void init_mutexes() {
	pthread_once((pthread_once_t*) get_attr(LOCK_SNMP_O),        init_snmp_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_SETEUID_O),     init_seteuid_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_GHBN_O),        init_ghbn_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_POOL_O),        init_pool_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_SYSLOG_O),      init_syslog_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_O),         init_php_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_0_O),  init_php_proc_0_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_1_O),  init_php_proc_1_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_2_O),  init_php_proc_2_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_3_O),  init_php_proc_3_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_4_O),  init_php_proc_4_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_5_O),  init_php_proc_5_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_6_O),  init_php_proc_6_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_7_O),  init_php_proc_7_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_8_O),  init_php_proc_8_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_9_O),  init_php_proc_9_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_10_O), init_php_proc_10_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_11_O), init_php_proc_11_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_12_O), init_php_proc_12_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_13_O), init_php_proc_13_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_PHP_PROC_14_O), init_php_proc_14_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_THDET_O),       init_thdet_lock);
	pthread_once((pthread_once_t*) get_attr(LOCK_HOST_TIME_O),   init_host_time_lock);
}

const char* get_name(int lock) {
	switch (lock) {
		case LOCK_SNMP:        return "snmp";
		case LOCK_SETEUID:     return "seteuid";
		case LOCK_GHBN:        return "ghbn";
		case LOCK_POOL:        return "pool";
		case LOCK_SYSLOG:      return "syslog";
		case LOCK_PHP:         return "php";
		case LOCK_PHP_PROC_0:  return "php_proc_0";
		case LOCK_PHP_PROC_1:  return "php_proc_1";
		case LOCK_PHP_PROC_2:  return "php_proc_2";
		case LOCK_PHP_PROC_3:  return "php_proc_3";
		case LOCK_PHP_PROC_4:  return "php_proc_4";
		case LOCK_PHP_PROC_5:  return "php_proc_5";
		case LOCK_PHP_PROC_6:  return "php_proc_6";
		case LOCK_PHP_PROC_7:  return "php_proc_7";
		case LOCK_PHP_PROC_8:  return "php_proc_8";
		case LOCK_PHP_PROC_9:  return "php_proc_9";
		case LOCK_PHP_PROC_10: return "php_proc_10";
		case LOCK_PHP_PROC_11: return "php_proc_11";
		case LOCK_PHP_PROC_12: return "php_proc_12";
		case LOCK_PHP_PROC_13: return "php_proc_13";
		case LOCK_PHP_PROC_14: return "php_proc_14";
		case LOCK_THDET:       return "thdet";
		case LOCK_HOST_TIME:   return "host_time";
	}

	return "Unknown lock";
}

pthread_cond_t* get_cond(int lock) {
	pthread_cond_t *ret_val = NULL;

	switch (lock) {
		case LOCK_SNMP:        ret_val = &snmp_cond;        break;
		case LOCK_SETEUID:     ret_val = &seteuid_cond;     break;
		case LOCK_GHBN:        ret_val = &ghbn_cond;        break;
		case LOCK_POOL:        ret_val = &pool_cond;        break;
		case LOCK_SYSLOG:      ret_val = &syslog_cond;      break;
		case LOCK_PHP:         ret_val = &php_cond;         break;
		case LOCK_PHP_PROC_0:  ret_val = &php_proc_0_cond;  break;
		case LOCK_PHP_PROC_1:  ret_val = &php_proc_1_cond;  break;
		case LOCK_PHP_PROC_2:  ret_val = &php_proc_2_cond;  break;
		case LOCK_PHP_PROC_3:  ret_val = &php_proc_3_cond;  break;
		case LOCK_PHP_PROC_4:  ret_val = &php_proc_4_cond;  break;
		case LOCK_PHP_PROC_5:  ret_val = &php_proc_5_cond;  break;
		case LOCK_PHP_PROC_6:  ret_val = &php_proc_6_cond;  break;
		case LOCK_PHP_PROC_7:  ret_val = &php_proc_7_cond;  break;
		case LOCK_PHP_PROC_8:  ret_val = &php_proc_8_cond;  break;
		case LOCK_PHP_PROC_9:  ret_val = &php_proc_9_cond;  break;
		case LOCK_PHP_PROC_10: ret_val = &php_proc_10_cond; break;
		case LOCK_PHP_PROC_11: ret_val = &php_proc_11_cond; break;
		case LOCK_PHP_PROC_12: ret_val = &php_proc_12_cond; break;
		case LOCK_PHP_PROC_13: ret_val = &php_proc_13_cond; break;
		case LOCK_PHP_PROC_14: ret_val = &php_proc_14_cond; break;
		case LOCK_THDET:       ret_val = &thdet_cond;       break;
		case LOCK_HOST_TIME:   ret_val = &host_time_cond;   break;
	}

	SPINE_LOG_DEVDBG(("LOCKS: [ RET ] Returning cond for %s", get_name(lock)));

	return ret_val;
}

pthread_mutex_t* get_lock(int lock) {
	pthread_mutex_t *ret_val = NULL;

	switch (lock) {
		case LOCK_SNMP:        ret_val = &snmp_lock;        break;
		case LOCK_SETEUID:     ret_val = &seteuid_lock;     break;
		case LOCK_GHBN:        ret_val = &ghbn_lock;        break;
		case LOCK_POOL:        ret_val = &pool_lock;        break;
		case LOCK_SYSLOG:      ret_val = &syslog_lock;      break;
		case LOCK_PHP:         ret_val = &php_lock;         break;
		case LOCK_PHP_PROC_0:  ret_val = &php_proc_0_lock;  break;
		case LOCK_PHP_PROC_1:  ret_val = &php_proc_1_lock;  break;
		case LOCK_PHP_PROC_2:  ret_val = &php_proc_2_lock;  break;
		case LOCK_PHP_PROC_3:  ret_val = &php_proc_3_lock;  break;
		case LOCK_PHP_PROC_4:  ret_val = &php_proc_4_lock;  break;
		case LOCK_PHP_PROC_5:  ret_val = &php_proc_5_lock;  break;
		case LOCK_PHP_PROC_6:  ret_val = &php_proc_6_lock;  break;
		case LOCK_PHP_PROC_7:  ret_val = &php_proc_7_lock;  break;
		case LOCK_PHP_PROC_8:  ret_val = &php_proc_8_lock;  break;
		case LOCK_PHP_PROC_9:  ret_val = &php_proc_9_lock;  break;
		case LOCK_PHP_PROC_10: ret_val = &php_proc_10_lock; break;
		case LOCK_PHP_PROC_11: ret_val = &php_proc_11_lock; break;
		case LOCK_PHP_PROC_12: ret_val = &php_proc_12_lock; break;
		case LOCK_PHP_PROC_13: ret_val = &php_proc_13_lock; break;
		case LOCK_PHP_PROC_14: ret_val = &php_proc_14_lock; break;
		case LOCK_THDET:       ret_val = &thdet_lock;       break;
		case LOCK_HOST_TIME:   ret_val = &host_time_lock;   break;
	}

	SPINE_LOG_DEVDBG(("LOCKS: [ RET ] Returning lock for %s", get_name(lock)));

	return ret_val;
}

pthread_once_t* get_attr(int locko) {
	pthread_once_t *ret_val = NULL;

	switch (locko) {
		case LOCK_SNMP_O:        ret_val = &snmp_lock_o;        break;
		case LOCK_SETEUID_O:     ret_val = &seteuid_lock_o;     break;
		case LOCK_GHBN_O:        ret_val = &ghbn_lock_o;        break;
		case LOCK_POOL_O:        ret_val = &pool_lock_o;        break;
		case LOCK_SYSLOG_O:      ret_val = &syslog_lock_o;      break;
		case LOCK_PHP_O:         ret_val = &php_lock_o;         break;
		case LOCK_PHP_PROC_0_O:  ret_val = &php_proc_0_lock_o;  break;
		case LOCK_PHP_PROC_1_O:  ret_val = &php_proc_1_lock_o;  break;
		case LOCK_PHP_PROC_2_O:  ret_val = &php_proc_2_lock_o;  break;
		case LOCK_PHP_PROC_3_O:  ret_val = &php_proc_3_lock_o;  break;
		case LOCK_PHP_PROC_4_O:  ret_val = &php_proc_4_lock_o;  break;
		case LOCK_PHP_PROC_5_O:  ret_val = &php_proc_5_lock_o;  break;
		case LOCK_PHP_PROC_6_O:  ret_val = &php_proc_6_lock_o;  break;
		case LOCK_PHP_PROC_7_O:  ret_val = &php_proc_7_lock_o;  break;
		case LOCK_PHP_PROC_8_O:  ret_val = &php_proc_8_lock_o;  break;
		case LOCK_PHP_PROC_9_O:  ret_val = &php_proc_9_lock_o;  break;
		case LOCK_PHP_PROC_10_O: ret_val = &php_proc_10_lock_o; break;
		case LOCK_PHP_PROC_11_O: ret_val = &php_proc_11_lock_o; break;
		case LOCK_PHP_PROC_12_O: ret_val = &php_proc_12_lock_o; break;
		case LOCK_PHP_PROC_13_O: ret_val = &php_proc_13_lock_o; break;
		case LOCK_PHP_PROC_14_O: ret_val = &php_proc_14_lock_o; break;
		case LOCK_THDET_O:       ret_val = &thdet_lock_o;       break;
		case LOCK_HOST_TIME_O:   ret_val = &host_time_lock_o;   break;
	}

	SPINE_LOG_DEVDBG(("LOCKS: [ RET ] Returning attr for %s", get_name(locko)));

	return ret_val;
}

void thread_mutex_lock(int mutex) {
	SPINE_LOG_DEVDBG(("LOCKS: [START] Mutex lock for %s", get_name(mutex)));
	pthread_mutex_lock(get_lock(mutex));
	SPINE_LOG_DEVDBG(("LOCKS: [ END ] Mutex lock for %s", get_name(mutex)));
}

void thread_mutex_unlock(int mutex) {
	SPINE_LOG_DEVDBG(("LOCKS: [START] Mutex unlock for %s", get_name(mutex)));
	pthread_mutex_unlock(get_lock(mutex));
	SPINE_LOG_DEVDBG(("LOCKS: [ END ] Mutex unlock for %s", get_name(mutex)));
}

int thread_mutex_trylock(int mutex) {
	SPINE_LOG_DEVDBG(("LOCKS: [START] Mutex try lock for %s", get_name(mutex)));
	int ret_val = pthread_mutex_trylock(get_lock(mutex));
	SPINE_LOG_DEVDBG(("LOCKS: [ END ] Mutex try lock for %s, result = %d", get_name(mutex), ret_val));
	return ret_val;
}

