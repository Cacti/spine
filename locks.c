/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2003 Ian Berry                                            |
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
 |    - Rivo Nurges (rrd support, mysql poller cache, misc functions)      |
 |    - RTG (core poller code, pthreads, snmp, autoconf examples)          |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#include <pthread.h>

static pthread_mutex_t crew_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t* get_lock(int lock) {
	pthread_mutex_t *ret_val;

	switch (lock) {
	case LOCK_CREW:
		ret_val = &crew_lock;
		break;
	case LOCK_STATS:
                ret_val = &stats_lock;
                break;
	}
	
	return ret_val;
}

void mutex_lock(int mutex) {
	pthread_mutex_lock(get_lock(mutex));
}

void mutex_unlock(int mutex) {
	pthread_mutex_unlock(get_lock(mutex));
}
