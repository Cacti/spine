#include "locks.h"
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
