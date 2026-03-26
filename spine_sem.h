/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_SEM_H
#define SPINE_SEM_H

/*
 * Portable counting semaphore using pthreads.
 *
 * macOS deprecated unnamed POSIX semaphores (sem_init, sem_getvalue).
 * This wrapper provides the same counting semantics using a pthread
 * mutex + condition variable, which works on all POSIX platforms.
 *
 * Spine uses semaphores as atomic counters (sem_post, sem_getvalue, sem_trywait).
 */

#include <pthread.h>
#include <errno.h>

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t  cond;
	int             value;
} spine_sem_t;

static inline int spine_sem_init(spine_sem_t *s, int value) {
	if (pthread_mutex_init(&s->mutex, NULL) != 0) return -1;
	if (pthread_cond_init(&s->cond, NULL) != 0) {
		pthread_mutex_destroy(&s->mutex);
		return -1;
	}
	s->value = value;
	return 0;
}

static inline int spine_sem_post(spine_sem_t *s) {
	pthread_mutex_lock(&s->mutex);
	s->value++;
	pthread_cond_signal(&s->cond);
	pthread_mutex_unlock(&s->mutex);
	return 0;
}

static inline int spine_sem_getvalue(spine_sem_t *s, int *val) {
	pthread_mutex_lock(&s->mutex);
	*val = s->value;
	pthread_mutex_unlock(&s->mutex);
	return 0;
}

static inline int spine_sem_wait(spine_sem_t *s) {
	pthread_mutex_lock(&s->mutex);
	while (s->value <= 0)
		pthread_cond_wait(&s->cond, &s->mutex);
	s->value--;
	pthread_mutex_unlock(&s->mutex);
	return 0;
}

static inline int spine_sem_trywait(spine_sem_t *s) {
	pthread_mutex_lock(&s->mutex);
	if (s->value <= 0) {
		pthread_mutex_unlock(&s->mutex);
		errno = EAGAIN;
		return -1;
	}
	s->value--;
	pthread_mutex_unlock(&s->mutex);
	return 0;
}

static inline int spine_sem_destroy(spine_sem_t *s) {
	pthread_mutex_destroy(&s->mutex);
	pthread_cond_destroy(&s->cond);
	return 0;
}

#endif /* SPINE_SEM_H */
