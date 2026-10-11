/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "platform/worker_set.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

static void finish_worker(void *argument) {
	spine_worker_slot_t *slot = argument;
	/* Completion is published during cancellation unwinding too. An atomic
     * release avoids depending on mutex-interceptor state in that path. The
     * parent still joins before reclaiming any slot or argument. */
	atomic_store_explicit(&slot->finished, true, memory_order_release);
}

void *spine_worker_entry(void *argument) {
	spine_worker_slot_t *slot = argument;
	void *result;
	pthread_cleanup_push(finish_worker, slot);
	result = slot->function(slot->argument);
	pthread_cleanup_pop(1);
	return result;
}

int spine_worker_set_init(spine_worker_set_t *workers, size_t capacity) {
	int error;
	size_t index;
	if (workers == NULL || workers->slots != NULL || capacity == 0 || capacity > SIZE_MAX / sizeof(*workers->slots)) return EINVAL;
	workers->slots = calloc(capacity, sizeof(*workers->slots));
	if (workers->slots == NULL) return ENOMEM;
	error = pthread_mutex_init(&workers->mutex, NULL);
	if (error != 0) {
		free(workers->slots);
		workers->slots = NULL;
		return error;
	}
	for (index = 0; index < capacity; index++) atomic_init(&workers->slots[index].finished, false);
	workers->capacity = capacity;
	return 0;
}

int spine_worker_set_reap(spine_worker_set_t *workers, size_t *remaining) {
	size_t index;
	size_t count = 0;
	if (workers == NULL || workers->slots == NULL || remaining == NULL) return EINVAL;
	for (index = 0; index < workers->capacity; index++) {
		spine_worker_slot_t *slot = &workers->slots[index];
		bool finished;
		int error;
		pthread_mutex_lock(&workers->mutex);
		finished = slot->occupied && atomic_load_explicit(&slot->finished, memory_order_acquire);
		pthread_mutex_unlock(&workers->mutex);
		if (finished) {
			error = pthread_join(slot->thread, NULL);
			if (error != 0) return error;
			slot->occupied = false;
			slot->argument = NULL;
		}
		if (slot->occupied) count++;
	}
	*remaining = count;
	return 0;
}

int spine_worker_set_start(spine_worker_set_t *workers, const pthread_attr_t *attributes,
	void *(*function)(void *), void *argument) {
	size_t remaining;
	size_t index;
	int error;
	int detached;
	if (function == NULL || attributes == NULL) return EINVAL;
	error = pthread_attr_getdetachstate(attributes, &detached);
	if (error != 0) return error;
	if (detached != PTHREAD_CREATE_JOINABLE) return EINVAL;
	error = spine_worker_set_reap(workers, &remaining);
	if (error != 0) return error;
	for (index = 0; index < workers->capacity; index++) {
		spine_worker_slot_t *slot = &workers->slots[index];
		if (slot->occupied) continue;
		slot->owner = workers;
		slot->function = function;
		slot->argument = argument;
		atomic_store_explicit(&slot->finished, false, memory_order_relaxed);
		slot->occupied = true;
		error = pthread_create(&slot->thread, attributes, spine_worker_entry, slot);
		if (error != 0) {
			slot->occupied = false;
			slot->argument = NULL;
		}
		return error;
	}
	return EAGAIN;
}

int spine_worker_set_destroy(spine_worker_set_t *workers) {
	size_t remaining;
	int error = spine_worker_set_reap(workers, &remaining);
	if (error != 0) return error;
	if (remaining != 0) return EBUSY;
	error = pthread_mutex_destroy(&workers->mutex);
	if (error != 0) return error;
	free(workers->slots);
	workers->slots = NULL;
	workers->capacity = 0;
	return 0;
}
