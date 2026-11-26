/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef SPINE_WORKER_SET_H
#define SPINE_WORKER_SET_H
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <pthread.h>

typedef struct spine_worker_set spine_worker_set_t;
typedef struct {
	pthread_t thread;
	spine_worker_set_t *owner;
	void *(*function)(void *);
	void *argument;
	bool occupied;
	atomic_bool finished;
} spine_worker_slot_t;

/* The parent owns this bounded registry until every child has been joined.
 * Arguments retain the callback's ownership contract. A completion flag only
 * permits joining; it never permits freeing shared runtime state by itself. */
struct spine_worker_set {
	spine_worker_slot_t *slots;
	size_t capacity;
	pthread_mutex_t mutex;
};

/* Initialize a zeroed registry. Only its parent calls start/reap/destroy. */
int spine_worker_set_init(spine_worker_set_t *workers, size_t capacity);
int spine_worker_set_start(spine_worker_set_t *workers, const pthread_attr_t *attributes,
	void *(*function)(void *), void *argument);
int spine_worker_set_reap(spine_worker_set_t *workers, size_t *remaining);
int spine_worker_set_destroy(spine_worker_set_t *workers);
void *spine_worker_entry(void *argument);
#endif
