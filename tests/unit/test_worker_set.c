/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "config/config.h"
#include "platform/worker_set.h"

#ifdef SPINE_WORKER_TEST_WRAP
static int fail_allocate;
static int fail_initialize;
static int fail_create;
static int fail_join;
static int fail_destroy;
static int fail_attributes;
extern void *__real_calloc(size_t, size_t);
extern int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
extern int __real_pthread_mutex_destroy(pthread_mutex_t *);
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*) (void *), void *);
extern int __real_pthread_join(pthread_t, void **);
extern int __real_pthread_attr_getdetachstate(const pthread_attr_t *, int *);

void *__wrap_calloc(size_t count, size_t size) {
	if (fail_allocate) {
		fail_allocate = 0;
		return NULL;
	}
	return __real_calloc(count, size);
}
int __wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attributes) {
	if (fail_initialize) {
		fail_initialize = 0;
		return EAGAIN;
	}
	return __real_pthread_mutex_init(mutex, attributes);
}
int __wrap_pthread_mutex_destroy(pthread_mutex_t *mutex) {
	if (fail_destroy) {
		fail_destroy = 0;
		return EBUSY;
	}
	return __real_pthread_mutex_destroy(mutex);
}
int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes, void *(*function)(void *), void *argument) {
	if (fail_create) {
		fail_create = 0;
		return EPERM;
	}
	return __real_pthread_create(thread, attributes, function, argument);
}
int __wrap_pthread_join(pthread_t thread, void **result) {
	if (fail_join) {
		fail_join = 0;
		return EINVAL;
	}
	return __real_pthread_join(thread, result);
}
int __wrap_pthread_attr_getdetachstate(const pthread_attr_t *attributes, int *state) {
	if (fail_attributes) {
		fail_attributes = 0;
		return EINVAL;
	}
	return __real_pthread_attr_getdetachstate(attributes, state);
}
#endif

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	bool release;
	bool entered;
} worker_gate_t;

static void unlock_gate(void *argument) {
	pthread_mutex_unlock(argument);
}

static void *gated_worker(void *argument) {
	worker_gate_t *gate = argument;
	pthread_mutex_lock(&gate->mutex);
	pthread_cleanup_push(unlock_gate, &gate->mutex);
	gate->entered = true;
	pthread_cond_broadcast(&gate->condition);
	while (!gate->release) pthread_cond_wait(&gate->condition, &gate->mutex);
	pthread_cleanup_pop(1);
	return argument;
}

static void await_entry(worker_gate_t *gate) {
	pthread_mutex_lock(&gate->mutex);
	while (!gate->entered) pthread_cond_wait(&gate->condition, &gate->mutex);
	pthread_mutex_unlock(&gate->mutex);
}

static void release_gate(worker_gate_t *gate) {
	pthread_mutex_lock(&gate->mutex);
	gate->release = true;
	pthread_cond_broadcast(&gate->condition);
	pthread_mutex_unlock(&gate->mutex);
}

static void await_finished(spine_worker_set_t *workers, size_t index) {
	bool finished;
	unsigned int attempts;
	for (attempts = 0; attempts < 5000; attempts++) {
		pthread_mutex_lock(&workers->mutex);
		finished = workers->slots[index].finished;
		pthread_mutex_unlock(&workers->mutex);
		if (finished) return;
		usleep(1000);
	}
	fail_msg("worker did not publish completion");
}

static void test_registry_bounds_and_order(void **state) {
	spine_worker_set_t workers = {0};
	pthread_attr_t attributes;
	worker_gate_t first = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, false};
	worker_gate_t second = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, false};
	size_t remaining;
	(void) state;
	assert_int_equal(spine_worker_set_init(NULL, 1), EINVAL);
	assert_int_equal(spine_worker_set_init(&workers, 0), EINVAL);
	assert_int_equal(spine_worker_set_init(&workers, SIZE_MAX), EINVAL);
	assert_int_equal(spine_worker_set_reap(NULL, &remaining), EINVAL);
	assert_int_equal(spine_worker_set_destroy(&workers), EINVAL);
	assert_int_equal(spine_worker_set_init(&workers, 2), 0);
	assert_int_equal(spine_worker_set_init(&workers, 2), EINVAL);
	assert_int_equal(spine_worker_set_reap(&workers, NULL), EINVAL);
	assert_int_equal(pthread_attr_init(&attributes), 0);
	assert_int_equal(spine_worker_set_start(&workers, NULL, gated_worker, &first), EINVAL);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, NULL, &first), EINVAL);
	assert_int_equal(pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED), 0);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, gated_worker, &first), EINVAL);
	assert_int_equal(pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_JOINABLE), 0);
	assert_int_equal(spine_worker_set_start(NULL, &attributes, gated_worker, &first), EINVAL);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, gated_worker, &first), 0);
	await_entry(&first);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, gated_worker, &second), 0);
	await_entry(&second);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, gated_worker, &second), EAGAIN);
	assert_int_equal(spine_worker_set_destroy(&workers), EBUSY);
	/* The second worker finishes first. Reusing it must not join/block on
	 * the first worker, which still waits on its gate. */
	release_gate(&second);
	await_finished(&workers, 1);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, gated_worker, &second), 0);
	await_finished(&workers, 1);
	assert_int_equal(spine_worker_set_reap(&workers, &remaining), 0);
	assert_int_equal(remaining, 1);
	release_gate(&first);
	await_finished(&workers, 0);
	assert_int_equal(spine_worker_set_destroy(&workers), 0);
	assert_null(workers.slots);
	assert_int_equal(workers.capacity, 0);
	assert_int_equal(pthread_attr_destroy(&attributes), 0);
	assert_int_equal(pthread_mutex_destroy(&first.mutex), 0);
	assert_int_equal(pthread_mutex_destroy(&second.mutex), 0);
	assert_int_equal(pthread_cond_destroy(&first.condition), 0);
	assert_int_equal(pthread_cond_destroy(&second.condition), 0);
}

static void *exiting_worker(void *argument) {
	pthread_exit(argument);
}

/* Publish entry before reaching a cancellation point with no fixture mutex
 * held. The test concerns registry ownership; cancelling a condition wait
 * additionally depends on libc's internal mutex reacquisition bookkeeping. */
static void *cancellable_worker(void *argument) {
	worker_gate_t *gate = argument;
	pthread_mutex_lock(&gate->mutex);
	gate->entered = true;
	pthread_cond_broadcast(&gate->condition);
	pthread_mutex_unlock(&gate->mutex);
	for (;;) usleep(1000);
}

static void test_exit_and_cancellation_are_joined(void **state) {
	spine_worker_set_t workers = {0};
	pthread_attr_t attributes;
	worker_gate_t gate = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, false};
	(void) state;
	assert_int_equal(pthread_attr_init(&attributes), 0);
	assert_int_equal(spine_worker_set_init(&workers, 1), 0);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, exiting_worker, &gate), 0);
	await_finished(&workers, 0);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, cancellable_worker, &gate), 0);
	await_entry(&gate);
	assert_int_equal(pthread_cancel(workers.slots[0].thread), 0);
	await_finished(&workers, 0);
	assert_int_equal(spine_worker_set_destroy(&workers), 0);
	assert_int_equal(pthread_attr_destroy(&attributes), 0);
	assert_int_equal(pthread_mutex_destroy(&gate.mutex), 0);
	assert_int_equal(pthread_cond_destroy(&gate.condition), 0);
}

#ifdef SPINE_WORKER_TEST_WRAP
static void test_registry_failures_preserve_ownership(void **state) {
	spine_worker_set_t workers = {0};
	pthread_attr_t attributes;
	size_t remaining;
	(void) state;
	fail_allocate = 1;
	assert_int_equal(spine_worker_set_init(&workers, 1), ENOMEM);
	assert_null(workers.slots);
	fail_initialize = 1;
	assert_int_equal(spine_worker_set_init(&workers, 1), EAGAIN);
	assert_null(workers.slots);
	assert_int_equal(spine_worker_set_init(&workers, 1), 0);
	assert_int_equal(pthread_attr_init(&attributes), 0);
	fail_attributes = 1;
	assert_int_equal(spine_worker_set_start(&workers, &attributes, exiting_worker, NULL), EINVAL);
	fail_create = 1;
	assert_int_equal(spine_worker_set_start(&workers, &attributes, exiting_worker, NULL), EPERM);
	assert_false(workers.slots[0].occupied);
	assert_null(workers.slots[0].argument);
	assert_int_equal(spine_worker_set_start(&workers, &attributes, exiting_worker, NULL), 0);
	await_finished(&workers, 0);
	fail_join = 1;
	assert_int_equal(spine_worker_set_start(&workers, &attributes, exiting_worker, NULL), EINVAL);
	assert_true(workers.slots[0].occupied);
	fail_join = 1;
	assert_int_equal(spine_worker_set_destroy(&workers), EINVAL);
	assert_true(workers.slots[0].occupied);
	assert_int_equal(spine_worker_set_reap(&workers, &remaining), 0);
	assert_int_equal(remaining, 0);
	fail_destroy = 1;
	assert_int_equal(spine_worker_set_destroy(&workers), EBUSY);
	assert_non_null(workers.slots);
	assert_int_equal(spine_worker_set_destroy(&workers), 0);
	assert_int_equal(pthread_attr_destroy(&attributes), 0);
}
#endif

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_registry_bounds_and_order),
		cmocka_unit_test(test_exit_and_cancellation_are_joined),
#ifdef SPINE_WORKER_TEST_WRAP
		cmocka_unit_test(test_registry_failures_preserve_ownership),
#endif
	};
	alarm(20);
	return cmocka_run_group_tests(tests, NULL, NULL);
}
