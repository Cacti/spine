/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "database/lease.h"
#include <limits.h>

#ifdef SPINE_LEASE_TEST_WRAP
static int fail_allocate;
static int fail_initialize;
static int fail_destroy;
extern void *__real_calloc(size_t, size_t);
extern int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
extern int __real_pthread_mutex_destroy(pthread_mutex_t *);
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
#endif

typedef struct {
	pool_t *pool;
	db_lease_t lease;
} foreign_lease_t;

static void *foreign_release(void *argument) {
	foreign_lease_t *foreign = argument;
	return (void *) (intptr_t) db_pool_return_owned(foreign->pool, &foreign->lease);
}

static void test_lease_bounds_generations_and_thread_ownership(void **state) {
	pool_t slots[2] = {0};
	db_lease_t lease = {0};
	db_lease_t next = {0};
	db_lease_t stale;
	db_lease_t invalid;
	foreign_lease_t foreign;
	pthread_t thread;
	void *result;
	(void) state;
	assert_int_equal(db_pool_ownership_init(NULL, 1), EINVAL);
	assert_int_equal(db_pool_ownership_init(slots, 0), EINVAL);
	assert_int_equal(db_pool_ownership_init(slots, (size_t) INT_MAX + 1), EINVAL);
	assert_int_equal(db_pool_owned_size(NULL), 0);
	assert_int_equal(db_pool_owned_size(slots), 0);
	assert_int_equal(db_pool_ownership_destroy(NULL), EINVAL);
	assert_int_equal(db_pool_ownership_destroy(slots), EINVAL);
	assert_null(db_pool_take_owned(NULL, &lease));
	assert_null(db_pool_take_owned(slots, &lease));
	assert_int_equal(db_pool_return_owned(NULL, &lease), EINVAL);
	assert_int_equal(db_pool_return_owned(slots, &lease), EINVAL);
	lease.connection = &slots[0];
	assert_int_equal(db_pool_return_owned(slots, &lease), EINVAL);
	lease.connection = NULL;
	assert_int_equal(db_pool_ownership_init(slots, 2), 0);
	assert_int_equal(db_pool_ownership_init(slots, 2), EINVAL);
	assert_int_equal(db_pool_owned_size(slots), 2);
	assert_int_equal(db_pool_owned_size(&slots[1]), 0);
	assert_int_equal(db_pool_ownership_destroy(&slots[1]), EINVAL);
	assert_null(db_pool_take_owned(&slots[1], &lease));
	assert_null(db_pool_take_owned(slots, NULL));
	assert_int_equal(db_pool_return_owned(slots, NULL), EINVAL);
	assert_int_equal(db_pool_return_owned(slots, &lease), EINVAL);
	slots[0].free = FALSE;
	slots[1].free = TRUE;
	assert_ptr_equal(db_pool_take_owned(slots, &lease), &slots[1]);
	assert_int_equal(lease.index, 1);
	assert_int_equal(lease.generation, 1);
	assert_null(db_pool_take_owned(slots, &lease));
	assert_null(db_pool_take_owned(slots, &next));
	assert_int_equal(db_pool_ownership_destroy(slots), EBUSY);
	/* An inconsistent legacy free marker cannot admit a second borrower. */
	slots[1].free = TRUE;
	assert_null(db_pool_take_owned(slots, &next));
	slots[1].free = FALSE;
	invalid = lease;
	invalid.index = SIZE_MAX;
	assert_int_equal(db_pool_return_owned(slots, &invalid), EINVAL);
	invalid = lease;
	invalid.connection = &slots[0];
	assert_int_equal(db_pool_return_owned(slots, &invalid), EINVAL);
	assert_int_equal(db_pool_return_owned(&slots[1], &lease), EINVAL);
	foreign.pool = slots;
	foreign.lease = lease;
	assert_int_equal(pthread_create(&thread, NULL, foreign_release, &foreign), 0);
	assert_int_equal(pthread_join(thread, &result), 0);
	assert_int_equal((intptr_t) result, EPERM);
	assert_true(slots[1].leased);
	stale = lease;
	assert_int_equal(db_pool_return_owned(slots, &lease), 0);
	assert_null(lease.connection);
	assert_int_equal(db_pool_return_owned(slots, &stale), EPERM);
	assert_ptr_equal(db_pool_take_owned(slots, &next), &slots[1]);
	assert_int_equal(next.generation, 2);
	assert_int_equal(db_pool_return_owned(slots, &stale), EPERM);
	assert_true(slots[1].leased);
	assert_int_equal(db_pool_return_owned(slots, &next), 0);
	/* Refuse reuse at generation exhaustion rather than wrap a stale token. */
	slots[0].free = TRUE;
	slots[0].generation = UINT64_MAX;
	assert_ptr_equal(db_pool_take_owned(slots, &lease), &slots[1]);
	assert_int_equal(db_pool_return_owned(slots, &lease), 0);
	assert_int_equal(db_pool_ownership_destroy(slots), 0);
	assert_null(slots[0].ownership);
	assert_null(slots[1].ownership);
}

#ifdef SPINE_LEASE_TEST_WRAP
static void test_lease_initialization_and_destruction_failures(void **state) {
	pool_t slots[1] = {0};
	(void) state;
	fail_allocate = 1;
	assert_int_equal(db_pool_ownership_init(slots, 1), ENOMEM);
	assert_null(slots[0].ownership);
	fail_initialize = 1;
	assert_int_equal(db_pool_ownership_init(slots, 1), EAGAIN);
	assert_null(slots[0].ownership);
	assert_int_equal(db_pool_ownership_init(slots, 1), 0);
	fail_destroy = 1;
	assert_int_equal(db_pool_ownership_destroy(slots), EBUSY);
	assert_non_null(slots[0].ownership);
	assert_int_equal(db_pool_ownership_destroy(slots), 0);
}
#endif

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_lease_bounds_generations_and_thread_ownership),
#ifdef SPINE_LEASE_TEST_WRAP
		cmocka_unit_test(test_lease_initialization_and_destruction_failures),
#endif
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
