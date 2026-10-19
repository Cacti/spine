/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* Failure paths of the clock, socket wait, descriptor and permit helpers.
 * The fatal ones end in die(), so they run in a child and the parent checks
 * the exit status. Each wrapped call fails once, only while armed, so cmocka
 * and the logging code keep working around the fault. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "internal/common.h"
#include "app/spine.h"
#include "platform/clock.h"
#include "platform/socket.h"
#include "tests/support/child_run.h"

static int fail_nanosleep;
static int fail_clock_gettime;
static pthread_mutex_t *fail_lock_mutex;
static pthread_mutex_t *fail_unlock_mutex;
static int fail_attr_init;

int __real_nanosleep(const struct timespec *requested, struct timespec *remaining);
int __wrap_nanosleep(const struct timespec *requested, struct timespec *remaining) {
	if (fail_nanosleep) {
		fail_nanosleep = FALSE;
		errno = EINVAL;
		return -1;
	}
	return __real_nanosleep(requested, remaining);
}

int __real_clock_gettime(clockid_t clock, struct timespec *now);
int __wrap_clock_gettime(clockid_t clock, struct timespec *now) {
	if (fail_clock_gettime) {
		fail_clock_gettime = FALSE;
		errno = EINVAL;
		return -1;
	}
	return __real_clock_gettime(clock, now);
}

int __real_pthread_mutex_lock(pthread_mutex_t *mutex);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
	if (mutex == fail_lock_mutex) {
		fail_lock_mutex = NULL;
		return EINVAL;
	}
	return __real_pthread_mutex_lock(mutex);
}

int __real_pthread_mutex_unlock(pthread_mutex_t *mutex);
int __wrap_pthread_mutex_unlock(pthread_mutex_t *mutex) {
	if (mutex == fail_unlock_mutex) {
		fail_unlock_mutex = NULL;
		return EPERM;
	}
	return __real_pthread_mutex_unlock(mutex);
}

int __real_pthread_attr_init(pthread_attr_t *attributes);
int __wrap_pthread_attr_init(pthread_attr_t *attributes) {
	if (fail_attr_init) {
		fail_attr_init = FALSE;
		return ENOMEM;
	}
	return __real_pthread_attr_init(attributes);
}

static int platform_setup(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	fail_nanosleep = FALSE;
	fail_clock_gettime = FALSE;
	fail_lock_mutex = NULL;
	fail_unlock_mutex = NULL;
	fail_attr_init = FALSE;
	return 0;
}

static void sleep_with_a_broken_timer(void) {
	fail_nanosleep = TRUE;
	spine_sleep_usec(1);
}

static void read_a_broken_clock(void) {
	fail_clock_gettime = TRUE;
	(void) spine_monotonic_time();
}

static void test_sleep_failure_other_than_eintr_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(sleep_with_a_broken_timer), EXIT_FAILURE);
}

static void test_monotonic_clock_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(read_a_broken_clock), EXIT_FAILURE);
}

static void test_wait_rejects_descriptors_select_cannot_hold(void **state) {
	(void) state;
	errno = 0;
	assert_int_equal(spine_wait_readable(-1, spine_monotonic_time() + 1), -1);
	assert_int_equal(errno, EBADF);
	errno = 0;
	assert_int_equal(spine_wait_writable(FD_SETSIZE, spine_monotonic_time() + 1), -1);
	assert_int_equal(errno, EBADF);
}

static void test_wait_rejects_a_non_finite_deadline(void **state) {
	(void) state;
	errno = 0;
	assert_int_equal(spine_wait_readable(0, NAN), -1);
	assert_int_equal(errno, EINVAL);
	errno = 0;
	assert_int_equal(spine_wait_readable(0, INFINITY), -1);
	assert_int_equal(errno, EINVAL);
}

static void test_wait_rejects_a_deadline_beyond_the_select_range(void **state) {
	(void) state;
	errno = 0;
	assert_int_equal(spine_wait_readable(0, spine_monotonic_time() + 4e9), -1);
	assert_int_equal(errno, EINVAL);
}

static void ignore_alarm(int signal_number) {
	(void) signal_number;
}

static void test_wait_resumes_after_an_interrupted_select(void **state) {
	struct sigaction action;
	struct sigaction previous;
	struct itimerval timer;
	int pipe_fds[2];
	double started;

	(void) state;
	assert_int_equal(pipe(pipe_fds), 0);
	memset(&action, 0, sizeof(action));
	action.sa_handler = ignore_alarm;
	sigemptyset(&action.sa_mask);
	assert_int_equal(sigaction(SIGALRM, &action, &previous), 0);
	memset(&timer, 0, sizeof(timer));
	timer.it_value.tv_usec = 10000;

	started = spine_monotonic_time();
	assert_int_equal(setitimer(ITIMER_REAL, &timer, NULL), 0);
	assert_int_equal(spine_wait_readable(pipe_fds[0], started + 0.2), 0);
	/* the signal lands at 10 ms; returning before the deadline would mean the
	 * wait gave up on EINTR instead of resuming */
	assert_true(spine_monotonic_time() - started >= 0.19);

	sigaction(SIGALRM, &previous, NULL);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
}

static void test_cloexec_reports_a_descriptor_that_is_not_open(void **state) {
	(void) state;
	set.logging.log_destination = LOGDEST_STDOUT;
	errno = 0;
	assert_int_equal(spine_set_cloexec(-1), -1);
	assert_int_equal(errno, EBADF);
}

static void test_dup_cloexec_reports_a_descriptor_that_is_not_open(void **state) {
	(void) state;
	errno = 0;
	assert_int_equal(spine_dup_cloexec(-1), -1);
	assert_int_equal(errno, EBADF);
}

static void lock_a_permit_set_whose_mutex_fails(void) {
	spine_permits_t permits;

	if (spine_permits_init(&permits, 1) != 0) _exit(2);
	fail_lock_mutex = &permits.mutex;
	(void) spine_permits_try_acquire(&permits);
}

static void unlock_a_permit_set_whose_mutex_fails(void) {
	spine_permits_t permits;

	if (spine_permits_init(&permits, 1) != 0) _exit(2);
	fail_unlock_mutex = &permits.mutex;
	(void) spine_permits_available(&permits);
}

static void test_permit_lock_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(lock_a_permit_set_whose_mutex_fails), EXIT_FAILURE);
}

static void test_permit_unlock_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(unlock_a_permit_set_whose_mutex_fails), EXIT_FAILURE);
}

static void test_thread_attributes_report_an_init_failure(void **state) {
	pthread_attr_t attributes;

	(void) state;
	fail_attr_init = TRUE;
	assert_int_equal(spine_thread_attr_init(&attributes), ENOMEM);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_sleep_failure_other_than_eintr_is_fatal, platform_setup),
		cmocka_unit_test_setup(test_monotonic_clock_failure_is_fatal, platform_setup),
		cmocka_unit_test_setup(test_wait_rejects_descriptors_select_cannot_hold, platform_setup),
		cmocka_unit_test_setup(test_wait_rejects_a_non_finite_deadline, platform_setup),
		cmocka_unit_test_setup(test_wait_rejects_a_deadline_beyond_the_select_range, platform_setup),
		cmocka_unit_test_setup(test_wait_resumes_after_an_interrupted_select, platform_setup),
		cmocka_unit_test_setup(test_cloexec_reports_a_descriptor_that_is_not_open, platform_setup),
		cmocka_unit_test_setup(test_dup_cloexec_reports_a_descriptor_that_is_not_open, platform_setup),
		cmocka_unit_test_setup(test_permit_lock_failure_is_fatal, platform_setup),
		cmocka_unit_test_setup(test_permit_unlock_failure_is_fatal, platform_setup),
		cmocka_unit_test_setup(test_thread_attributes_report_an_init_failure, platform_setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
