/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* php_read_response() against a pipe whose select() and read() calls fail on
 * demand. read.c is compiled into this test with those calls redirected, so
 * the production reader runs unmodified and the other script server sources
 * are linked as built. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

#include "internal/common.h"
#include "app/spine.h"
#include "script/server_internal.h"
#include "tests/support/child_run.h"

static int select_errors;
static int select_error_number;
static int select_hides_descriptor;
static int read_interruptions;
static size_t failing_allocation;
static double scripted_times[2];
static int scripted_time_count;

static int controlled_select(int count, fd_set *readable, fd_set *writable, fd_set *failed,
	struct timeval *timeout) {
	if (select_errors > 0) {
		select_errors--;
		errno = select_error_number;
		return -1;
	}
	if (select_hides_descriptor) {
		FD_ZERO(readable);
		return 1;
	}
	return select(count, readable, writable, failed, timeout);
}

static ssize_t controlled_read(int fd, void *buffer, size_t capacity) {
	if (read_interruptions > 0) {
		read_interruptions--;
		errno = EINTR;
		return -1;
	}
	return read(fd, buffer, capacity);
}

/* The EINTR branch recomputes the remaining timeout from two clock reads, so
 * the test scripts exactly those two reads. */
static double controlled_time(void) {
	if (scripted_time_count > 0) {
		return scripted_times[2 - scripted_time_count--];
	}
	return get_time_as_double();
}

static void *controlled_malloc(size_t size) {
	if (size == failing_allocation) {
		failing_allocation = 0;
		return NULL;
	}
	return malloc(size);
}

#define select controlled_select
#define read controlled_read
#define get_time_as_double controlled_time
#define malloc controlled_malloc
#include "../../src/script/read.c"
#undef malloc
#undef get_time_as_double
#undef read
#undef select

static int pipe_fds[2];

static int read_setup(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	set.logging.log_destination = LOGDEST_STDOUT;
	set.php.php_servers = 1;
	select_errors = 0;
	select_error_number = 0;
	select_hides_descriptor = FALSE;
	read_interruptions = 0;
	failing_allocation = 0;
	scripted_time_count = 0;

	php_processes = calloc(MAX_PHP_SERVERS, sizeof(*php_processes));
	assert_non_null(php_processes);
	php_processes_initialize(php_processes, MAX_PHP_SERVERS);
	assert_int_equal(pipe(pipe_fds), 0);
	php_processes[0].php_read_fd = pipe_fds[0];
	php_processes[0].php_write_fd = pipe_fds[1];
	php_processes[0].php_state = PHP_READY;
	return 0;
}

static int read_teardown(void **state) {
	(void) state;
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	free(php_processes);
	php_processes = NULL;
	return 0;
}

static void send_line(const char *line) {
	assert_int_equal(write(pipe_fds[1], line, strlen(line)), (ssize_t) strlen(line));
}

static void test_select_failures_leave_the_slot_busy(void **state) {
	const int failures[] = {EBADF, EINVAL, ENOMEM, EIO};
	char *result;
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(failures) / sizeof(failures[0]); index++) {
		php_processes[0].php_state = PHP_READY;
		select_errors = 1;
		select_error_number = failures[index];

		result = php_read_response(0, "poll 1", FALSE, 1);
		assert_non_null(result);
		assert_string_equal(result, "U");
		free(result);
		assert_int_equal(php_processes[0].php_state, PHP_BUSY);
	}
}

static void test_interrupted_select_resumes_with_the_remaining_timeout(void **state) {
	char *result;

	(void) state;
	send_line("42\n");
	select_errors = 1;
	select_error_number = EINTR;

	result = php_read_response(0, "poll 1", FALSE, 5);
	assert_non_null(result);
	assert_string_equal(result, "42\n");
	free(result);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
}

/* Both clock reads are exactly one timeout apart, so nothing is left to wait
 * and the reader gives up instead of retrying forever. */
static void test_interrupted_select_gives_up_when_the_timeout_is_spent(void **state) {
	char *result;

	(void) state;
	scripted_times[0] = 1000.0;
	scripted_times[1] = 1001.0;
	scripted_time_count = 2;
	select_errors = 1;
	select_error_number = EINTR;

	result = php_read_response(0, "poll 1", FALSE, 1);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(scripted_time_count, 0);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_interrupted_read_is_retried(void **state) {
	char *result;

	(void) state;
	send_line("7\n");
	read_interruptions = 1;

	result = php_read_response(0, "poll 1", FALSE, 5);
	assert_non_null(result);
	assert_string_equal(result, "7\n");
	free(result);
	assert_int_equal(read_interruptions, 0);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
}

static void test_descriptor_missing_from_the_ready_set_is_a_failure(void **state) {
	char *result;

	(void) state;
	send_line("7\n");
	select_hides_descriptor = TRUE;

	result = php_read_response(0, "poll 1", FALSE, 5);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void read_with_no_result_buffer(void) {
	failing_allocation = RESULTS_BUFFER;
	free(php_read_response(0, "poll 1", FALSE, 1));
}

static void test_result_allocation_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(read_with_no_result_buffer), EXIT_FAILURE);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_select_failures_leave_the_slot_busy, read_setup, read_teardown),
		cmocka_unit_test_setup_teardown(test_interrupted_select_resumes_with_the_remaining_timeout, read_setup, read_teardown),
		cmocka_unit_test_setup_teardown(test_interrupted_select_gives_up_when_the_timeout_is_spent, read_setup, read_teardown),
		cmocka_unit_test_setup_teardown(test_interrupted_read_is_retried, read_setup, read_teardown),
		cmocka_unit_test_setup_teardown(test_descriptor_missing_from_the_ready_set_is_a_failure, read_setup, read_teardown),
		cmocka_unit_test_setup_teardown(test_result_allocation_failure_is_fatal, read_setup, read_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
