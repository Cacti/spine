/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "internal/common.h"
#include "app/spine.h"

static int scenario;
static int calls;
static int controlled_wait(int fd, double deadline) {
	(void) fd;
	(void) deadline;
	if (scenario == 1) {
		errno = EBADF;
		return -1;
	}
	return scenario == 2 ? 0 : 1;
}
static ssize_t controlled_read(int fd, void *buffer, size_t capacity) {
	(void) fd;
	calls++;
	if (scenario == 3) {
		errno = EIO;
		return -1;
	}
	if (scenario == 4 && calls == 1) {
		errno = EINTR;
		return -1;
	}
	if (scenario == 5) return 0;
	if (calls == 1 || (scenario == 4 && calls == 2)) {
		assert_true(capacity >= 2);
		memcpy(buffer, "42", 2);
		return 2;
	}
	if (scenario == 6) {
		*(char *) buffer = '3';
		return 1;
	}
	return 0;
}
static int handoff_test;
static int handoff_disabled;
static int handoff_fd;
static int controlled_popen(const char *command, const char *type) {
	int fd = nft_popen(command, type);
	if (handoff_test) handoff_fd = fd;
	return fd;
}
static int controlled_pclose(int fd) {
	int previous;
	if (handoff_test) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
		handoff_disabled = previous == PTHREAD_CANCEL_DISABLE;
		pthread_setcancelstate(previous, NULL);
		pthread_cancel(pthread_self());
		pthread_testcancel();
	}
	return nft_pclose(fd);
}
#define nft_popen controlled_popen
#define nft_pclose controlled_pclose
#define spine_wait_readable controlled_wait
#define read controlled_read
#include "../../src/script/external.c"
#undef read
#undef spine_wait_readable
#undef nft_popen
#undef nft_pclose

static bool reject_upsert(MYSQL *destination, char *buffer, size_t capacity,
	const char *const *columns, size_t count) {
	(void) destination;
	(void) buffer;
	(void) capacity;
	(void) columns;
	(void) count;
	return FALSE;
}
#define db_upsert_suffix reject_upsert
#include "../../src/database/persistence.c"
#undef db_upsert_suffix

static void test_limited_read_outcomes(void **state) {
	host_t host = {.id = 1};
	script_result_context_t context = {&host, "fixture", 1, "DS"};
	char result[RESULTS_BUFFER];
	(void) state;
	set.php.script_max_output = 2;
	for (scenario = 0; scenario <= 6; scenario++) {
		calls = 0;
		memset(result, 0, sizeof(result));
		assert_int_equal(read_script_result(&context, -1, 1.0, result), scenario == 0 || scenario == 4);
		assert_string_equal(result, scenario == 0 || scenario == 4 ? "42" : "U");
	}
	set.php.script_max_output = 0;
	set.php.script_cpu_seconds = 2;
	scenario = calls = 0;
	assert_true(read_script_result(&context, -1, 1.0, result));
	assert_string_equal(result, "42");
}

static void test_suffix_failure_preserves_buffer_ownership(void **state) {
	poller_queries_t queries = {0};
	target_t item = {0};
	poll_output_buffers_t buffers;
	(void) state;
	strcpy(queries.output, "INSERT INTO poller_output VALUES");
	strcpy(queries.boost_output, "INSERT INTO poller_output_boost VALUES");
	set.boost.boost_enabled = set.boost.boost_redirect = TRUE;
	set.poller.poller_id = 2;
	set.poller.mode = REMOTE_ONLINE;
	buffers = write_poll_results(NULL, NULL, &queries, &item, 1, "1791676800");
	assert_true(buffers.failed);
	assert_non_null(buffers.output);
	assert_non_null(buffers.boost);
	free(buffers.output);
	free(buffers.boost);
}

static void *poll_with_pending_cancellation(void *argument) {
	host_t *host = argument;
	char *result = exec_poll(host, "/bin/echo 42", 1, "DS");
	free(result);
	pthread_testcancel();
	return NULL;
}

static void test_close_handoff_defers_cancellation(void **state) {
	host_t host = {.id = 1};
	pthread_t worker;
	void *result;
	int registered;
	(void) state;
	scenario = calls = handoff_disabled = 0;
	handoff_fd = -1;
	handoff_test = 1;
	set.php.script_timeout = 5;
	set.php.script_max_output = 2;
	set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);
	assert_int_equal(pthread_create(&worker, NULL, poll_with_pending_cancellation, &host), 0);
	assert_int_equal(pthread_join(worker, &result), 0);
	handoff_test = 0;
	registered = nft_pchild(handoff_fd);
	if (registered > 0) nft_pclose(handoff_fd);
	assert_ptr_equal(result, PTHREAD_CANCELED);
	assert_true(handoff_disabled);
	assert_int_equal(registered, -1);
	assert_int_equal(spine_permits_available(&available_scripts), 1);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {cmocka_unit_test(test_limited_read_outcomes), cmocka_unit_test(test_suffix_failure_preserves_buffer_ownership), cmocka_unit_test(test_close_handoff_defers_cancellation)};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
