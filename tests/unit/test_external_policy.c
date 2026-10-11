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
#define spine_wait_readable controlled_wait
#define read controlled_read
#include "../../src/script/external.c"
#undef read
#undef spine_wait_readable

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

int main(void) {
	const struct CMUnitTest tests[] = {cmocka_unit_test(test_limited_read_outcomes), cmocka_unit_test(test_suffix_failure_preserves_buffer_ownership)};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
