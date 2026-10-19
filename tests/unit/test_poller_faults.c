/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* Reindex and regex-storage failure paths.
 *
 * reindex.c is compiled into the test so its static helpers can be driven
 * directly, with the allocators it calls redirected. Allocation failure ends
 * in die(), so those cases run in a child and the parent checks the exit
 * status. The thread-local storage calls behind regex_replace() are wrapped
 * at link time and fail only while armed.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "internal/common.h"
#include "app/spine.h"
#include "poller/poller_internal.h"
#include "tests/support/child_run.h"

static size_t failing_allocation;
static const char *failing_copy;
static int fail_once;
static int fail_key_create;
static int fail_setspecific;
static int setspecific_calls;

static void *controlled_malloc(size_t size) {
	if (size == failing_allocation) {
		failing_allocation = 0;
		return NULL;
	}
	return malloc(size);
}

static char *controlled_strdup(const char *text) {
	if (failing_copy != NULL && strcmp(text, failing_copy) == 0) {
		failing_copy = NULL;
		return NULL;
	}
	return strdup(text);
}

#define malloc controlled_malloc
#define strdup controlled_strdup
#include "../../src/poller/reindex.c"
#undef strdup
#undef malloc

int __real_pthread_once(pthread_once_t *once, void (*initializer)(void));
int __wrap_pthread_once(pthread_once_t *once, void (*initializer)(void)) {
	if (fail_once) return EINVAL;
	return __real_pthread_once(once, initializer);
}

int __real_pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
int __wrap_pthread_key_create(pthread_key_t *key, void (*destructor)(void *)) {
	if (fail_key_create) return EAGAIN;
	return __real_pthread_key_create(key, destructor);
}

int __real_pthread_setspecific(pthread_key_t key, const void *value);
int __wrap_pthread_setspecific(pthread_key_t key, const void *value) {
	setspecific_calls++;
	if (fail_setspecific) return ENOMEM;
	return __real_pthread_setspecific(key, value);
}

static int faults_setup(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	failing_allocation = 0;
	failing_copy = NULL;
	fail_once = FALSE;
	fail_key_create = FALSE;
	fail_setspecific = FALSE;
	setspecific_calls = 0;
	return 0;
}

static void test_unknown_assertion_operator_never_fails(void **state) {
	reindex_t reindex;

	(void) state;
	memset(&reindex, 0, sizeof(reindex));
	snprintf(reindex.op, sizeof(reindex.op), "~");
	snprintf(reindex.assert_value, sizeof(reindex.assert_value), "1");

	assert_false(reindex_assertion_failed(&reindex, "5"));
}

static void test_empty_script_command_yields_no_result(void **state) {
	host_t host = {.id = 1};
	reindex_t reindex;
	char uptime[BUFSIZE] = "";
	bool unavailable = FALSE;

	(void) state;
	memset(&reindex, 0, sizeof(reindex));
	reindex.action = POLLER_ACTION_SCRIPT;

	assert_null(poll_reindex_action(&host, &reindex, 1, uptime, &unavailable));
	assert_false(unavailable);
}

static void test_snmp_count_without_a_session_is_unknown(void **state) {
	host_t host = {.id = 1};
	reindex_t reindex;
	char uptime[BUFSIZE] = "";
	bool unavailable = FALSE;
	char *result;

	(void) state;
	memset(&reindex, 0, sizeof(reindex));
	reindex.action = POLLER_ACTION_SNMP_COUNT;
	snprintf(reindex.arg1, sizeof(reindex.arg1), ".1.3.6.1.2.1.2.2.1.1");

	result = poll_reindex_action(&host, &reindex, 1, uptime, &unavailable);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_true(host.ignore_host);
}

static host_t allocation_host;
static reindex_t allocation_reindex;

static void prepare_allocation_case(int action, const char *arg1) {
	memset(&allocation_host, 0, sizeof(allocation_host));
	memset(&allocation_reindex, 0, sizeof(allocation_reindex));
	allocation_host.id = 1;
	/* never dereferenced: every case fails before a request is built */
	allocation_host.snmp.session = (void *) (uintptr_t) 1;
	allocation_reindex.action = action;
	snprintf(allocation_reindex.arg1, sizeof(allocation_reindex.arg1), "%s", arg1);
}

static void run_reindex_action(void) {
	char uptime[BUFSIZE] = "";
	bool unavailable = FALSE;

	(void) poll_reindex_action(&allocation_host, &allocation_reindex, 1, uptime, &unavailable);
}

static void run_reindex_uptime_action(void) {
	char uptime[BUFSIZE] = "12345";
	bool unavailable = FALSE;

	(void) poll_reindex_action(&allocation_host, &allocation_reindex, 1, uptime, &unavailable);
}

static void test_reindex_result_allocation_failures_are_fatal(void **state) {
	static const int actions[] = {POLLER_ACTION_SNMP_COUNT, POLLER_ACTION_SCRIPT_COUNT, POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT};
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(actions) / sizeof(actions[0]); index++) {
		prepare_allocation_case(actions[index], "/bin/true");
		failing_allocation = BUFSIZE;
		print_message("action=%d\n", actions[index]);
		assert_int_equal(spine_test_run_child(run_reindex_action), EXIT_FAILURE);
	}

	prepare_allocation_case(POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.3.0");
	failing_allocation = BUFSIZE;
	assert_int_equal(spine_test_run_child(run_reindex_uptime_action), EXIT_FAILURE);
}

static void test_uptime_result_allocation_failure_is_fatal(void **state) {
	(void) state;
	prepare_allocation_case(POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.3.0");
	/* an ignored host answers U without a request, leaving no uptime to copy */
	allocation_host.ignore_host = TRUE;
	failing_copy = "U";

	assert_int_equal(spine_test_run_child(run_reindex_action), EXIT_FAILURE);
}

static void replace_with_a_match(void) {
	char value[] = "abc";

	(void) regex_replace("b", value);
}

static void test_regex_storage_failures_are_fatal(void **state) {
	(void) state;
	fail_once = TRUE;
	assert_int_equal(spine_test_run_child(replace_with_a_match), EXIT_FAILURE);
	fail_once = FALSE;

	fail_key_create = TRUE;
	assert_int_equal(spine_test_run_child(replace_with_a_match), EXIT_FAILURE);
	fail_key_create = FALSE;

	fail_setspecific = TRUE;
	assert_int_equal(spine_test_run_child(replace_with_a_match), EXIT_FAILURE);
}

static void *log_from_a_fresh_thread(void *argument) {
	(void) argument;
	spine_log("probe from a thread without log buffers");
	return NULL;
}

/* A thread whose log buffers cannot be attached still logs, from the stack. */
static void test_log_buffers_that_cannot_be_attached_are_released(void **state) {
	pthread_t thread;

	(void) state;
	set.logging.log_destination = LOGDEST_STDOUT;
	fail_setspecific = TRUE;
	assert_int_equal(pthread_create(&thread, NULL, log_from_a_fresh_thread, NULL), 0);
	assert_int_equal(pthread_join(thread, NULL), 0);
	fail_setspecific = FALSE;
	assert_true(setspecific_calls >= 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_unknown_assertion_operator_never_fails, faults_setup),
		cmocka_unit_test_setup(test_empty_script_command_yields_no_result, faults_setup),
		cmocka_unit_test_setup(test_snmp_count_without_a_session_is_unknown, faults_setup),
		cmocka_unit_test_setup(test_reindex_result_allocation_failures_are_fatal, faults_setup),
		cmocka_unit_test_setup(test_uptime_result_allocation_failure_is_fatal, faults_setup),
		cmocka_unit_test_setup(test_regex_storage_failures_are_fatal, faults_setup),
		cmocka_unit_test_setup(test_log_buffers_that_cannot_be_attached_are_released, faults_setup),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
