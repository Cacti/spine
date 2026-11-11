/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "internal/common.h"
#include "app/spine.h"
#include "tests/support/child_run.h"

static int scenario;
static int calls;
static int wait_errno;
static int sleeps;
static size_t failing_allocation;
static int controlled_wait(int fd, double deadline) {
	(void) fd;
	(void) deadline;
	if (scenario == 1) {
		errno = wait_errno != 0 ? wait_errno : EBADF;
		return -1;
	}
	return scenario == 2 ? 0 : 1;
}
/* Counts any retry sleep external.c makes; a blocking permit wait makes none. */
__attribute__((unused)) static void counted_sleep(unsigned int microseconds) {
	sleeps++;
	spine_sleep_usec(microseconds);
}
static void *controlled_malloc(size_t size) {
	if (size == failing_allocation) {
		failing_allocation = 0;
		return NULL;
	}
	return malloc(size);
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
/* Starts the script directly while the policy stays set, so a test can
 * apply a resource policy without the resource helper binary. */
static int popen_without_helper;
static int controlled_popen(const char *command, const char *type) {
	unsigned int cpu_seconds = set.php.script_cpu_seconds;
	unsigned int memory_mb = set.php.script_memory_mb;
	int fd;
	if (popen_without_helper) set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	fd = nft_popen(command, type);
	set.php.script_cpu_seconds = cpu_seconds;
	set.php.script_memory_mb = memory_mb;
	if (handoff_test) handoff_fd = fd;
	return fd;
}
static int controlled_pclose(int fd, double deadline) {
	int previous;
	if (handoff_test) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
		handoff_disabled = previous == PTHREAD_CANCEL_DISABLE;
		pthread_setcancelstate(previous, NULL);
		pthread_cancel(pthread_self());
		pthread_testcancel();
	}
	return nft_pclose_deadline(fd, deadline);
}
#define nft_popen controlled_popen
#define nft_pclose_deadline controlled_pclose
#define spine_wait_readable controlled_wait
#define read controlled_read
#define spine_sleep_usec counted_sleep
#define malloc controlled_malloc
#include "../../src/script/external.c"
#undef malloc
#undef spine_sleep_usec
#undef read
#undef spine_wait_readable
#undef nft_popen
#undef nft_pclose_deadline

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

/* Without output limits the reader takes the plain select() path, which names
 * the failure and leaves the item undefined. */
static void test_unlimited_read_reports_wait_failures(void **state) {
	host_t host = {.id = 1};
	script_result_context_t context = {&host, "fixture", 1, "DS"};
	const int failures[] = {EBADF, EINVAL, EIO};
	char result[RESULTS_BUFFER];
	size_t index;
	(void) state;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	scenario = 1;
	for (index = 0; index < sizeof(failures) / sizeof(failures[0]); index++) {
		wait_errno = failures[index];
		memset(result, 0, sizeof(result));
		assert_false(read_script_result(&context, -1, 1.0, result));
		assert_string_equal(result, "U");
	}
	wait_errno = 0;
	scenario = 0;
}

static void test_timeout_without_a_registered_child_is_undefined(void **state) {
	host_t host = {.id = 1};
	script_result_context_t context = {&host, "fixture", 1, "DS"};
	char result[RESULTS_BUFFER];
	(void) state;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	scenario = 2;
	memset(result, 0, sizeof(result));
	assert_false(read_script_result(&context, -1, 1.0, result));
	assert_string_equal(result, "U");
	scenario = 0;
}

static void *return_script_permit(void *unused) {
	(void) unused;
	spine_sleep_usec(50000);
	assert_int_equal(spine_permits_release(&available_scripts), 0);
	return NULL;
}

/* A script waiting for a permit sleeps on it and runs once another script
 * returns one; with none returned it gives up within its budget. */
static void test_script_waits_for_a_returned_permit(void **state) {
	host_t host = {.id = 1};
	pthread_t releaser;
	char *result;
	double begin;
	(void) state;
	scenario = calls = sleeps = 0;
	set.php.script_timeout = 5;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 0), 0);
	assert_int_equal(pthread_create(&releaser, NULL, return_script_permit, NULL), 0);

	result = exec_poll(&host, "/bin/echo 42", 1, "DS");
	assert_string_equal(result, "42");
	free(result);
	assert_int_equal(sleeps, 0);
	assert_int_equal(pthread_join(releaser, NULL), 0);
	assert_int_equal(spine_permits_available(&available_scripts), 1);

	/* 15 tries 10 ms apart per second of timeout, less the first sleep */
	assert_int_equal(spine_permits_try_acquire(&available_scripts), 0);
	set.php.script_timeout = 1;
	begin = spine_monotonic_time();
	result = exec_poll(&host, "/bin/echo 42", 1, "DS");
	assert_string_equal(result, "U");
	free(result);
	assert_true(spine_monotonic_time() - begin >= 0.13);
	assert_int_equal(spine_permits_available(&available_scripts), 0);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

static void poll_with_no_result_buffer(void) {
	host_t host = {.id = 1};

	failing_allocation = RESULTS_BUFFER;
	free(exec_poll(&host, "/bin/echo 42", 1, "DS"));
}

static void test_result_allocation_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(poll_with_no_result_buffer), EXIT_FAILURE);
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

/* Long arguments or an over-long executable path are an invalid item. Building
 * the /usr/bin/ candidate used to terminate Spine on the formatting guard. */
static void test_long_command_is_an_invalid_item(void **state) {
	host_t host = {.id = 1};
	char command[BUFSIZE + 200];
	char *result;
	(void) state;
	set.php.script_timeout = 5;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);

	memset(command, 'x', sizeof(command) - 1);
	command[sizeof(command) - 1] = '\0';
	memcpy(command, "spine_no_such_tool ", strlen("spine_no_such_tool "));
	result = exec_poll(&host, command, 1, "DS");
	assert_string_equal(result, "U");
	free(result);

	command[0] = '/';
	memset(command + 1, 'x', sizeof(command) - 2);
	result = exec_poll(&host, command, 1, "DS");
	assert_string_equal(result, "U");
	free(result);

	assert_int_equal(spine_permits_available(&available_scripts), 1);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

/* Under a resource policy a script may print its value, close stdout and
 * keep working. It must be allowed to finish inside script_timeout instead
 * of being killed at EOF. */
static void test_script_finishes_after_closing_its_output(void **state) {
	host_t host = {.id = 1};
	char directory[] = "spine-script-grace-XXXXXX";
	char saved[64];
	char command[256];
	char *result;
	(void) state;
	scenario = calls = 0;
	set.php.script_timeout = 5;
	set.php.script_max_output = 2;
	set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);
	assert_non_null(mkdtemp(directory));
	snprintf(saved, sizeof(saved), "%s/saved", directory);
	snprintf(command, sizeof(command), "/bin/echo 42; exec >&-; sleep 0.05; echo saved > %s", saved);

	set.php.script_cpu_seconds = 5;
	popen_without_helper = TRUE;
	result = exec_poll(&host, command, 1, "DS");
	popen_without_helper = FALSE;
	set.php.script_cpu_seconds = 0;
	assert_string_equal(result, "42");
	free(result);
	assert_int_equal(access(saved, F_OK), 0);
	assert_int_equal(unlink(saved), 0);
	assert_int_equal(rmdir(directory), 0);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

/* The grace period ends at the script deadline: a script that never exits,
 * even one that ignores SIGTERM, is still killed and reaped. */
static void test_lingering_script_is_bounded_by_its_deadline(void **state) {
	host_t host = {.id = 1};
	double start;
	char *result;
	int attempts;
	(void) state;
	scenario = calls = 0;
	set.php.script_timeout = 1;
	set.php.script_max_output = 2;
	set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);

	start = spine_monotonic_time();
	set.php.script_cpu_seconds = 5;
	popen_without_helper = TRUE;
	result = exec_poll(&host, "/bin/echo 42; exec >&-; trap '' TERM; while :; do sleep 1; done", 1, "DS");
	popen_without_helper = FALSE;
	set.php.script_cpu_seconds = 0;
	assert_true(spine_monotonic_time() - start < set.php.script_timeout + 1.0);
	assert_string_equal(result, "U");
	free(result);
	for (attempts = 0; attempts < 100 && nft_abandoned_pending() != 0; attempts++) usleep(20000);
	assert_int_equal(nft_abandoned_pending(), 0);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

/* An output cap alone is enforced by the read: the exit status stays
 * unused, so a script that prints its value and exits non-zero, or keeps
 * running after closing stdout, keeps its value and is not waited for. */
static void test_output_cap_alone_ignores_the_exit_status(void **state) {
	host_t host = {.id = 1};
	double start;
	char *result;
	int attempts;
	(void) state;
	scenario = calls = 0;
	set.php.script_timeout = 2;
	set.php.script_max_output = 8;
	set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);

	/* read() is the fixture's: the first call of each poll returns "42" */
	result = exec_poll(&host, "/bin/echo 42; exit 3", 1, "DS");
	assert_string_equal(result, "42");
	free(result);

	calls = 0;
	start = spine_monotonic_time();
	result = exec_poll(&host, "/bin/echo 42; exec 1>&-; sleep 3", 1, "DS");
	assert_true(spine_monotonic_time() - start < 0.5);
	assert_string_equal(result, "42");
	free(result);

	set.php.script_max_output = 0;
	for (attempts = 0; attempts < 200 && nft_abandoned_pending() != 0; attempts++) usleep(20000);
	assert_int_equal(nft_abandoned_pending(), 0);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

/* Without a resource policy the exit status is unused, so a script that
 * prints, closes stdout and keeps running is killed shortly after its value
 * is read. Waiting for it to script_timeout held the thread and a script
 * permit: this case took 1.98 s instead of 0.06 s. */
static void test_unlimited_lingering_script_is_not_waited_for(void **state) {
	host_t host = {.id = 1};
	double start;
	double elapsed;
	char *result;
	int attempts;
	(void) state;
	scenario = calls = 0;
	set.php.script_timeout = 2;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert_int_equal(spine_permits_init(&available_scripts, 1), 0);

	start = spine_monotonic_time();
	result = exec_poll(&host, "/bin/echo 5; exec 1>&-; sleep 3", 1, "DS");
	elapsed = spine_monotonic_time() - start;
	print_message("lingering unlimited script took %.3f s\n", elapsed);
	assert_true(elapsed < 0.5);
	assert_string_equal(result, "42");
	free(result);
	assert_int_equal(spine_permits_available(&available_scripts), 1);
	for (attempts = 0; attempts < 100 && nft_abandoned_pending() != 0; attempts++) usleep(20000);
	assert_int_equal(nft_abandoned_pending(), 0);
	assert_int_equal(spine_permits_destroy(&available_scripts), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {cmocka_unit_test(test_limited_read_outcomes), cmocka_unit_test(test_unlimited_read_reports_wait_failures), cmocka_unit_test(test_timeout_without_a_registered_child_is_undefined), cmocka_unit_test(test_script_waits_for_a_returned_permit), cmocka_unit_test(test_result_allocation_failure_is_fatal),
		cmocka_unit_test(test_suffix_failure_preserves_buffer_ownership), cmocka_unit_test(test_close_handoff_defers_cancellation), cmocka_unit_test(test_long_command_is_an_invalid_item),
		cmocka_unit_test(test_script_finishes_after_closing_its_output), cmocka_unit_test(test_lingering_script_is_bounded_by_its_deadline),
		cmocka_unit_test(test_output_cap_alone_ignores_the_exit_status),
		cmocka_unit_test(test_unlimited_lingering_script_is_not_waited_for)};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
