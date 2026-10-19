/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* Worker dispatch: permit waits, device partitioning and storage setup.
 *
 * workers.c is compiled into the test so its static helpers can be called and
 * the permit, thread-start, database and allocator calls it makes can be
 * scripted. No thread is started and no database is contacted.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "internal/common.h"
#include "app/spine.h"
#include "platform/worker_set.h"
#include "tests/support/child_run.h"

#define FAKE_ROWS 4

typedef struct {
	const char *cells[FAKE_ROWS][2];
	int count;
	int next;
	int freed;
} fake_result_t;

static fake_result_t fake_result;
static fake_result_t count_result;
static const char *count_cell;
static int permit_errors[16];
static int permit_error_count;
static int permit_error_next;
static const spine_permits_t *failing_permit;
static int start_statuses[8];
static int start_status_count;
static int start_calls;
static size_t failing_allocation;
static size_t failing_array_count;

static int controlled_try_acquire(spine_permits_t *permits) {
	if (failing_permit != NULL && permits == failing_permit) return EAGAIN;
	if (permit_error_next < permit_error_count) return permit_errors[permit_error_next++];
	return spine_permits_try_acquire(permits);
}

static int controlled_start(spine_worker_set_t *workers, const pthread_attr_t *attributes,
	void *(*function)(void *), void *argument) {
	int status = start_calls < start_status_count ? start_statuses[start_calls] : 0;

	(void) workers;
	(void) attributes;
	(void) function;
	start_calls++;
	/* the worker thread would own and free its instructions */
	if (status == 0) free(argument);
	return status;
}

static MYSQL_RES *controlled_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	(void) query;
	if (count_cell == NULL) return NULL;
	memset(&count_result, 0, sizeof(count_result));
	/* an empty string stands for a COUNT() query that returned no row */
	count_result.count = count_cell[0] == '\0' ? 0 : 1;
	count_result.cells[0][0] = count_cell;
	return (MYSQL_RES *) &count_result;
}

static MYSQL_ROW controlled_fetch_row(MYSQL_RES *opaque) {
	static const char *row[2];
	fake_result_t *result = (fake_result_t *) opaque;

	if (result->next >= result->count) return NULL;
	row[0] = result->cells[result->next][0];
	row[1] = result->cells[result->next][1];
	result->next++;
	return (MYSQL_ROW) row;
}

static uint64_t controlled_num_rows(MYSQL_RES *opaque) {
	return (uint64_t) ((fake_result_t *) opaque)->count;
}

static void controlled_free_result(MYSQL_RES *opaque) {
	((fake_result_t *) opaque)->freed++;
}

static void *controlled_malloc(size_t size) {
	if (size == failing_allocation) {
		failing_allocation = 0;
		return NULL;
	}
	return malloc(size);
}

static void *controlled_calloc(size_t count, size_t size) {
	if (count == failing_array_count && size == sizeof(poller_thread_t *)) {
		failing_array_count = 0;
		return NULL;
	}
	return calloc(count, size);
}

#define spine_permits_try_acquire controlled_try_acquire
#define spine_worker_set_start controlled_start
#define db_query controlled_query
#define mysql_fetch_row controlled_fetch_row
#define mysql_num_rows controlled_num_rows
#define db_free_result controlled_free_result
#define malloc controlled_malloc
#define calloc controlled_calloc
#include "../../src/poller/workers.c"
#undef calloc
#undef malloc
#undef db_free_result
#undef mysql_num_rows
#undef mysql_fetch_row
#undef db_query
#undef spine_worker_set_start
#undef spine_permits_try_acquire

static int workers_setup(void **state) {
	(void) state;
	config_defaults();
	init_mutexes();
	memset(&fake_result, 0, sizeof(fake_result));
	count_cell = NULL;
	permit_error_count = 0;
	permit_error_next = 0;
	failing_permit = NULL;
	start_status_count = 0;
	start_calls = 0;
	failing_allocation = 0;
	failing_array_count = 0;
	set.poller.poller_interval = 300;
	set.poller.poller_id = 2;
	start_time = get_time_as_double();
	assert_int_equal(spine_permits_init(&available_threads, 1), 0);
	return 0;
}

static int workers_teardown(void **state) {
	(void) state;
	spine_permits_destroy(&available_threads);
	return 0;
}

/* Ten refusals in a row, including errors that are not plain contention, are
 * waited out while the poll interval has room for it. */
static void test_permit_wait_survives_a_run_of_refusals(void **state) {
	(void) state;
	permit_errors[0] = EDEADLK;
	permit_errors[1] = EIO;
	for (int i = 2; i < 10; i++) permit_errors[i] = EAGAIN;
	permit_error_count = 10;

	assert_true(wait_for_worker_permit(&available_threads, 1, 1, "Available Thread Lock"));
	assert_int_equal(permit_error_next, 10);
}

static void test_permit_wait_gives_up_when_the_interval_is_spent(void **state) {
	(void) state;
	failing_permit = &available_threads;
	set.poller.poller_interval = 1;

	/* the tenth refusal comes 0.1 s in, and a further full second of waiting
	 * would not fit in a one second interval */
	assert_false(wait_for_worker_permit(&available_threads, 1, 1, "Available Thread Lock"));

	/* an interval that ended before the wait began stops it at the first sleep */
	set.poller.poller_interval = 5;
	start_time = get_time_as_double() - 10;
	assert_false(wait_for_worker_permit(&available_threads, 1, 1, "Available Thread Lock"));
}

static void test_startup_permit_failure_returns_the_thread_permit(void **state) {
	spine_permits_t startup;

	(void) state;
	assert_int_equal(spine_permits_init(&startup, 1), 0);
	failing_permit = &startup;
	start_time = get_time_as_double() - 10;
	set.poller.poller_interval = 5;

	assert_false(acquire_worker_permits(&startup, 1, 1));
	assert_int_equal(spine_permits_available(&available_threads), 1);
	spine_permits_destroy(&startup);
}

static void test_worker_start_fails_the_run_when_no_permit_arrives(void **state) {
	poller_thread_t device = {.host_id = 7};
	spine_worker_set_t workers = {0};
	spine_permits_t startup;
	pthread_attr_t attributes;

	(void) state;
	assert_int_equal(spine_permits_init(&startup, 1), 0);
	assert_int_equal(pthread_attr_init(&attributes), 0);
	failing_permit = &available_threads;
	start_time = get_time_as_double() - 10;
	set.poller.poller_interval = 5;
	set.exit.exit_code = EXIT_SUCCESS;

	assert_false(start_poll_worker(&device, 1, &startup, &attributes, &workers));
	assert_int_equal(set.exit.exit_code, EXIT_FAILURE);
	assert_int_equal(start_calls, 0);
	pthread_attr_destroy(&attributes);
	spine_permits_destroy(&startup);
}

static void count_with_no_rows(void) {
	MYSQL mysql;

	count_cell = "";
	(void) count_partition_items(&mysql, 1, 1, FALSE);
}

static void test_missing_item_count_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(count_with_no_rows), EXIT_FAILURE);
}

static void test_device_partition_sizes(void **state) {
	poller_partition_t partition;
	char timestamp[SMALL_BUFSIZE] = "";
	MYSQL mysql;

	(void) state;
	memset(&mysql, 0, sizeof(mysql));

	/* ping-only polling is one thread, whatever the device asked for */
	set.availability.ping_only = TRUE;
	count_cell = "9";
	memset(&partition, 0, sizeof(partition));
	partition.threads = 4;
	partition.timestamp = timestamp;
	prepare_device_partition(&mysql, 5, 1, &partition);
	assert_int_equal(partition.threads, 1);
	assert_int_equal(partition.items, 9);

	/* a later thread of a split device stamps the start time if none exists */
	set.availability.ping_only = FALSE;
	set.poller.active_profiles = 1;
	count_cell = "12";
	memset(&partition, 0, sizeof(partition));
	partition.threads = 4;
	partition.timestamp = timestamp;
	prepare_device_partition(&mysql, 5, 2, &partition);
	assert_int_equal(partition.threads, 4);
	assert_true(partition.time > 0);
	assert_true(strlen(timestamp) > 0);
}

static void test_worker_completion_reports_failed_and_missing_devices(void **state) {
	poller_thread_t first = {.host_id = 1, .host_thread = 1, .host_data_ids = 3, .complete = TRUE, .output_failed = TRUE};
	poller_thread_t second = {.host_id = 2, .host_thread = 1, .host_data_ids = 3, .poll_failed = TRUE};
	poller_thread_t *table[3] = {&first, &second, NULL};
	poller_thread_t **saved = details;

	(void) state;
	set.availability.ping_only = FALSE;
	details = table;
	report_worker_completion(3);
	details = saved;
	/* the report only logs; it must leave the device records alone */
	assert_true(first.output_failed);
	assert_true(second.poll_failed);
	assert_false(second.complete);

	set.availability.ping_only = TRUE;
	details = NULL;
	report_worker_completion(3);
	details = saved;
}

static void test_storage_counts_the_non_device_source_for_poller_one(void **state) {
	char *host_time = NULL;
	int *ids = NULL;
	int rows = 0;

	(void) state;
	fake_result.count = 3;
	set.poller.poller_id = 1;
	set.hosts.has_device_0 = TRUE;

	prepare_worker_storage((MYSQL_RES *) &fake_result, &rows, &ids, &host_time);
	assert_int_equal(rows, 4);
	assert_non_null(details);
	assert_non_null(ids);
	assert_non_null(host_time);
	free_worker_storage(rows, ids, NULL, host_time);
	details = NULL;
}

static void prepare_storage_for_seven_rows(void) {
	char *host_time = NULL;
	int *ids = NULL;
	int rows = 0;

	fake_result.count = 7;
	prepare_worker_storage((MYSQL_RES *) &fake_result, &rows, &ids, &host_time);
	/* only reached if no allocation failed */
	free_worker_storage(rows, ids, NULL, host_time);
}

static void test_storage_allocation_failures_are_fatal(void **state) {
	(void) state;
	failing_array_count = 7;
	assert_int_equal(spine_test_run_child(prepare_storage_for_seven_rows), EXIT_FAILURE);

	/* a child's one-shot fault does not clear in the parent */
	failing_array_count = 0;
	failing_allocation = 7 * sizeof(int);
	assert_int_equal(spine_test_run_child(prepare_storage_for_seven_rows), EXIT_FAILURE);

	failing_allocation = SMALL_BUFSIZE;
	assert_int_equal(spine_test_run_child(prepare_storage_for_seven_rows), EXIT_FAILURE);
}

static void fill_device_rows(void) {
	memset(&fake_result, 0, sizeof(fake_result));
	fake_result.count = 2;
	fake_result.cells[0][0] = "5";
	fake_result.cells[0][1] = "0";
	fake_result.cells[1][0] = "6";
	fake_result.cells[1][1] = "1";
}

static void test_launch_dispatches_one_worker_per_device(void **state) {
	pthread_attr_t attributes;
	spine_worker_set_t workers = {0};
	spine_permits_t startup;
	char host_time[SMALL_BUFSIZE] = "";
	poller_thread_t *table[3] = {NULL, NULL, NULL};
	poller_thread_t **saved = details;
	MYSQL mysql;

	(void) state;
	memset(&mysql, 0, sizeof(mysql));
	assert_int_equal(spine_permits_init(&startup, 3), 0);
	assert_int_equal(pthread_attr_init(&attributes), 0);
	assert_int_equal(spine_permits_destroy(&available_threads), 0);
	assert_int_equal(spine_permits_init(&available_threads, 3), 0);
	set.poller.poller_id = 1;
	set.hosts.has_device_0 = TRUE;
	set.poller.threads = 3;
	count_cell = "4";
	fill_device_rows();
	details = table;

	/* device 0 first, then the two listed devices; a thread count below one
	 * still means one thread */
	launch_poll_workers(&mysql, (MYSQL_RES *) &fake_result, 3, &workers, &startup, &attributes, host_time);
	assert_int_equal(start_calls, 3);
	assert_non_null(table[0]);
	assert_int_equal(table[0]->host_id, 0);
	assert_int_equal(table[1]->host_id, 5);
	assert_int_equal(table[1]->host_threads, 1);
	assert_int_equal(table[2]->host_id, 6);

	for (int i = 0; i < 3; i++) free(table[i]);
	details = saved;
	pthread_attr_destroy(&attributes);
	spine_permits_destroy(&startup);
}

static void launch_with_no_instruction_memory(void) {
	pthread_attr_t attributes;
	spine_worker_set_t workers = {0};
	spine_permits_t startup;
	char host_time[SMALL_BUFSIZE] = "";
	poller_thread_t *table[2] = {NULL, NULL};
	MYSQL mysql;

	memset(&mysql, 0, sizeof(mysql));
	spine_permits_init(&startup, 2);
	pthread_attr_init(&attributes);
	count_cell = "4";
	fill_device_rows();
	details = table;
	failing_allocation = sizeof(poller_thread_t);
	launch_poll_workers(&mysql, (MYSQL_RES *) &fake_result, 2, &workers, &startup, &attributes, host_time);
}

static void test_launch_allocation_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(launch_with_no_instruction_memory), EXIT_FAILURE);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_permit_wait_survives_a_run_of_refusals, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_permit_wait_gives_up_when_the_interval_is_spent, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_startup_permit_failure_returns_the_thread_permit, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_worker_start_fails_the_run_when_no_permit_arrives, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_missing_item_count_is_fatal, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_device_partition_sizes, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_worker_completion_reports_failed_and_missing_devices, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_storage_counts_the_non_device_source_for_poller_one, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_storage_allocation_failures_are_fatal, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_launch_dispatches_one_worker_per_device, workers_setup, workers_teardown),
		cmocka_unit_test_setup_teardown(test_launch_allocation_failure_is_fatal, workers_setup, workers_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
