/* Production-linked sql.c tests with deterministic Connector/C responses. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "spine.h"
#include "sql.h"

static const char *controlled_query;
static unsigned int controlled_errors[8];
static int controlled_error_count;
static int controlled_error_index;
static unsigned int last_error;
static int query_calls;
static int sleep_calls;
static int close_calls;
static int free_result_calls;
static my_ulonglong num_rows;
static unsigned long thread_ids[8];
static int thread_id_count;
static int thread_id_index;
static MYSQL_RES *fake_result = (MYSQL_RES *)(uintptr_t)0x1234;

int __wrap_mysql_query(MYSQL *mysql, const char *query) {
	(void) mysql;
	query_calls++;
	last_error = 0;
	if (controlled_query != NULL && strcmp(query, controlled_query) == 0 &&
	    controlled_error_index < controlled_error_count) {
		last_error = controlled_errors[controlled_error_index++];
		return last_error == 0 ? 0 : 1;
	}
	return 0;
}

unsigned int __wrap_mysql_errno(MYSQL *mysql) {
	(void) mysql;
	return last_error;
}

const char *__wrap_mysql_error(MYSQL *mysql) {
	(void) mysql;
	return "injected Connector/C error";
}

MYSQL_RES *__wrap_mysql_store_result(MYSQL *mysql) {
	(void) mysql;
	return fake_result;
}

my_ulonglong __wrap_mysql_num_rows(MYSQL_RES *result) {
	assert_ptr_equal(result, fake_result);
	return num_rows;
}

void __wrap_mysql_free_result(MYSQL_RES *result) {
	assert_ptr_equal(result, fake_result);
	free_result_calls++;
}

unsigned long __wrap_mysql_thread_id(MYSQL *mysql) {
	(void) mysql;
	if (thread_id_index < thread_id_count) {
		return thread_ids[thread_id_index++];
	}
	return thread_id_count > 0 ? thread_ids[thread_id_count - 1] : 1;
}

int __wrap_mysql_ping(MYSQL *mysql) {
	(void) mysql;
	return 0;
}

void __wrap_mysql_close(MYSQL *mysql) {
	(void) mysql;
	close_calls++;
}

int __wrap_usleep(useconds_t usec) {
	(void) usec;
	sleep_calls++;
	return 0;
}

unsigned int __wrap_sleep(unsigned int seconds) {
	(void) seconds;
	sleep_calls++;
	return 0;
}

static int sql_reset(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	memset(controlled_errors, 0, sizeof(controlled_errors));
	memset(thread_ids, 0, sizeof(thread_ids));
	controlled_query = NULL;
	controlled_error_count = 0;
	controlled_error_index = 0;
	last_error = 0;
	query_calls = 0;
	sleep_calls = 0;
	close_calls = 0;
	free_result_calls = 0;
	num_rows = 0;
	thread_id_count = 0;
	thread_id_index = 0;
	errno = 0;
	set.log_destination = LOGDEST_STDOUT;
	set.threads = 2;
	init_mutexes();
	return 0;
}

static void test_insert_honors_read_only_mode(void **state) {
	MYSQL mysql;
	(void) state;
	set.SQL_readonly = TRUE;
	assert_int_equal(db_insert(&mysql, LOCAL, "INSERT readonly"), TRUE);
	assert_int_equal(query_calls, 0);
}

static void test_insert_success_and_permanent_error(void **state) {
	MYSQL mysql;
	(void) state;
	controlled_query = "INSERT test";
	assert_int_equal(db_insert(&mysql, LOCAL, controlled_query), TRUE);
	assert_int_equal(query_calls, 1);

	controlled_errors[0] = 1064;
	controlled_error_count = 1;
	controlled_error_index = 0;
	assert_int_equal(db_insert(&mysql, LOCAL, controlled_query), FALSE);
	assert_int_equal(query_calls, 2);
}

static void test_insert_retries_a_deadlock(void **state) {
	MYSQL mysql;
	(void) state;
	controlled_query = "INSERT retry";
	controlled_errors[0] = 1213;
	controlled_errors[1] = 0;
	controlled_error_count = 2;
	assert_int_equal(db_insert(&mysql, LOCAL, controlled_query), TRUE);
	assert_int_equal(controlled_error_index, 2);
	assert_int_equal(sleep_calls, 1);
}

static void test_insert_reconnects_and_retries_lost_connection(void **state) {
	MYSQL mysql;
	(void) state;
	controlled_query = "INSERT reconnect";
	controlled_errors[0] = 2006;
	controlled_errors[1] = 0;
	controlled_error_count = 2;
	thread_ids[0] = 10;
	thread_ids[1] = 11;
	thread_id_count = 2;
	assert_int_equal(db_insert(&mysql, REMOTE, controlled_query), TRUE);
	assert_int_equal(controlled_error_index, 2);
	assert_int_equal(thread_id_index, 2);
	assert_true(query_calls >= 9);
}

static void test_query_returns_the_connector_result(void **state) {
	MYSQL mysql;
	MYSQL_RES *result;
	(void) state;
	result = db_query(&mysql, LOCAL, "SELECT test");
	assert_ptr_equal(result, fake_result);
	assert_int_equal(query_calls, 1);
}

static void test_column_exists_releases_both_result_shapes(void **state) {
	MYSQL mysql;
	(void) state;
	num_rows = 1;
	assert_int_equal(db_column_exists(&mysql, LOCAL, "host", "id"), TRUE);
	num_rows = 0;
	assert_int_equal(db_column_exists(&mysql, LOCAL, "host", "missing"), FALSE);
	assert_int_equal(free_result_calls, 2);
}

static void test_pool_checkout_and_release(void **state) {
	pool_t *connection;
	(void) state;
	db_pool_local = calloc((size_t)set.threads, sizeof(*db_pool_local));
	db_pool_remote = calloc((size_t)set.threads, sizeof(*db_pool_remote));
	assert_non_null(db_pool_local);
	assert_non_null(db_pool_remote);
	db_pool_local[0].id = 7;
	db_pool_local[0].free = TRUE;
	db_pool_remote[1].id = 9;
	db_pool_remote[1].free = TRUE;

	connection = db_get_connection(LOCAL);
	assert_ptr_equal(connection, &db_pool_local[0]);
	assert_int_equal(connection->free, FALSE);
	db_release_connection(LOCAL, 0);
	assert_int_equal(connection->free, TRUE);

	connection = db_get_connection(REMOTE);
	assert_ptr_equal(connection, &db_pool_remote[1]);
	db_release_connection(REMOTE, 1);
	assert_int_equal(connection->free, TRUE);

	free(db_pool_local);
	free(db_pool_remote);
	db_pool_local = NULL;
	db_pool_remote = NULL;
}

static void test_pool_reports_exhaustion(void **state) {
	(void) state;
	db_pool_local = calloc((size_t)set.threads, sizeof(*db_pool_local));
	assert_non_null(db_pool_local);
	assert_null(db_get_connection(LOCAL));
	free(db_pool_local);
	db_pool_local = NULL;
}

static void test_disconnect_is_null_safe(void **state) {
	MYSQL mysql;
	(void) state;
	db_disconnect(NULL);
	assert_int_equal(close_calls, 0);
	db_disconnect(&mysql);
	assert_int_equal(close_calls, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_insert_honors_read_only_mode, sql_reset),
		cmocka_unit_test_setup(test_insert_success_and_permanent_error, sql_reset),
		cmocka_unit_test_setup(test_insert_retries_a_deadlock, sql_reset),
		cmocka_unit_test_setup(test_insert_reconnects_and_retries_lost_connection, sql_reset),
		cmocka_unit_test_setup(test_query_returns_the_connector_result, sql_reset),
		cmocka_unit_test_setup(test_column_exists_releases_both_result_shapes, sql_reset),
		cmocka_unit_test_setup(test_pool_checkout_and_release, sql_reset),
		cmocka_unit_test_setup(test_pool_reports_exhaustion, sql_reset),
		cmocka_unit_test_setup(test_disconnect_is_null_safe, sql_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
