/* Remote-push batching tests against the shipped util.c implementation. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "spine.h"
#include "util.h"

#define HOST_ROWS 501
#define ITEM_ROWS 10001

static MYSQL_RES *host_result = (MYSQL_RES *)(uintptr_t)0x1000;
static MYSQL_RES *item_result = (MYSQL_RES *)(uintptr_t)0x2000;
static int query_index;
static int host_index;
static int item_index;
static int host_batches;
static int item_batches;
static int saw_host_boundary;
static int saw_item_boundary;
static int inserted_statements;

void __wrap_db_connect(int type, MYSQL *mysql) {
	(void) type;
	(void) mysql;
}

void __wrap_db_disconnect(MYSQL *mysql) {
	(void) mysql;
}

int __wrap_db_insert(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	inserted_statements++;
	if (strncmp(query, "INSERT INTO host ", strlen("INSERT INTO host ")) == 0) {
		host_batches++;
		if (strstr(query, "501, '") != NULL) saw_host_boundary = TRUE;
	} else if (strncmp(query, "INSERT INTO poller_item ", strlen("INSERT INTO poller_item ")) == 0) {
		item_batches++;
		if (strstr(query, "(10001, ") != NULL) saw_item_boundary = TRUE;
	}
	return TRUE;
}

MYSQL_RES *__wrap_db_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	(void) query;
	return query_index++ == 0 ? host_result : item_result;
}

void __wrap_db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	(void) mysql;
	if (output != NULL && max_size > 0) {
		snprintf(output, (size_t)max_size, "%s", input == NULL ? "" : input);
	}
}

void __wrap_db_free_result(MYSQL_RES *result) {
	(void) result;
}

my_ulonglong __wrap_mysql_num_rows(MYSQL_RES *result) {
	return result == host_result ? HOST_ROWS : ITEM_ROWS;
}

MYSQL_ROW __wrap_mysql_fetch_row(MYSQL_RES *result) {
	static char host_id[32];
	static char item_id[32];
	static char *host_row[21];
	static char *item_row[5];
	int i;

	if (result == host_result) {
		if (host_index >= HOST_ROWS) return NULL;
		host_index++;
		snprintf(host_id, sizeof(host_id), "%d", host_index);
		for (i = 0; i < 21; i++) host_row[i] = "1";
		host_row[0] = host_id;
		return host_row;
	}

	if (item_index >= ITEM_ROWS) return NULL;
	item_index++;
	snprintf(item_id, sizeof(item_id), "%d", item_index);
	for (i = 0; i < 5; i++) item_row[i] = "1";
	item_row[0] = item_id;
	return item_row;
}

static int reset(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	query_index = 0;
	host_index = 0;
	item_index = 0;
	host_batches = 0;
	item_batches = 0;
	saw_host_boundary = FALSE;
	saw_item_boundary = FALSE;
	inserted_statements = 0;
	set.poller_id = 2;
	set.mode = REMOTE_ONLINE;
	set.log_destination = LOGDEST_STDOUT;
	return 0;
}

static void test_batch_boundaries_do_not_drop_the_triggering_rows(void **state) {
	(void) state;
	poller_push_data_to_main();

	assert_int_equal(host_index, HOST_ROWS);
	assert_int_equal(item_index, ITEM_ROWS);
	assert_int_equal(host_batches, 2);
	assert_int_equal(item_batches, 2);
	assert_true(saw_host_boundary);
	assert_true(saw_item_boundary);
}

static void test_overflowed_batch_is_not_inserted(void **state) {
	MYSQL mysql;
	char *sqlbuf;
	char *cursor;
	int before;

	(void) state;
	sqlbuf = calloc(1, HUGE_BUFSIZE);
	assert_non_null(sqlbuf);
	cursor = sqlbuf + HUGE_BUFSIZE - 1;
	before = inserted_statements;

	push_flush_batch_test(&mysql, sqlbuf, &cursor, "suffix-does-not-fit");
	assert_int_equal(inserted_statements, before);
	free(sqlbuf);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_batch_boundaries_do_not_drop_the_triggering_rows, reset),
		cmocka_unit_test_setup(test_overflowed_batch_is_not_inserted, reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
