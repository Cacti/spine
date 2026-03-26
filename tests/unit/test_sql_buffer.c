/*
 * Unit tests for the sql_buffer_t dynamic SQL buffer.
 *
 * Covers:
 *   - sql_buffer_init / sql_buffer_free lifecycle
 *   - sql_buffer_append normal writes and reallocation
 *   - overflow guard: requests exceeding SQL_MAX_BUFFER_CAPACITY must fail
 *
 * Self-contained: the sql_buffer_t type and sql_buffer_append are stubbed
 * inline so this file compiles without MySQL or SNMP headers.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Maximum buffer size the production code enforces. */
#ifndef SQL_MAX_BUFFER_CAPACITY
#define SQL_MAX_BUFFER_CAPACITY (64 * 1024 * 1024)  /* 64 MiB */
#endif

/* -------------------------------------------------------------------------
 * Minimal sql_buffer_t stub matching the production interface.
 *
 * The production sql_buffer_append checks SQL_MAX_BUFFER_CAPACITY twice:
 *   1. Before doubling: if required_capacity already exceeds the cap, fail.
 *   2. After doubling:  if the doubled new_capacity wraps or overflows, fail.
 *
 * The stub here mirrors that logic exactly so tests remain meaningful when
 * the real implementation is later linked in.
 * ------------------------------------------------------------------------- */

typedef struct {
	char   *buffer;
	size_t  length;
	size_t  capacity;
} sql_buffer_t;

static int sql_buffer_init(sql_buffer_t *sb, size_t initial_capacity) {
	if (sb == NULL || initial_capacity == 0) return -1;

	sb->buffer = (char *)malloc(initial_capacity);
	if (sb->buffer == NULL) return -1;

	sb->buffer[0] = '\0';
	sb->length    = 0;
	sb->capacity  = initial_capacity;
	return 0;
}

static void sql_buffer_free(sql_buffer_t *sb) {
	if (sb == NULL) return;
	free(sb->buffer);
	sb->buffer   = NULL;
	sb->length   = 0;
	sb->capacity = 0;
}

static int sql_buffer_append(sql_buffer_t *sb, const char *format, ...) {
	va_list args;
	va_list args_copy;
	int     written;
	size_t  available;
	size_t  required_capacity;
	size_t  new_capacity;
	char   *new_buffer;

	if (sb == NULL || format == NULL) return -1;

	va_start(args, format);
	va_copy(args_copy, args);

	available = sb->capacity - sb->length;
	written   = vsnprintf(sb->buffer + sb->length, available, format, args);
	va_end(args);

	if (written < 0) {
		va_end(args_copy);
		return -1;
	}

	if ((size_t)written >= available) {
		required_capacity = sb->length + (size_t)written + 1;
		if (required_capacity > SQL_MAX_BUFFER_CAPACITY) {
			va_end(args_copy);
			return -1;
		}

		new_capacity = sb->capacity;
		while (new_capacity < required_capacity) new_capacity *= 2;

		if (new_capacity > SQL_MAX_BUFFER_CAPACITY) {
			va_end(args_copy);
			return -1;
		}

		new_buffer = (char *)realloc(sb->buffer, new_capacity);
		if (new_buffer == NULL) {
			va_end(args_copy);
			return -1;
		}

		sb->buffer   = new_buffer;
		sb->capacity = new_capacity;

		written = vsnprintf(sb->buffer + sb->length, sb->capacity - sb->length, format, args_copy);
	}
	va_end(args_copy);

	sb->length += (size_t)written;
	return 0;
}

/* -------------------------------------------------------------------------
 * Tests
 * ------------------------------------------------------------------------- */

static void test_sql_buffer_init(void **state) {
	(void)state;

	sql_buffer_t sb;
	int ret = sql_buffer_init(&sb, 1024);
	assert_int_equal(ret, 0);
	assert_int_equal((int)sb.capacity, 1024);
	assert_int_equal((int)sb.length, 0);
	assert_int_equal(sb.buffer[0], '\0');
	sql_buffer_free(&sb);
}

static void test_sql_buffer_append_simple(void **state) {
	(void)state;

	sql_buffer_t sb;
	sql_buffer_init(&sb, 16);

	int ret = sql_buffer_append(&sb, "%s", "hello");
	assert_int_equal(ret, 0);
	assert_int_equal((int)sb.length, 5);
	assert_string_equal(sb.buffer, "hello");

	sql_buffer_free(&sb);
}

static void test_sql_buffer_append_triggers_realloc(void **state) {
	(void)state;

	sql_buffer_t sb;
	sql_buffer_init(&sb, 16);

	int ret = sql_buffer_append(&sb, "%s", "hello");
	assert_int_equal(ret, 0);

	/* Force a reallocation: append a string longer than remaining capacity. */
	ret = sql_buffer_append(&sb, " world. This is a longer string that will force a reallocation.");
	assert_int_equal(ret, 0);
	assert_true(sb.length > 15);
	assert_true(sb.capacity > 16);

	sql_buffer_free(&sb);
}

static void test_sql_buffer_append_overflow_rejected(void **state) {
	(void)state;

	sql_buffer_t sb;
	sql_buffer_init(&sb, 64);

	/* Fabricate a request that would exceed SQL_MAX_BUFFER_CAPACITY.
	 * We do this by pre-filling length to just below the cap and then
	 * requesting one more byte than remains allowed. */
	sb.length = SQL_MAX_BUFFER_CAPACITY - 4;

	/* required_capacity = length + strlen("hello") + 1 = cap + 2, over limit. */
	int ret = sql_buffer_append(&sb, "%s", "hello");
	assert_int_equal(ret, -1);

	/* length must be unchanged: the guard must not modify the buffer. */
	assert_int_equal((int)sb.length, (int)(SQL_MAX_BUFFER_CAPACITY - 4));

	sql_buffer_free(&sb);
}

static void test_sql_buffer_free_null_safe(void **state) {
	(void)state;

	/* Must not crash on NULL. */
	sql_buffer_free(NULL);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_sql_buffer_init),
		cmocka_unit_test(test_sql_buffer_append_simple),
		cmocka_unit_test(test_sql_buffer_append_triggers_realloc),
		cmocka_unit_test(test_sql_buffer_append_overflow_rejected),
		cmocka_unit_test(test_sql_buffer_free_null_safe),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
