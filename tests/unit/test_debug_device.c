/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Unit tests for add_debug_device / is_debug_device (uthash)             |
 +-------------------------------------------------------------------------+
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "uthash.h"

/* stub spine_log and die */
int spine_log(const char *format, ...) { (void)format; return 0; }
void die(const char *format, ...) { (void)format; exit(1); }

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

#ifndef CALLOC_OR_DIE
#define CALLOC_OR_DIE(dst, type, count, size, reason) \
	do { \
		if (((dst) = (type *)calloc(count, size)) == NULL) { \
			die("FATAL: calloc() failed for %s", reason); \
		} \
	} while (0)
#endif

/* inline the uthash-based debug device tracking from util.c */
typedef struct debug_device_s {
	int device_id;
	UT_hash_handle hh;
} debug_device_t;

static debug_device_t *debug_devices_hash = NULL;

void add_debug_device(int device_id) {
	debug_device_t *d;

	if (device_id <= 0) return;

	HASH_FIND_INT(debug_devices_hash, &device_id, d);

	if (d == NULL) {
		CALLOC_OR_DIE(d, debug_device_t, 1, sizeof(debug_device_t), "test debug_device_t");
		d->device_id = device_id;
		HASH_ADD_INT(debug_devices_hash, device_id, d);
	}
}

int is_debug_device(int device_id) {
	debug_device_t *d;

	if (device_id <= 0) return FALSE;

	HASH_FIND_INT(debug_devices_hash, &device_id, d);

	return (d != NULL) ? TRUE : FALSE;
}

static void clear_hash(void) {
	debug_device_t *d;
	debug_device_t *tmp;
	HASH_ITER(hh, debug_devices_hash, d, tmp) {
		HASH_DEL(debug_devices_hash, d);
		free(d);
	}
}

static int teardown(void **state) {
	(void)state;
	clear_hash();
	return 0;
}

static void test_no_debug_devices(void **state) {
	(void)state;
	assert_int_equal(is_debug_device(1), FALSE);
	assert_int_equal(is_debug_device(100), FALSE);
}

static void test_add_and_find(void **state) {
	(void)state;
	add_debug_device(42);
	assert_int_equal(is_debug_device(42), TRUE);
	assert_int_equal(is_debug_device(43), FALSE);
}

static void test_multiple_devices(void **state) {
	(void)state;
	add_debug_device(10);
	add_debug_device(20);
	add_debug_device(30);
	assert_int_equal(is_debug_device(10), TRUE);
	assert_int_equal(is_debug_device(20), TRUE);
	assert_int_equal(is_debug_device(30), TRUE);
	assert_int_equal(is_debug_device(15), FALSE);
}

static void test_device_zero_rejected(void **state) {
	(void)state;
	add_debug_device(0);
	assert_int_equal(is_debug_device(0), FALSE);
}

static void test_negative_device_rejected(void **state) {
	(void)state;
	add_debug_device(-5);
	assert_int_equal(is_debug_device(-5), FALSE);
}

static void test_duplicate_add_safe(void **state) {
	(void)state;
	add_debug_device(42);
	add_debug_device(42);
	assert_int_equal(is_debug_device(42), TRUE);
	/* no double-add crash */
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_no_debug_devices, teardown),
		cmocka_unit_test_teardown(test_add_and_find, teardown),
		cmocka_unit_test_teardown(test_multiple_devices, teardown),
		cmocka_unit_test_teardown(test_device_zero_rejected, teardown),
		cmocka_unit_test_teardown(test_negative_device_rejected, teardown),
		cmocka_unit_test_teardown(test_duplicate_add_safe, teardown),
	};
	return cmocka_run_group_tests_name("debug_device", tests, NULL, NULL);
}
