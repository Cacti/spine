/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.     |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit tests for STRDUP_OR_DIE, MALLOC_OR_DIE, and CALLOC_OR_DIE macros.
 *
 * The die() path cannot be exercised in unit tests because it terminates
 * the process.  These tests cover the success paths only.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * Provide a stub die() so that util.h's macro definitions resolve without
 * dragging in the real implementation, which pulls in MySQL/SNMP headers.
 * We declare it noreturn-compatible but make it abort() so a test that
 * accidentally reaches the failure branch produces a clear failure instead
 * of a silent hang.
 */
static void stub_die(const char *fmt, ...) {
	(void)fmt;
	abort();
}

/*
 * Re-define the macros from util.h against our stub, avoiding the need to
 * compile in all of spine's heavyweight dependencies.
 */
#define STRDUP_OR_DIE(dst, src, reason) \
	do { \
		if (((dst) = strdup(src)) == NULL) { \
			stub_die("FATAL: malloc() failed during strdup() for %s", reason); \
		} \
	} while (0)

#define MALLOC_OR_DIE(dst, type, size, reason) \
	do { \
		if (((dst) = (type *)malloc(size)) == NULL) { \
			stub_die("FATAL: malloc() failed during allocation of %s", reason); \
		} \
	} while (0)

#define CALLOC_OR_DIE(dst, type, count, size, reason) \
	do { \
		if (((dst) = (type *)calloc(count, size)) == NULL) { \
			stub_die("FATAL: calloc() failed during allocation of %s", reason); \
		} \
	} while (0)

/* ----- STRDUP_OR_DIE ---------------------------------------------------- */

static void test_strdup_returns_nonnull(void **state) {
	char *p;
	(void)state;

	STRDUP_OR_DIE(p, "hello", "test");
	assert_non_null(p);
	free(p);
}

static void test_strdup_copies_content(void **state) {
	char *p;
	const char *src;
	(void)state;

	src = "test string";
	STRDUP_OR_DIE(p, src, "test");

	assert_string_equal(p, src);
	/* pointer must differ: we have an independent copy */
	assert_ptr_not_equal(p, src);
	free(p);
}

static void test_strdup_empty_string(void **state) {
	char *p;
	(void)state;

	STRDUP_OR_DIE(p, "", "empty");
	assert_non_null(p);
	assert_string_equal(p, "");
	free(p);
}

/* ----- MALLOC_OR_DIE ------------------------------------------------------ */

static void test_malloc_returns_nonnull(void **state) {
	int *p;
	(void)state;

	MALLOC_OR_DIE(p, int, sizeof(int) * 4, "int array");
	assert_non_null(p);
	free(p);
}

static void test_malloc_size_is_usable(void **state) {
	unsigned char *p;
	size_t i;
	size_t n;
	(void)state;

	n = 64;
	MALLOC_OR_DIE(p, unsigned char, n, "byte buffer");
	assert_non_null(p);

	/* Write and read back every byte to confirm the allocation is live. */
	for (i = 0; i < n; i++) p[i] = (unsigned char)(i & 0xff);
	for (i = 0; i < n; i++) assert_int_equal(p[i], (int)(i & 0xff));
	free(p);
}

/* ----- CALLOC_OR_DIE ------------------------------------------------------ */

static void test_calloc_returns_nonnull(void **state) {
	int *p;
	(void)state;

	CALLOC_OR_DIE(p, int, 4, sizeof(int), "int array");
	assert_non_null(p);
	free(p);
}

static void test_calloc_zeroes_memory(void **state) {
	unsigned char *p;
	size_t i;
	size_t n;
	(void)state;

	n = 128;
	CALLOC_OR_DIE(p, unsigned char, n, sizeof(unsigned char), "byte buffer");
	assert_non_null(p);

	/* calloc guarantees zero-initialisation. */
	for (i = 0; i < n; i++) assert_int_equal(p[i], 0);
	free(p);
}

static void test_calloc_struct_zeroed(void **state) {
	typedef struct { int a; long b; double c; } sample_t;
	sample_t *p;
	(void)state;

	CALLOC_OR_DIE(p, sample_t, 1, sizeof(sample_t), "sample_t");
	assert_non_null(p);
	assert_int_equal(p->a, 0);
	assert_int_equal(p->b, 0L);
	/* floating-point zero has an all-bits-zero representation on IEEE 754 */
	assert_int_equal(p->c == 0.0, 1);
	free(p);
}

/* ----- main --------------------------------------------------------------- */

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_strdup_returns_nonnull),
		cmocka_unit_test(test_strdup_copies_content),
		cmocka_unit_test(test_strdup_empty_string),
		cmocka_unit_test(test_malloc_returns_nonnull),
		cmocka_unit_test(test_malloc_size_is_usable),
		cmocka_unit_test(test_calloc_returns_nonnull),
		cmocka_unit_test(test_calloc_zeroes_memory),
		cmocka_unit_test(test_calloc_struct_zeroed),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
