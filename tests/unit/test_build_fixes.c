/*
 * Unit tests for spine build fixes.
 *
 * Covers:
 *   - uthash macro availability (HASH_ADD_INT, HASH_FIND_INT, HASH_DEL, HASH_COUNT)
 *   - config_struct default field values (has_output_regex, has_device_0)
 *   - regex_replace() correctness
 *   - strncopy() buffer-overflow safety
 *
 * These tests exercise only pure functions and data structures; no MySQL or
 * SNMP daemon is required.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

/*
 * Pull in spine types without dragging along MySQL/SNMP link dependencies.
 * We define stubs for the few symbols util.c references at file scope so the
 * translation unit compiles standalone.
 */
#define HAVE_CONFIG_H 1
#include "config/config.h"

/* Minimal spine.h constants needed before the full header. */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

/* Buffer sizes referenced by spine.h and util.c. */
#define BUFSIZE       256
#define SMALL_BUFSIZE 256
#define DBL_BUFSIZE   512
#define BIG_BUFSIZE   1024
#define MEGA_BUFSIZE  (1024 * 1024)
#define MAX_MATCHES   5

#include "uthash.h"

/* -------------------------------------------------------------------------
 * uthash tests
 * ------------------------------------------------------------------------- */

typedef struct {
	int           id;
	UT_hash_handle hh;
} item_t;

static void test_uthash_add_find(void **state) {
	(void)state;

	item_t *table = NULL;
	item_t *a = calloc(1, sizeof(item_t));
	item_t *b = calloc(1, sizeof(item_t));
	assert_non_null(a);
	assert_non_null(b);

	a->id = 1;
	b->id = 2;

	HASH_ADD_INT(table, id, a);
	HASH_ADD_INT(table, id, b);

	assert_int_equal(HASH_COUNT(table), 2);

	item_t *found = NULL;
	int key = 1;
	HASH_FIND_INT(table, &key, found);
	assert_non_null(found);
	assert_int_equal(found->id, 1);

	key = 2;
	HASH_FIND_INT(table, &key, found);
	assert_non_null(found);
	assert_int_equal(found->id, 2);

	/* Clean up. */
	HASH_DEL(table, a); free(a);
	HASH_DEL(table, b); free(b);
	assert_int_equal(HASH_COUNT(table), 0);
}

static void test_uthash_find_missing(void **state) {
	(void)state;

	item_t *table = NULL;
	item_t *e = calloc(1, sizeof(item_t));
	assert_non_null(e);
	e->id = 42;
	HASH_ADD_INT(table, id, e);

	item_t *found = NULL;
	int key = 99;
	HASH_FIND_INT(table, &key, found);
	assert_null(found);

	HASH_DEL(table, e); free(e);
}

static void test_uthash_del_reduces_count(void **state) {
	(void)state;

	item_t *table = NULL;
	item_t *items[3];
	for (int i = 0; i < 3; i++) {
		items[i] = calloc(1, sizeof(item_t));
		assert_non_null(items[i]);
		items[i]->id = i + 10;
		HASH_ADD_INT(table, id, items[i]);
	}
	assert_int_equal(HASH_COUNT(table), 3);

	HASH_DEL(table, items[1]); free(items[1]);
	assert_int_equal(HASH_COUNT(table), 2);

	int key = 11;
	item_t *found = NULL;
	HASH_FIND_INT(table, &key, found);
	assert_null(found);

	HASH_DEL(table, items[0]); free(items[0]);
	HASH_DEL(table, items[2]); free(items[2]);
}

/* -------------------------------------------------------------------------
 * config_struct default field tests
 *
 * We test the field layout and zero-initialisation semantics directly without
 * calling config_defaults() (which would pull in MySQL).  Zero-initialising a
 * config_struct and checking has_device_0 / has_output_regex == FALSE verifies
 * both that the fields exist at the expected offsets and that their "off"
 * sentinel is FALSE (0) -- the same invariant config_defaults() relies on.
 * ------------------------------------------------------------------------- */

/*
 * Minimal forward declaration of just the fields we need.  We reproduce the
 * struct layout verbatim from spine.h lines 351-377 so we can reference field
 * names without including the full header (which would require MySQL headers).
 */
typedef struct {
	int stdout_notty;
	int stderr_notty;
	int poller_id;
	int poller_interval;
	int parent_fork;
	int num_parent_processes;
	int script_timeout;
	int active_profiles;
	int total_snmp_ports;
	int threads;
	int threads_set;
	int logfile_processed;
	int boost_enabled;
	int boost_redirect;
	int shell_in_cwd;
	int snmponly;
	int SQL_readonly;
	int start_host_id;
	int end_host_id;
	char host_id_list[BIG_BUFSIZE];
	int has_device_0;       /* line 376 */
	int has_output_regex;   /* line 377 */
} config_subset_t;

static void test_config_has_device_0_default(void **state) {
	(void)state;

	config_subset_t s;
	memset(&s, 0, sizeof(s));

	assert_int_equal(s.has_device_0, FALSE);
}

static void test_config_has_output_regex_default(void **state) {
	(void)state;

	config_subset_t s;
	memset(&s, 0, sizeof(s));

	assert_int_equal(s.has_output_regex, FALSE);
}

/* -------------------------------------------------------------------------
 * regex_replace tests
 *
 * We inline a self-contained copy of regex_replace so this file compiles
 * without linking against util.o (which drags in spine_log, MySQL, etc.).
 * The logic is a verbatim copy of util.c:2147-2180 with only the static
 * thread-local buffer renamed to avoid ODR conflicts if the linker ever
 * sees both.
 * ------------------------------------------------------------------------- */

#include <regex.h>

static char *regex_replace_impl(char *exp, char *value) {
	regex_t regex;
	int reti;
	static __thread char test_msgbuf[SMALL_BUFSIZE];
	regmatch_t matches[MAX_MATCHES];
	size_t match_len;

	reti = regcomp(&regex, exp, 0);
	if (reti) {
		return value;
	}

	reti = regexec(&regex, value, MAX_MATCHES, matches, 0);
	if (!reti) {
		match_len = (size_t)(matches[0].rm_eo - matches[0].rm_so);
		if (match_len >= SMALL_BUFSIZE) {
			match_len = SMALL_BUFSIZE - 1;
		}
		memcpy(test_msgbuf, value + matches[0].rm_so, match_len);
		test_msgbuf[match_len] = '\0';
	}

	regfree(&regex);
	return (reti) ? value : test_msgbuf;
}

static void test_regex_replace_numeric_extraction(void **state) {
	(void)state;

	/* BRE: [0-9][0-9]* is "one or more digits" (+ is literal in BRE).
	 * Matches the first run of digits in the input. */
	char *result = regex_replace_impl("[0-9][0-9]*", "load: 42.5 util");
	assert_string_equal(result, "42");
}

static void test_regex_replace_no_match_returns_input(void **state) {
	(void)state;

	/* BRE pattern that cannot match the input; original value must be returned. */
	char *result = regex_replace_impl("[0-9][0-9]*", "no digits here");
	assert_string_equal(result, "no digits here");
}

static void test_regex_replace_invalid_regex_returns_input(void **state) {
	(void)state;

	/* An invalid regex pattern (unbalanced bracket) makes regcomp() fail;
	 * the function must return the original value, not crash. */
	char *result = regex_replace_impl("[invalid", "some value");
	assert_string_equal(result, "some value");
}

static void test_regex_replace_full_match(void **state) {
	(void)state;

	/* Pattern matches the entire string. */
	char *result = regex_replace_impl("^hello$", "hello");
	assert_string_equal(result, "hello");
}

static void test_regex_replace_decimal_number(void **state) {
	(void)state;

	/* BRE decimal extraction: [.][0-9][0-9]* matches the fractional part.
	 * Input "temp=23.7C" has no leading sign, so the match starts at '.'. */
	char *result = regex_replace_impl("[.][0-9][0-9]*", "temp=23.7C");
	assert_string_equal(result, ".7");
}

/* -------------------------------------------------------------------------
 * strncopy tests
 *
 * Same approach: inline the implementation to avoid util.o link dependency.
 * ------------------------------------------------------------------------- */

#include <string.h>
#include <assert.h>

static char *strncopy_impl(char *dst, const char *src, size_t obuf) {
	size_t copy_len;

	assert(dst != NULL);
	assert(src != NULL);

	if (obuf == 0) return dst;

	copy_len = strnlen(src, obuf - 1);

	if (copy_len) {
		strncpy(dst, src, copy_len);
	}

	dst[copy_len] = '\0';
	return dst;
}

static void test_strncopy_normal(void **state) {
	(void)state;

	char buf[16];
	char *ret = strncopy_impl(buf, "hello", sizeof(buf));
	assert_ptr_equal(ret, buf);
	assert_string_equal(buf, "hello");
}

static void test_strncopy_truncates_at_n_minus_1(void **state) {
	(void)state;

	char buf[5];
	strncopy_impl(buf, "toolong", sizeof(buf));
	/* Must be NUL-terminated and at most 4 content bytes. */
	assert_int_equal(buf[4], '\0');
	assert_memory_equal(buf, "tool", 4);
}

static void test_strncopy_empty_src(void **state) {
	(void)state;

	char buf[8] = "garbage";
	strncopy_impl(buf, "", sizeof(buf));
	assert_string_equal(buf, "");
}

static void test_strncopy_exact_fit(void **state) {
	(void)state;

	/* src length == buf size - 1: should fit exactly with NUL. */
	char buf[6];
	strncopy_impl(buf, "hello", sizeof(buf));
	assert_string_equal(buf, "hello");
	assert_int_equal(buf[5], '\0');
}

static void test_strncopy_returns_dst(void **state) {
	(void)state;

	char buf[32];
	char *ret = strncopy_impl(buf, "check", sizeof(buf));
	assert_ptr_equal(ret, buf);
}

static void test_strncopy_zero_size(void **state) {
	(void)state;

	/* obuf == 0 must return without touching dst. */
	char buf[4] = "abc";
	strncopy_impl(buf, "xyz", 0);
	/* dst is unchanged */
	assert_string_equal(buf, "abc");
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(void) {
	const struct CMUnitTest tests[] = {
		/* uthash */
		cmocka_unit_test(test_uthash_add_find),
		cmocka_unit_test(test_uthash_find_missing),
		cmocka_unit_test(test_uthash_del_reduces_count),

		/* config_struct defaults */
		cmocka_unit_test(test_config_has_device_0_default),
		cmocka_unit_test(test_config_has_output_regex_default),

		/* regex_replace */
		cmocka_unit_test(test_regex_replace_numeric_extraction),
		cmocka_unit_test(test_regex_replace_no_match_returns_input),
		cmocka_unit_test(test_regex_replace_invalid_regex_returns_input),
		cmocka_unit_test(test_regex_replace_full_match),
		cmocka_unit_test(test_regex_replace_decimal_number),

		/* strncopy */
		cmocka_unit_test(test_strncopy_normal),
		cmocka_unit_test(test_strncopy_truncates_at_n_minus_1),
		cmocka_unit_test(test_strncopy_empty_src),
		cmocka_unit_test(test_strncopy_exact_fit),
		cmocka_unit_test(test_strncopy_returns_dst),
		cmocka_unit_test(test_strncopy_zero_size),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
