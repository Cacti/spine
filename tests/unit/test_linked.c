/* Unit tests that exercise the shipped objects.
 *
 * The other test binaries in this directory inline the function under test, or
 * replicate its predicate, so they compile standalone.  That keeps them cheap
 * but means a fix can land in util.c while the test still passes against the
 * old copy.  This binary links the real translation units instead, with
 * tests/fuzz/stubs.c supplying the globals that spine.c would otherwise define,
 * so what runs here is what ships.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"
#include "util.h"

/* --- strncopy(): issue#447, the off-by-one when src fills the destination -- */

static void test_strncopy_truncates_within_the_buffer(void **state) {
	struct { char dst[8]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strncopy(b.dst, "ABCDEFGHIJK", sizeof b.dst);

	assert_string_equal(b.dst, "ABCDEFG");
	assert_int_equal(strlen(b.dst), sizeof b.dst - 1);
	assert_int_equal(b.canary, 0xAA);
}

static void test_strncopy_copies_a_short_source_whole(void **state) {
	char dst[16];
	(void) state;

	memset(dst, 0xAA, sizeof dst);
	strncopy(dst, "abc", sizeof dst);
	assert_string_equal(dst, "abc");
}

static void test_strncopy_handles_a_zero_size(void **state) {
	char dst[4] = {'z', 'z', 'z', '\0'};
	(void) state;

	strncopy(dst, "abc", 0);
	assert_string_equal(dst, "zzz");
}

static void test_strncopy_terminates_an_exact_fit(void **state) {
	struct { char dst[4]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strncopy(b.dst, "abc", sizeof b.dst);

	assert_string_equal(b.dst, "abc");
	assert_int_equal(b.canary, 0xAA);
}

/* --- regex_replace(): returns the match, or the input when it cannot ------- */

static void test_regex_replace_returns_the_match(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[0-9][0-9]*", "load 42 avg"), "42");
}

static void test_regex_replace_passes_through_on_no_match(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[0-9][0-9]*", "no digits"), "no digits");
}

static void test_regex_replace_passes_through_on_bad_pattern(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[unclosed", "value"), "value");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_strncopy_truncates_within_the_buffer),
		cmocka_unit_test(test_strncopy_copies_a_short_source_whole),
		cmocka_unit_test(test_strncopy_handles_a_zero_size),
		cmocka_unit_test(test_strncopy_terminates_an_exact_fit),
		cmocka_unit_test(test_regex_replace_returns_the_match),
		cmocka_unit_test(test_regex_replace_passes_through_on_no_match),
		cmocka_unit_test(test_regex_replace_passes_through_on_bad_pattern),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
