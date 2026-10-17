/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* Table tests for classify_result(), linked against the shipped util.c.
 *
 * Each row is a raw script or SNMP output, what Spine must decide it is, and
 * the exact text that reaches poller_output.  An output that cannot be read
 * as a whole value must come back as U, never as a guess.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "internal/common.h"
#include "app/spine.h"
#include "internal/util.h"

typedef struct {
	const char *raw;
	result_kind_t kind;
	const char *text;
} classify_case_t;

static const classify_case_t cases[] = {
	/* integers, including the padding scripts and BSD wc -l emit */
	{"42",                         RESULT_COUNTER,     "42"},
	{" 42",                        RESULT_COUNTER,     "42"},
	{"42\n",                       RESULT_COUNTER,     "42"},
	{"  10\n",                     RESULT_COUNTER,     "10"},
	{"42\r\n",                     RESULT_COUNTER,     "42"},
	{"\"42\"",                     RESULT_COUNTER,     "42"},
	{"'42'",                       RESULT_COUNTER,     "42"},
	{"+7",                         RESULT_COUNTER,     "+7"},
	{"-5",                         RESULT_SIGNED,      "-5"},
	{"18446744073709551615",       RESULT_COUNTER,     "18446744073709551615"},
	{"20000000000001",             RESULT_COUNTER,     "20000000000001"},
	{"-9223372036854775808",       RESULT_SIGNED,      "-9223372036854775808"},
	/* beyond 64 bits it is still a number, so the text is kept whole */
	{"18446744073709551616",       RESULT_FLOAT,       "18446744073709551616"},
	{"-9223372036854775809",       RESULT_FLOAT,       "-9223372036854775809"},

	/* floats */
	{"3.14",                       RESULT_FLOAT,       "3.14"},
	{"1.5e3",                      RESULT_FLOAT,       "1.5e3"},
	{".5",                         RESULT_FLOAT,       ".5"},
	{"-12.5",                      RESULT_FLOAT,       "-12.5"},
	{"1e999",                      RESULT_UNKNOWN,     "U"},

	/* strtod() accepts these; Cacti does not, and neither may we */
	{"0x1A",                       RESULT_UNKNOWN,     "U"},
	{"nan",                        RESULT_UNKNOWN,     "U"},
	{"NaN",                        RESULT_UNKNOWN,     "U"},
	{"inf",                        RESULT_UNKNOWN,     "U"},
	{"U",                          RESULT_UNKNOWN,     "U"},

	/* hex octet strings, converted without a double in between */
	{"1F FF FF FF FF FF FF F1",    RESULT_HEX_COUNTER, "2305843009213693937"},
	{"20 00 00 00 00 00 01",       RESULT_HEX_COUNTER, "9007199254740993"},
	{"FF FF FF FF FF FF FF FF",    RESULT_HEX_COUNTER, "18446744073709551615"},
	{"00 00 00 00 00 00 00 00 01", RESULT_HEX_COUNTER, "1"},
	{"AA-BB-CC",                   RESULT_HEX_COUNTER, "11189196"},
	{"\"FF ff\t\"",                RESULT_HEX_COUNTER, "65535"},
	{"01 FF FF FF FF FF FF FF FF", RESULT_UNKNOWN,     "U"},
	{"FFFFFFFFFFFFFFFF",           RESULT_UNKNOWN,     "U"},
	{"AA BB CC",                   RESULT_HEX_COUNTER, "11189196"},
	/* Cacti splits octets on space, '-' and ':' only */
	{"AA\tBB",                     RESULT_UNKNOWN,     "U"},
	{"zz",                         RESULT_UNKNOWN,     "U"},
	/* a lone octet is hex once it is not decimal, as in Cacti */
	{"FF",                         RESULT_HEX_COUNTER, "255"},
	{"ff",                         RESULT_HEX_COUNTER, "255"},
	{" FF",                        RESULT_HEX_COUNTER, "255"},
	{"0A",                         RESULT_HEX_COUNTER, "10"},
	{"1F",                         RESULT_HEX_COUNTER, "31"},
	{"9E",                         RESULT_HEX_COUNTER, "158"},
	{"00",                         RESULT_COUNTER,     "00"},

	/* nothing that could be a value */
	{"",                           RESULT_UNKNOWN,     "U"},
	{"   ",                        RESULT_UNKNOWN,     "U"},
	{"---",                        RESULT_UNKNOWN,     "U"},
	{"no sample",                  RESULT_UNKNOWN,     "U"},
	{"1.2.3",                      RESULT_UNKNOWN,     "U"},

	/* Cacti multipart output; it wins over hex, as it always has */
	{"a:1 b:2",                    RESULT_MULTIPART,   "a:1 b:2"},
	{"a:1 b!2",                    RESULT_MULTIPART,   "a:1 b!2"},
	{" a:1 b:2\n",                 RESULT_MULTIPART,   "a:1 b:2"},
	{"00:1b:44:11:3a:b7",          RESULT_MULTIPART,   "00:1b:44:11:3a:b7"},
	{"ff:ff:ff:ff:ff:ff:ff:ff",    RESULT_MULTIPART,   "ff:ff:ff:ff:ff:ff:ff:ff"},
	{"AA\tBB:CC",                  RESULT_MULTIPART,   "AA\tBB:CC"},
	{"a:1  b:2",                   RESULT_UNKNOWN,     "U"},

	/* a number wrapped in text, which Cacti's strip_alpha() also accepts */
	{"4096 Bytes",                 RESULT_COUNTER,     "4096"},
	{"text -12.5 Bytes",           RESULT_FLOAT,       "-12.5"},
	/* once read as the octets 0x042C */
	{"-42C",                       RESULT_SIGNED,      "-42"},
};

static void test_classify_table(void **state) {
	(void) state;

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		classified_result_t out;
		char raw[64];

		/* classify a copy, then check the copy is untouched */
		strncopy(raw, cases[i].raw, sizeof(raw));
		result_kind_t kind = classify_result(raw, &out);
		print_message("case %zu: '%s'\n", i, cases[i].raw);
		assert_int_equal(kind, cases[i].kind);
		assert_int_equal(out.kind, cases[i].kind);
		assert_string_equal(out.text, cases[i].text);
		assert_string_equal(raw, cases[i].raw);
	}
}

static void test_classify_values(void **state) {
	classified_result_t out;
	(void) state;

	assert_int_equal(classify_result("18446744073709551615", &out), RESULT_COUNTER);
	assert_true(out.value.counter == UINT64_MAX);
	assert_int_equal(classify_result("-9223372036854775808", &out), RESULT_SIGNED);
	assert_true(out.value.integer == INT64_MIN);
	assert_int_equal(classify_result("1.5e3", &out), RESULT_FLOAT);
	assert_true(out.value.real == 1500.0);
	/* 2^53 + 1 has no exact double; the octet path must not use one */
	assert_int_equal(classify_result("20 00 00 00 00 00 01", &out), RESULT_HEX_COUNTER);
	assert_true(out.value.counter == 9007199254740993ULL);
	assert_int_equal(classify_result("  10\n", &out), RESULT_COUNTER);
	assert_true(out.value.counter == 10);
	assert_int_equal(classify_result(NULL, &out), RESULT_UNKNOWN);
	assert_string_equal(out.text, "U");
}

static void test_classify_longer_than_results_buffer(void **state) {
	char *raw = malloc(RESULTS_BUFFER * 2);
	classified_result_t out;
	(void) state;

	assert_non_null(raw);

	/* Truncating a long value would store a different one. */
	memset(raw, '7', RESULTS_BUFFER + 10);
	raw[RESULTS_BUFFER + 10] = '\0';
	assert_int_equal(classify_result(raw, &out), RESULT_UNKNOWN);
	assert_string_equal(out.text, "U");

	memset(raw, 'a', RESULTS_BUFFER + 10);
	raw[1] = ':';
	assert_int_equal(classify_result(raw, &out), RESULT_UNKNOWN);

	/* Padding does not count against the buffer. */
	memset(raw, ' ', RESULTS_BUFFER + 10);
	raw[RESULTS_BUFFER] = '4';
	raw[RESULTS_BUFFER + 1] = '2';
	assert_int_equal(classify_result(raw, &out), RESULT_COUNTER);
	assert_string_equal(out.text, "42");

	/* A short value behind a long run of padding is still that value. */
	memset(raw, ' ', RESULTS_BUFFER + 10);
	raw[RESULTS_BUFFER + 8] = 'f';
	raw[RESULTS_BUFFER + 9] = 'f';
	assert_int_equal(classify_result(raw, &out), RESULT_HEX_COUNTER);
	assert_string_equal(out.text, "255");

	/* The longest storable value still fits. */
	memset(raw, 'a', RESULTS_BUFFER - 1);
	raw[1] = ':';
	raw[RESULTS_BUFFER - 1] = '\0';
	assert_int_equal(classify_result(raw, &out), RESULT_MULTIPART);
	assert_int_equal(strlen(out.text), RESULTS_BUFFER - 1);

	free(raw);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_classify_table),
		cmocka_unit_test(test_classify_values),
		cmocka_unit_test(test_classify_longer_than_results_buffer),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
