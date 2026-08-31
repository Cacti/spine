/*
 * Regression guard for issue#565.
 *
 * spine_log() bounds its two strncat() calls so the formatted message may fill
 * flogmessage exactly.  Appending the trailing newline unconditionally then put
 * the terminator one byte past a LOGSIZE stack buffer.  The append is now
 * bounded; these tests pin that down.
 *
 * As elsewhere in tests/unit the routine under test is copied here so this
 * translation unit links without MySQL, Net-SNMP or the spine globals.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

/* a stand-in for LOGSIZE; the predicate is size-independent */
#define TEST_LOGSIZE 64

/* ------------------------- copied from util.c ------------------------- */
static void append_newline(char *flogmessage, size_t flogmessage_size) {
	if (!strstr(flogmessage, "\n")) {
		size_t flogmessage_len = strlen(flogmessage);

		if (flogmessage_len < flogmessage_size - 1) {
			flogmessage[flogmessage_len]     = '\n';
			flogmessage[flogmessage_len + 1] = '\0';
		}
	}
}
/* ----------------------- end copied from util.c ----------------------- */

/* Guard byte immediately after the buffer, so an off-by-one is observable. */
struct guarded {
	char buf[TEST_LOGSIZE];
	char canary;
};

static void fill(struct guarded *g, size_t used) {
	memset(g, 0, sizeof(*g));
	memset(g->buf, 'x', used);
	g->buf[used] = '\0';
	g->canary = 0x7f;
}

static void test_full_buffer_is_left_alone(void **state) {
	struct guarded g;

	(void) state;

	/* TEST_LOGSIZE-1 characters plus the terminator: no room for a newline */
	fill(&g, TEST_LOGSIZE - 1);
	append_newline(g.buf, TEST_LOGSIZE);

	assert_int_equal(g.canary, 0x7f);
	assert_int_equal(strlen(g.buf), TEST_LOGSIZE - 1);
	assert_null(strchr(g.buf, '\n'));
}

static void test_one_byte_short_takes_the_newline(void **state) {
	struct guarded g;

	(void) state;

	fill(&g, TEST_LOGSIZE - 2);
	append_newline(g.buf, TEST_LOGSIZE);

	assert_int_equal(g.canary, 0x7f);
	assert_int_equal(strlen(g.buf), TEST_LOGSIZE - 1);
	assert_int_equal(g.buf[TEST_LOGSIZE - 2], '\n');
}

static void test_short_message_takes_the_newline(void **state) {
	struct guarded g;

	(void) state;

	fill(&g, 3);
	append_newline(g.buf, TEST_LOGSIZE);

	assert_int_equal(g.canary, 0x7f);
	assert_string_equal(g.buf, "xxx\n");
}

static void test_existing_newline_is_not_doubled(void **state) {
	struct guarded g;

	(void) state;

	memset(&g, 0, sizeof(g));
	strcpy(g.buf, "already\n");
	g.canary = 0x7f;

	append_newline(g.buf, TEST_LOGSIZE);

	assert_int_equal(g.canary, 0x7f);
	assert_string_equal(g.buf, "already\n");
}

static void test_empty_message(void **state) {
	struct guarded g;

	(void) state;

	fill(&g, 0);
	append_newline(g.buf, TEST_LOGSIZE);

	assert_int_equal(g.canary, 0x7f);
	assert_string_equal(g.buf, "\n");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_full_buffer_is_left_alone),
		cmocka_unit_test(test_one_byte_short_takes_the_newline),
		cmocka_unit_test(test_short_message_takes_the_newline),
		cmocka_unit_test(test_existing_newline_is_not_doubled),
		cmocka_unit_test(test_empty_message),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
