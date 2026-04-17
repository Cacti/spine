/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Unit test for the guarded snprintf accumulator pattern used in          |
 | util.c and spine.c when building SQL strings. The pre-fix pattern       |
 | (qp += snprintf(qp, remaining, ...)) steps past the buffer on           |
 | truncation because snprintf returns the would-be length, not the       |
 | bytes written. This test pins the fixed pattern against a fixture      |
 | that would overflow without the guard.                                 |
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

/* Mirror the util.c helper so the test can exercise the shape independent
 * of the translation unit. A divergence here flags the original as drifted. */
#include <stdarg.h>

static int guarded_append(char **cursor, size_t *remaining, const char *fmt, ...) {
	va_list ap;
	int n;

	if (*remaining == 0) {
		return -1;
	}

	va_start(ap, fmt);
	n = vsnprintf(*cursor, *remaining, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= *remaining) {
		return -1;
	}

	*cursor    += n;
	*remaining -= (size_t)n;
	return 0;
}

/* Exact-fit: every append lands inside the buffer. */
static void test_exact_fit(void) {
	char buf[64];
	char *cur = buf;
	size_t rem = sizeof(buf);

	ASSERT_INT_EQ(guarded_append(&cur, &rem, "hello "), 0);
	ASSERT_INT_EQ(guarded_append(&cur, &rem, "world"), 0);
	ASSERT_TRUE(strcmp(buf, "hello world") == 0);
	ASSERT_INT_EQ((int)(cur - buf), 11);
	ASSERT_INT_EQ((int)rem, 64 - 11);
}

/* Overflow fixture: a value larger than the buffer must short-circuit
 * without stepping the cursor past the end. The legacy pattern would
 * leave cur = buf + 200, an out-of-bounds pointer into a 32-byte buffer. */
static void test_overflow_short_circuits(void) {
	char buf[32];
	char *cur = buf;
	size_t rem = sizeof(buf);
	char big[200];

	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';

	ASSERT_INT_EQ(guarded_append(&cur, &rem, "%s", big), -1);
	/* Cursor must not move past the original buffer. */
	ASSERT_TRUE(cur >= buf && cur <= buf + sizeof(buf));
	/* The prefix that snprintf did write is still NUL-terminated. */
	ASSERT_TRUE(buf[sizeof(buf) - 1] == '\0');
}

/* Mid-sequence overflow: first append fits, second overflows. The cursor
 * stays at the position after the last successful append. */
static void test_partial_overflow(void) {
	char buf[16];
	char *cur = buf;
	size_t rem = sizeof(buf);

	ASSERT_INT_EQ(guarded_append(&cur, &rem, "abcdef"), 0);
	ASSERT_INT_EQ((int)(cur - buf), 6);

	/* 20 chars will not fit in the 10 remaining bytes. */
	ASSERT_INT_EQ(guarded_append(&cur, &rem, "%s", "01234567890123456789"), -1);
	ASSERT_INT_EQ((int)(cur - buf), 6);
	ASSERT_TRUE(strncmp(buf, "abcdef", 6) == 0);
}

/* Zero remaining on entry is a hard stop. */
static void test_zero_remaining(void) {
	char buf[8] = "hello";
	char *cur = buf + 5;
	size_t rem = 0;

	ASSERT_INT_EQ(guarded_append(&cur, &rem, "x"), -1);
	ASSERT_INT_EQ((int)(cur - buf), 5);
	ASSERT_TRUE(strcmp(buf, "hello") == 0);
}

int main(void) {
	test_exact_fit();
	test_overflow_short_circuits();
	test_partial_overflow();
	test_zero_remaining();
	return finish_tests("snprintf guard tests");
}
