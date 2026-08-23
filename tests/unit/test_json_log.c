/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | spine_json_escape() coverage. Guards the log / health-check JSON
 | emitters against crafted payload that would otherwise produce invalid
 | JSON (unescaped quote, newline, control byte).
 +-------------------------------------------------------------------------+
*/

#include <stddef.h>
#include <string.h>

#include "test_platform_helpers.h"

/* Forward declaration: avoid pulling in util.h, which transitively needs
 * the full spine MySQL headers. The function has no runtime dependencies
 * of its own, so a free-standing prototype is enough. */
extern char *spine_json_escape(char *dst, size_t dst_len, const char *src);

static void expect_escape(const char *src, const char *want) {
	char buf[256];
	spine_json_escape(buf, sizeof(buf), src);
	if (strcmp(buf, want) != 0) {
		ASSERT_TRUE_MSG(0, "json-escape mismatch");
	}
}

static void test_null_and_empty(void) {
	char buf[16];
	buf[0] = 'x';
	spine_json_escape(buf, sizeof(buf), NULL);
	ASSERT_INT_EQ((int) buf[0], 0);

	expect_escape("", "");
}

static void test_quote_and_backslash(void) {
	expect_escape("say \"hi\"", "say \\\"hi\\\"");
	expect_escape("a\\b",       "a\\\\b");
	expect_escape("\"\\",       "\\\"\\\\");
}

static void test_whitespace_controls(void) {
	expect_escape("line1\nline2", "line1\\nline2");
	expect_escape("a\rb",         "a\\rb");
	expect_escape("a\tb",         "a\\tb");
}

static void test_low_control_byte_uxxxx(void) {
	/* \x01 (SOH) must expand to \u0001, \x1f to \u001f. */
	expect_escape("\x01", "\\u0001");
	expect_escape("\x1f", "\\u001f");
	expect_escape("A\x07" "B", "A\\u0007B");
}

static void test_utf8_passthrough(void) {
	/* Multi-byte UTF-8 above 0x7F is left untouched: the escaper only
	 * rewrites ASCII control / quote / backslash. */
	expect_escape("caf\xc3\xa9", "caf\xc3\xa9");
	expect_escape("\xe2\x9a\xa0", "\xe2\x9a\xa0");
}

static void test_all_escapes(void) {
	expect_escape("\"\\\n\r\t", "\\\"\\\\\\n\\r\\t");
}

static void test_buffer_always_terminated(void) {
	char buf[4];
	buf[3] = 0x7f;
	spine_json_escape(buf, sizeof(buf), "abcdefghij");
	/* The escaper keeps room for up to 7-byte output growth and NUL, so
	 * with dst_len=4 it writes nothing but the terminator. */
	ASSERT_INT_EQ((int) buf[0], 0);
}

int main(void) {
	test_null_and_empty();
	test_quote_and_backslash();
	test_whitespace_controls();
	test_low_control_byte_uxxxx();
	test_utf8_passthrough();
	test_all_escapes();
	test_buffer_always_terminated();
	return finish_tests("json log tests");
}
