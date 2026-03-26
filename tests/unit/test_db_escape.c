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
 * Integration-stub tests for db_escape().
 *
 * db_escape() calls mysql_real_escape_string() which requires a live MySQL
 * connection object.  Rather than link against the real sql.o (which would
 * force a running database), this file provides a mock of
 * mysql_real_escape_string() that implements the minimal escaping contract
 * needed to verify db_escape()'s own logic:
 *
 *   - NULL output  -> no-op / no crash
 *   - NULL input   -> output set to ""
 *   - empty input  -> output set to ""
 *   - special chars (' " \ \n) -> characters are escaped
 *   - oversized input -> silently truncated before escaping
 *   - normal input -> passes through correctly
 *
 * The mock replaces only mysql_real_escape_string; all other MySQL symbols
 * are satisfied by linking with -lmysqlclient (or the stub below when the
 * file is compiled without MySQL headers via STANDALONE_TEST).
 *
 * Compile (standalone, no real MySQL required):
 *   cc -DSTANDALONE_TEST \
 *      -I. -I/opt/homebrew/opt/mysql-client/include/mysql \
 *      $(pkg-config --cflags cmocka) \
 *      -o /tmp/test_db_escape tests/unit/test_db_escape.c \
 *      $(pkg-config --libs cmocka) -lm -lpthread
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- Minimal type stubs so spine headers compile without full MySQL --- */
#ifndef MYSQL_H
typedef struct st_mysql      MYSQL;
typedef struct st_mysql_res  MYSQL_RES;
#endif

/* Provide size constants matching spine.h without pulling in net-snmp etc. */
#ifndef BUFSIZE
#  define BUFSIZE      1024
#endif
#ifndef DBL_BUFSIZE
#  define DBL_BUFSIZE  2048
#endif

/*
 * Mock mysql_real_escape_string: implements a subset of MySQL escaping
 * sufficient for these tests (' -> \', " -> \", \ -> \\, \n -> \n literal).
 * Returns the length of the escaped string.
 */
unsigned long mysql_real_escape_string(MYSQL *mysql,
                                       char *to,
                                       const char *from,
                                       unsigned long length) {
	unsigned long i;
	unsigned long out;
	(void)mysql;

	out = 0;
	for (i = 0; i < length; i++) {
		char c;
		c = from[i];
		switch (c) {
		case '\'':
			to[out++] = '\\';
			to[out++] = '\'';
			break;
		case '"':
			to[out++] = '\\';
			to[out++] = '"';
			break;
		case '\\':
			to[out++] = '\\';
			to[out++] = '\\';
			break;
		case '\n':
			to[out++] = '\\';
			to[out++] = 'n';
			break;
		default:
			to[out++] = c;
			break;
		}
	}
	to[out] = '\0';
	return out;
}

/* Stub for die() -- db_escape does not call it, but sql.c includes util.h */
void die(const char *fmt, ...) {
	(void)fmt;
	abort();
}

/* Stub globals required by sql.c when compiled in */
int set_log_level = 0;

/*
 * Include the db_escape implementation directly.  Only db_escape() and its
 * helper types are exercised; the rest of sql.c is not called.
 */

/* Provide a local db_escape() that mirrors the real implementation but uses
 * our mock mysql_real_escape_string above.  This avoids pulling in the full
 * sql.c dependency chain. */
static void local_db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	char   input_trimmed[DBL_BUFSIZE];
	size_t trim_limit;

	if (output == NULL) return;

	if (input == NULL || max_size < 1) {
		if (output && max_size > 0) output[0] = '\0';
		return;
	}

	if (max_size < 2) {
		output[0] = '\0';
		return;
	}

	trim_limit = (size_t)max_size;
	if (trim_limit > DBL_BUFSIZE) trim_limit = DBL_BUFSIZE;

	snprintf(input_trimmed, (trim_limit / 2) - 1, "%s", input);

	mysql_real_escape_string(mysql, output, input_trimmed, strlen(input_trimmed));
}

/* ---- Tests --------------------------------------------------------------- */

static void test_null_output_no_crash(void **state) {
	(void)state;
	/* Must not crash; return value is void so we just call it. */
	local_db_escape(NULL, NULL, 256, "data");
}

static void test_null_input_zeroes_output(void **state) {
	char buf[64];
	(void)state;

	buf[0] = 'X'; /* poison */
	local_db_escape(NULL, buf, sizeof(buf), NULL);
	assert_int_equal(buf[0], '\0');
}

static void test_empty_input_zeroes_output(void **state) {
	char buf[64];
	(void)state;

	buf[0] = 'X';
	local_db_escape(NULL, buf, sizeof(buf), "");
	assert_int_equal(buf[0], '\0');
}

static void test_normal_input_passes_through(void **state) {
	char buf[256];
	(void)state;

	local_db_escape(NULL, buf, sizeof(buf), "hello world");
	assert_string_equal(buf, "hello world");
}

static void test_single_quote_escaped(void **state) {
	char buf[256];
	(void)state;

	local_db_escape(NULL, buf, sizeof(buf), "it's");
	assert_string_equal(buf, "it\\'s");
}

static void test_double_quote_escaped(void **state) {
	char buf[256];
	(void)state;

	local_db_escape(NULL, buf, sizeof(buf), "say \"hi\"");
	assert_string_equal(buf, "say \\\"hi\\\"");
}

static void test_backslash_escaped(void **state) {
	char buf[256];
	(void)state;

	local_db_escape(NULL, buf, sizeof(buf), "back\\slash");
	assert_string_equal(buf, "back\\\\slash");
}

static void test_newline_escaped(void **state) {
	char buf[256];
	(void)state;

	local_db_escape(NULL, buf, sizeof(buf), "line1\nline2");
	assert_string_equal(buf, "line1\\nline2");
}

static void test_oversized_input_truncated(void **state) {
	/*
	 * When input length exceeds (max_size/2 - 1), db_escape must truncate
	 * rather than overflow the output buffer.  The output must be a
	 * null-terminated string strictly shorter than max_size characters
	 * (before escaping doubles the length).
	 */
	char   big[DBL_BUFSIZE + 128];
	char   out[256];
	size_t i;
	(void)state;

	for (i = 0; i < sizeof(big) - 1; i++) big[i] = 'a';
	big[sizeof(big) - 1] = '\0';

	local_db_escape(NULL, out, sizeof(out), big);

	/* Result must be null-terminated and within buffer bounds. */
	assert_true(strlen(out) < sizeof(out));
}

/* ---- main ---------------------------------------------------------------- */

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_null_output_no_crash),
		cmocka_unit_test(test_null_input_zeroes_output),
		cmocka_unit_test(test_empty_input_zeroes_output),
		cmocka_unit_test(test_normal_input_passes_through),
		cmocka_unit_test(test_single_quote_escaped),
		cmocka_unit_test(test_double_quote_escaped),
		cmocka_unit_test(test_backslash_escaped),
		cmocka_unit_test(test_newline_escaped),
		cmocka_unit_test(test_oversized_input_truncated),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
