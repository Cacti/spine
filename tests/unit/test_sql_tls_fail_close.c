/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | H4 TLS fail-close regression guard.
 |
 | The full end-to-end behaviour (set.db_ssl=1 on a libmysqlclient without
 | MYSQL_OPT_SSL_MODE and without MYSQL_OPT_SSL_VERIFY_SERVER_CERT must
 | die() before mysql_real_connect()) is hard to exercise without a mock
 | libmysqlclient; every host CI toolchain ships one connector with a
 | specific feature mix. Instead we pin the invariant structurally: the
 | SSL code path in src/sql.c must contain a die() call that fires when
 | ssl_setting >= 1 and neither verify-server-cert nor ssl-mode is
 | compiled in, and a post-connect cipher check that die()s on a NULL
 | cipher. If a future refactor drops either guard, this test fails at
 | build time via ctest, which is the layer CI actually runs.
 |
 | The "compile-time" assertion here is source-level: we open the real
 | src/sql.c, scan for the required tokens, and assert_fail if any are
 | missing. This is deliberately blunt so the check stays cheap and does
 | not depend on a full mysql client stub.
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

#ifndef SPINE_SQL_C_PATH
#  define SPINE_SQL_C_PATH "src/sql.c"
#endif

static char *slurp(const char *path) {
	FILE *fp = fopen(path, "rb");
	if (fp == NULL) {
		fprintf(stderr, "cannot open %s: ", path);
		perror("");
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		fclose(fp);
		return NULL;
	}
	long size = ftell(fp);
	if (size < 0) {
		fclose(fp);
		return NULL;
	}
	rewind(fp);
	char *buf = (char *)malloc((size_t)size + 1);
	if (buf == NULL) {
		fclose(fp);
		return NULL;
	}
	size_t got = fread(buf, 1, (size_t)size, fp);
	fclose(fp);
	buf[got] = '\0';
	return buf;
}

static int contains(const char *haystack, const char *needle) {
	return strstr(haystack, needle) != NULL ? 1 : 0;
}

static void test_fail_close_die_on_missing_verify_option(void) {
	char *src = slurp(SPINE_SQL_C_PATH);
	ASSERT_TRUE(src != NULL);
	if (src == NULL) return;

	/* The `#if !defined(HAS_MYSQL_OPT_SSL_MODE) && !defined(HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT)`
	 * guard must exist and must gate a die() call. Matching the two
	 * distinctive tokens separately is enough; collapsing them into a
	 * single multi-line regex would add fragility without catching more
	 * regressions. */
	ASSERT_TRUE(contains(src,
		"!defined(HAS_MYSQL_OPT_SSL_MODE) && !defined(HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT)"));
	ASSERT_TRUE(contains(src,
		"refusing to connect"));

	/* mysql_ssl_set must be wired in the TLS-requested branch; without
	 * it older connectors never send CLIENT_SSL on the wire. */
	ASSERT_TRUE(contains(src, "mysql_ssl_set(mysql"));

	/* Post-connect cipher probe -- mysql_get_ssl_cipher() == NULL means
	 * the session is plaintext and we must die. */
	ASSERT_TRUE(contains(src, "mysql_get_ssl_cipher(mysql)"));
	ASSERT_TRUE(contains(src, "refusing to continue"));

	free(src);
}

static void test_ssl_options_gated_on_ssl_setting(void) {
	char *src = slurp(SPINE_SQL_C_PATH);
	ASSERT_TRUE(src != NULL);
	if (src == NULL) return;

	/* Regression guard: the MYSQL_OPT_SSL_KEY / CA / CERT options must
	 * only be set when TLS is actually requested. The structural shape
	 * we pin is "if (ssl_setting == 0)" as the plaintext short-circuit
	 * followed by an else branch that owns the MYSQL_OPT_SSL_KEY call.
	 * If someone hoists the options back out of the else, this fails. */
	const char *zero_branch = strstr(src, "if (ssl_setting == 0)");
	ASSERT_TRUE(zero_branch != NULL);

	const char *key_option = strstr(src, "MYSQL_OPT_SSL_KEY,  ssl_key");
	ASSERT_TRUE(key_option != NULL);
	if (zero_branch && key_option) {
		ASSERT_TRUE(key_option > zero_branch);
	}

	free(src);
}

int main(void) {
	test_fail_close_die_on_missing_verify_option();
	test_ssl_options_gated_on_ssl_setting();
	return finish_tests("sql tls fail-close tests");
}
