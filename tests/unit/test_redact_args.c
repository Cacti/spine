/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Unit test for spine_redact_args. Pins credential-bearing flag masking   |
 | so SNMP communities and auth/priv passphrases never land in the log.    |
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

/* Prototype only; we pull the implementation in through a dedicated TU
 * below to avoid linking the entire util.c (which drags mysql + snmp). */
extern void spine_redact_args(const char *cmd, char *out, size_t outsz);

static void expect_eq(const char *in, const char *want) {
	char out[512];
	spine_redact_args(in, out, sizeof(out));
	if (strcmp(out, want) != 0) {
		fprintf(stderr, "redact mismatch:\n  in:   %s\n  got:  %s\n  want: %s\n", in, out, want);
		test_failures++;
	}
}

static void test_short_community(void) {
	expect_eq("snmpget -c public -v2c host", "snmpget -c *** -v2c host");
}

static void test_long_password_eq(void) {
	expect_eq("tool --password=secret", "tool --password=***");
}

static void test_harmless_unchanged(void) {
	expect_eq("harmless_tool arg1 arg2", "harmless_tool arg1 arg2");
}

static void test_short_eq_form(void) {
	expect_eq("snmpwalk -c=public host", "snmpwalk -c=*** host");
}

static void test_multiple_creds(void) {
	expect_eq("snmpget -u alice -a sha -x aes -p secretpass host",
	          "snmpget -u *** -a *** -x *** -p *** host");
}

static void test_long_community(void) {
	expect_eq("tool --community public host", "tool --community *** host");
}

static void test_secret_flag(void) {
	expect_eq("tool --secret=topsecret", "tool --secret=***");
}

static void test_truncation_safe(void) {
	char out[8];
	spine_redact_args("snmpget -c public host", out, sizeof(out));
	/* Must be NUL-terminated and within bounds. */
	ASSERT_TRUE(strnlen(out, sizeof(out)) < sizeof(out));
}

static void test_null_inputs(void) {
	char out[16];
	out[0] = 'x';
	spine_redact_args(NULL, out, sizeof(out));
	ASSERT_TRUE(out[0] == '\0');

	/* Zero-size must not crash. */
	spine_redact_args("anything", out, 0);
}

static void test_non_cred_short_flag(void) {
	/* -v is not a credential flag; value must pass through. */
	expect_eq("snmpget -v 2c host", "snmpget -v 2c host");
}

int main(void) {
	test_short_community();
	test_long_password_eq();
	test_harmless_unchanged();
	test_short_eq_form();
	test_multiple_creds();
	test_long_community();
	test_secret_flag();
	test_truncation_safe();
	test_null_inputs();
	test_non_cred_short_flag();
	return finish_tests("redact args tests");
}
