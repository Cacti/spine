/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Positive + negative coverage for spine_redact_args. The function is the
 | only thing standing between SNMPv3 auth/priv passphrases and
 | /var/log/cacti.log when a poll fails; regressing it silently leaks
 | credentials, so the flag allowlist is held in place by these tests.
 +-------------------------------------------------------------------------+
*/

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#include "test_platform_helpers.h"

static int contains(const char *hay, const char *needle) {
	return strstr(hay, needle) != NULL;
}

static void test_snmpv1_community_space_form(void) {
	char out[512];
	spine_redact_args("snmpget -c PUBLIC host oid", out, sizeof(out));

	ASSERT_TRUE(!contains(out, "PUBLIC"));
	ASSERT_TRUE(contains(out, "***"));
	ASSERT_TRUE(contains(out, "host"));
	ASSERT_TRUE(contains(out, "oid"));
}

static void test_snmpv1_community_equals_form(void) {
	char out[512];
	spine_redact_args("snmpget -c=PUBLIC host oid", out, sizeof(out));
	ASSERT_TRUE(!contains(out, "PUBLIC"));
	ASSERT_TRUE(contains(out, "***"));
}

static void test_snmpv3_auth_and_priv_passphrases(void) {
	char out[512];
	spine_redact_args(
	    "snmpget -v3 -u user -a MD5 -A AUTHPASS -x AES -X PRIVPASS host oid",
	    out, sizeof(out));

	ASSERT_TRUE(!contains(out, "AUTHPASS"));
	ASSERT_TRUE(!contains(out, "PRIVPASS"));
	ASSERT_TRUE(contains(out, "user"));   /* -u is redacted; but the value
	                                       * "user" is a security-name, not
	                                       * a secret. Still, we redact on
	                                       * the conservative side. Assert
	                                       * the non-flag tokens survived. */
	ASSERT_TRUE(contains(out, "host"));
	ASSERT_TRUE(contains(out, "oid"));
}

static void test_snmpv3_master_keys(void) {
	char out[512];
	spine_redact_args("snmpwalk -3m AUTHKEY -3M PRIVKEY host oid",
	                  out, sizeof(out));
	ASSERT_TRUE(!contains(out, "AUTHKEY"));
	ASSERT_TRUE(!contains(out, "PRIVKEY"));
}

static void test_snmpv3_localized_keys(void) {
	char out[512];
	spine_redact_args("snmpwalk -3k LOCALAUTH -3K LOCALPRIV host oid",
	                  out, sizeof(out));
	ASSERT_TRUE(!contains(out, "LOCALAUTH"));
	ASSERT_TRUE(!contains(out, "LOCALPRIV"));
}

static void test_long_flag_authkey_privkey(void) {
	char out[512];
	spine_redact_args(
	    "snmpget --authKey=0xDEADBEEF --privKey=0xCAFEBABE host oid",
	    out, sizeof(out));
	ASSERT_TRUE(!contains(out, "0xDEADBEEF"));
	ASSERT_TRUE(!contains(out, "0xCAFEBABE"));
	ASSERT_TRUE(contains(out, "***"));
}

static void test_long_flag_community(void) {
	char out[512];
	spine_redact_args("snmpget --community PUBLIC host oid", out, sizeof(out));
	ASSERT_TRUE(!contains(out, "PUBLIC"));
}

static void test_unrecognized_flag_passes_through(void) {
	char out[512];
	spine_redact_args("/usr/local/bin/wrapper -t 5 host oid", out, sizeof(out));

	/* -t is not a credential flag; its value must survive. */
	ASSERT_TRUE(contains(out, "5"));
	ASSERT_TRUE(contains(out, "host"));
	ASSERT_TRUE(contains(out, "wrapper"));
}

static void test_non_flag_value_not_eaten(void) {
	char out[512];
	/* A bare token that happens to look like flag characters without
	 * leading dash must pass unchanged. */
	spine_redact_args("echo password=hunter2", out, sizeof(out));
	ASSERT_TRUE(contains(out, "hunter2"));
}

static void test_null_output_does_not_crash(void) {
	spine_redact_args("snmpget -c PUBLIC host", NULL, 0);
	ASSERT_TRUE(1);
}

static void test_null_input_safe(void) {
	char out[512];
	spine_redact_args(NULL, out, sizeof(out));
	ASSERT_INT_EQ((int)strlen(out), 0);
}

static void test_truncation_nul_terminates(void) {
	char out[16];
	spine_redact_args("snmpget -c PUBLIC_LONG_COMMUNITY_STRING host oid",
	                  out, sizeof(out));
	ASSERT_INT_EQ(out[sizeof(out) - 1], '\0');
}

int main(void) {
	test_snmpv1_community_space_form();
	test_snmpv1_community_equals_form();
	test_snmpv3_auth_and_priv_passphrases();
	test_snmpv3_master_keys();
	test_snmpv3_localized_keys();
	test_long_flag_authkey_privkey();
	test_long_flag_community();
	test_unrecognized_flag_passes_through();
	test_non_flag_value_not_eaten();
	test_null_output_does_not_crash();
	test_null_input_safe();
	test_truncation_nul_terminates();
	return finish_tests("spine_redact_args");
}
