/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "internal/common.h"
#include "app/spine.h"

static int calls;
static int fail_at;
static unsigned int verification_flags;
static unsigned char enforcement;
static unsigned char verification;

int spine_log(const char *format, ...) {
	(void) format;
	return TRUE;
}

static int fake_options(MYSQL *mysql, enum mysql_option option, const void *value) {
	(void) mysql;
	assert_non_null(value);
#if HAVE_DECL_MYSQL_OPT_SSL_ENFORCE && HAVE_DECL_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	if (option == MYSQL_OPT_SSL_ENFORCE) enforcement = *(const unsigned char *) value;
	if (option == MYSQL_OPT_SSL_VERIFY_SERVER_CERT) verification = *(const unsigned char *) value;
#else
	(void) option;
#endif
	calls++;
	return calls == fail_at ? 1 : 0;
}

#define mysql_options fake_options
#define ma_pvio_tls_verify_server_cert fake_verify
#include "../../src/database/tls.c"

#ifdef HAVE_MARIADB_TLS_VERIFICATION_CALLBACK
int fake_verify(struct st_ma_pvio_tls *tls, unsigned int flags) {
	(void) tls;
	verification_flags = flags;
	return 7;
}
#endif

static void test_each_option_failure_stops_policy(void **state) {
	MYSQL mysql = {0};
	spine_database_config_t configuration = {0};
	int total;
	int index;
	bool supported;
	(void) state;
	configuration.tls_mode = SPINE_TLS_VERIFY_FULL;
	memcpy(configuration.ssl_ca, "/fixture/ca.pem", sizeof("/fixture/ca.pem"));
#if HAVE_DECL_MYSQL_OPT_TLS_VERSION
	configuration.tls_min_version = 12;
#endif
#if HAVE_DECL_MYSQL_OPT_SSL_CIPHER
	memcpy(configuration.tls_cipher, "ECDHE-RSA-AES128-GCM-SHA256", sizeof("ECDHE-RSA-AES128-GCM-SHA256"));
#endif
#if HAVE_DECL_MYSQL_OPT_TLS_CIPHERSUITES
	memcpy(configuration.tls_ciphersuites, "TLS_AES_128_GCM_SHA256", sizeof("TLS_AES_128_GCM_SHA256"));
#endif
	calls = fail_at = 0;
	supported = db_apply_tls_policy(&mysql, &configuration);
	total = calls;
	if (total == 0) {
		assert_false(supported);
		return;
	}
	assert_true(supported);
	for (index = 1; index <= total; index++) {
		calls = 0;
		fail_at = index;
		assert_false(db_apply_tls_policy(&mysql, &configuration));
		assert_int_equal(calls, index);
	}
	/* The setter itself must report failure even without a connection. */
	calls = 0;
	fail_at = 1;
	assert_false(tls_option(&mysql, MYSQL_OPT_CONNECT_TIMEOUT, &total, "fixture"));
}

static void test_verification_callbacks_keep_requested_checks(void **state) {
	(void) state;
#ifdef HAVE_MARIADB_TLS_VERIFICATION_CALLBACK
	assert_int_equal(verify_database_identity(NULL, 0), 7);
	assert_true(verification_flags & MARIADB_TLS_VERIFY_HOST);
	assert_true(verification_flags & MARIADB_TLS_VERIFY_TRUST);
	assert_int_equal(verify_database_chain(NULL, MARIADB_TLS_VERIFY_HOST), 7);
	assert_false(verification_flags & MARIADB_TLS_VERIFY_HOST);
	assert_true(verification_flags & MARIADB_TLS_VERIFY_TRUST);
	assert_int_equal(encryption_only(NULL, 0), 0);
#else
	(void) verification_flags;
#endif
}

static void test_preferred_allows_plaintext_fallback(void **state) {
	MYSQL mysql = {0};
	spine_database_config_t configuration = {0};
	(void) state;
	configuration.tls_mode = SPINE_TLS_PREFERRED;
	calls = 0;
	fail_at = 0;
	enforcement = verification = 255;
#if HAVE_DECL_MYSQL_OPT_SSL_MODE
	assert_true(db_apply_tls_policy(&mysql, &configuration));
#elif HAVE_DECL_MYSQL_OPT_SSL_ENFORCE && HAVE_DECL_MYSQL_OPT_SSL_VERIFY_SERVER_CERT
	assert_true(db_apply_tls_policy(&mysql, &configuration));
	assert_int_equal(enforcement, 0);
	assert_int_equal(verification, 0);
	configuration.tls_mode = SPINE_TLS_VERIFY_FULL;
	memcpy(configuration.ssl_ca, "/fixture/ca.pem", sizeof("/fixture/ca.pem"));
	if (db_apply_tls_policy(&mysql, &configuration)) {
		assert_int_equal(enforcement, 1);
		assert_int_equal(verification, 1);
	}
#else
	assert_false(db_apply_tls_policy(&mysql, &configuration));
#endif
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_each_option_failure_stops_policy),
		cmocka_unit_test(test_verification_callbacks_keep_requested_checks),
		cmocka_unit_test(test_preferred_allows_plaintext_fallback),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
