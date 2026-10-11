/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "internal/common.h"
#include "app/spine.h"

static unsigned int fixture_port(const char *name) {
	const char *value = getenv(name);
	char *end;
	unsigned long port;
	assert(value != NULL && value[0] != '\0');
	port = strtoul(value, &end, 10);
	assert(*end == '\0' && port > 0 && port <= 65535);
	return (unsigned int) port;
}

static void assert_tls_connection(int type, bool expected) {
	MYSQL mysql;
	int connected;
	connected = db_connect(type, &mysql);
	fflush(stdout);
	fprintf(stderr, "TLS connection type=%i expected=%i connected=%i\n", type, expected, connected);
	assert(connected == expected);
	if (connected) assert(mysql_get_ssl_cipher(&mysql) != NULL);
	db_disconnect(&mysql);
}

void test_database_tls_contracts(void) {
	const char *ca = getenv("SPINE_TEST_TLS_CA");
	const char *untrusted_ca = getenv("SPINE_TEST_TLS_UNTRUSTED_CA");
	unsigned int trusted = fixture_port("SPINE_TEST_TLS_PORT");
	unsigned int wrong_name = fixture_port("SPINE_TEST_TLS_WRONG_NAME_PORT");
	unsigned int plaintext = fixture_port("SPINE_TEST_TLS_PLAINTEXT_PORT");
	int type;
	assert(ca != NULL && untrusted_ca != NULL);
	config_defaults();
	set.logging.log_destination = LOGDEST_STDOUT;
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	set.poller.poller_id = 2;
	STRNCOPY(set.database.host, "127.0.0.1");
	STRNCOPY(set.database.database, "spine_regressions");
	STRNCOPY(set.database.user, "root");
	set.database.password[0] = '\0';
	set.database.tls_mode = SPINE_TLS_VERIFY_FULL;
	set.database.tls_min_version = 12;
	STRNCOPY(set.database.ssl_ca, ca);
	set.database.port = trusted;
	set.remote_database = set.database;
	for (type = LOCAL; type <= REMOTE; type++) {
		spine_database_config_t *configuration = type == LOCAL ? &set.database : &set.remote_database;
		assert_tls_connection(type, TRUE);
		STRNCOPY(configuration->ssl_ca, untrusted_ca);
		assert_tls_connection(type, FALSE);
		STRNCOPY(configuration->ssl_ca, ca);
		configuration->port = wrong_name;
		assert_tls_connection(type, FALSE);
		configuration->port = trusted;
		configuration->tls_min_version = 13;
		assert_tls_connection(type, FALSE);
		configuration->tls_min_version = 12;
		STRNCOPY(configuration->tls_cipher, "ECDHE-RSA-AES128-GCM-SHA256");
		assert_tls_connection(type, TRUE);
		STRNCOPY(configuration->tls_cipher, "ECDHE-RSA-AES256-GCM-SHA384");
		assert_tls_connection(type, FALSE);
		configuration->tls_cipher[0] = '\0';
#if HAVE_DECL_MYSQL_OPT_SSL_MODE || defined(HAVE_MARIADB_TLS_VERIFICATION_CALLBACK)
		configuration->tls_mode = SPINE_TLS_REQUIRED;
		configuration->port = plaintext;
		assert_tls_connection(type, FALSE);
		configuration->port = trusted;
		assert_tls_connection(type, TRUE);
#else
		configuration->port = plaintext;
		assert_tls_connection(type, FALSE);
		configuration->port = trusted;
#endif
		configuration->tls_mode = SPINE_TLS_VERIFY_FULL;
	}
	puts("production database TLS trust, identity, protocol, cipher and downgrade contracts passed");
}
