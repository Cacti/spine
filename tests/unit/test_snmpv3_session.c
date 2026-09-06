/* SNMPv3 session construction.
 *
 * The security-level predicates and the session they drive both need coverage:
 * the session also has to install the right
 * auth protocol and refuse a configuration it cannot honour. Those decisions
 * live in snmp_host_init(), and until now nothing exercised them.
 *
 * The shipped snmp.c is compiled into this test with snmp_sess_open()
 * intercepted. That captures the completed structure before any engine-ID
 * discovery or network I/O and keeps the assertions deterministic.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"

static int captured_security_level;
static size_t captured_auth_key_len;
static size_t captured_priv_key_len;
static size_t captured_auth_proto_len;
static size_t captured_priv_proto_len;
static unsigned char captured_auth_key[USM_AUTH_KU_LEN];
static unsigned char captured_priv_key[USM_PRIV_KU_LEN];
static oid captured_auth_proto[MAX_OID_LEN];
static oid captured_priv_proto[MAX_OID_LEN];

static void *capture_snmp_sess_open(struct snmp_session *session);

#define snmp_sess_open capture_snmp_sess_open
#include "../../snmp.c"
#undef snmp_sess_open

static void *capture_snmp_sess_open(struct snmp_session *session) {
	captured_security_level = session->securityLevel;
	captured_auth_key_len = session->securityAuthKeyLen;
	captured_priv_key_len = session->securityPrivKeyLen;
	captured_auth_proto_len = session->securityAuthProtoLen;
	captured_priv_proto_len = session->securityPrivProtoLen;
	assert_true(captured_auth_key_len <= sizeof(captured_auth_key));
	assert_true(captured_priv_key_len <= sizeof(captured_priv_key));
	assert_true(captured_auth_proto_len <= MAX_OID_LEN);
	assert_true(captured_priv_proto_len <= MAX_OID_LEN);
	if (captured_auth_key_len > 0) {
		memcpy(captured_auth_key, session->securityAuthKey, captured_auth_key_len);
	}
	if (captured_priv_key_len > 0) {
		memcpy(captured_priv_key, session->securityPrivKey, captured_priv_key_len);
	}
	if (captured_auth_proto_len > 0) {
		assert_non_null(session->securityAuthProto);
		memcpy(captured_auth_proto, session->securityAuthProto,
			captured_auth_proto_len * sizeof(*captured_auth_proto));
	}
	if (captured_priv_proto_len > 0) {
		assert_non_null(session->securityPrivProto);
		memcpy(captured_priv_proto, session->securityPrivProto,
			captured_priv_proto_len * sizeof(*captured_priv_proto));
	}
	return (void *)(uintptr_t) 1;
}

static int session_reset(void **state) {
	(void) state;
	config_defaults();
	init_mutexes();
	set.snmp_retries = 1;
	captured_security_level = -1;
	captured_auth_key_len = 0;
	captured_priv_key_len = 0;
	captured_auth_proto_len = 0;
	captured_priv_proto_len = 0;
	memset(captured_auth_key, 0, sizeof(captured_auth_key));
	memset(captured_priv_key, 0, sizeof(captured_priv_key));
	memset(captured_auth_proto, 0, sizeof(captured_auth_proto));
	memset(captured_priv_proto, 0, sizeof(captured_priv_proto));
	return 0;
}

static int contains_nonzero(const unsigned char *value, size_t length) {
	size_t i;

	for (i = 0; i < length; i++) {
		if (value[i] != 0) {
			return TRUE;
		}
	}

	return FALSE;
}

static char *available_auth_protocol(void) {
	static char sha[] = "SHA";
	static char md5[] = "MD5";

	if (usm_lookup_auth_type(sha) > 0) {
		return sha;
	}
	if (usm_lookup_auth_type(md5) > 0) {
		return md5;
	}

	return NULL;
}

static char *available_priv_protocol(void) {
	static char aes[] = "AES";
	static char des[] = "DES";

	if (usm_lookup_priv_type(aes) >= 0) {
		return aes;
	}
	if (usm_lookup_priv_type(des) >= 0) {
		return des;
	}

	return NULL;
}

/* Returns the securityLevel of the session spine builds, or -1 when it
   refuses to build one. */
static int level_for(char *auth_protocol, char *auth_password,
	char *priv_protocol, char *priv_passphrase) {
	char host[] = "127.0.0.1";
	char user[] = "snmpuser";
	char ctx[]  = "";
	char eid[]  = "";
	void *sessp;

	sessp = snmp_host_init(1, host, 3, NULL, user, auth_password, auth_protocol,
		priv_passphrase, priv_protocol, ctx, eid, 161, 500);

	if (sessp == NULL) {
		return -1;
	}

	return captured_security_level;
}

static void test_value_presence_contract(void **state) {
	(void) state;
	assert_false(spine_snmpv3_protocol_is_set(NULL));
	assert_false(spine_snmpv3_protocol_is_set(""));
	assert_false(spine_snmpv3_protocol_is_set("[None]"));
	assert_true(spine_snmpv3_protocol_is_set("SHA"));
	assert_false(spine_snmpv3_passphrase_is_set(NULL));
	assert_false(spine_snmpv3_passphrase_is_set(""));
	assert_true(spine_snmpv3_passphrase_is_set("[None]"));
}

static void test_security_level_contract(void **state) {
	(void) state;
	assert_int_equal(spine_snmpv3_security_level("[None]", "", "[None]", ""), SNMP_SEC_LEVEL_NOAUTH);
	assert_int_equal(spine_snmpv3_security_level("SHA", "authpass123", "[None]", ""), SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_int_equal(spine_snmpv3_security_level("SHA", "authpass123", "AES", "privpass123"), SNMP_SEC_LEVEL_AUTHPRIV);
	assert_int_equal(spine_snmpv3_security_level("SHA", "", "AES", "privpass123"), SNMP_SEC_LEVEL_NOAUTH);
}

/* Cacti writes "[None]" for an unselected protocol. A device with neither
   authentication nor privacy is noAuthNoPriv, not an error: this is the level
   that was unusable before #582. */
static void test_no_credentials_is_noauthnopriv(void **state) {
	char none[] = "[None]";
	char empty[] = "";

	(void) state;
	assert_int_equal(level_for(none, empty, none, empty), SNMP_SEC_LEVEL_NOAUTH);
}

/* Authentication without privacy is authNoPriv. This was also unusable before
   #582, because the key was only derived on the privacy path. */
static void test_auth_without_privacy_is_authnopriv(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";
	const oid *expected_priv;
	size_t expected_priv_len;

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, none, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_true(captured_auth_key_len > 0);
	assert_true(contains_nonzero(captured_auth_key, captured_auth_key_len));
	expected_priv = usmNoPrivProtocol;
	expected_priv_len = OID_LENGTH(usmNoPrivProtocol);
	assert_int_equal(captured_priv_proto_len, expected_priv_len);
	assert_int_equal(snmp_oid_compare(captured_priv_proto, captured_priv_proto_len,
		expected_priv, expected_priv_len), 0);
}

static void test_auth_protocol_oids_match_the_selected_algorithms(void **state) {
	struct auth_case {
		char *name;
		const oid *expected;
		size_t expected_len;
	};
	const struct auth_case cases[] = {
		{ "MD5",    usmHMACMD5AuthProtocol,       OID_LENGTH(usmHMACMD5AuthProtocol) },
		{ "SHA",    usmHMACSHA1AuthProtocol,      OID_LENGTH(usmHMACSHA1AuthProtocol) },
		{ "SHA224", usmHMAC128SHA224AuthProtocol, OID_LENGTH(usmHMAC128SHA224AuthProtocol) },
		{ "SHA256", usmHMAC192SHA256AuthProtocol, OID_LENGTH(usmHMAC192SHA256AuthProtocol) },
		{ "SHA384", usmHMAC256SHA384AuthProtocol, OID_LENGTH(usmHMAC256SHA384AuthProtocol) },
		{ "SHA512", usmHMAC384SHA512AuthProtocol, OID_LENGTH(usmHMAC384SHA512AuthProtocol) },
	};
	char password[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";
	size_t i;
	int exercised = 0;

	(void) state;
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		if (usm_lookup_auth_type(cases[i].name) <= 0) continue;

		exercised++;
		assert_int_equal(level_for(cases[i].name, password, none, empty),
			SNMP_SEC_LEVEL_AUTHNOPRIV);
		assert_int_equal(captured_auth_proto_len, cases[i].expected_len);
		assert_int_equal(snmp_oid_compare(captured_auth_proto,
			captured_auth_proto_len, cases[i].expected,
			cases[i].expected_len), 0);
	}

	assert_true(exercised > 0);
}

static void test_auth_with_privacy_is_authpriv(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char *priv = available_priv_protocol();
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL || priv == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, priv, ppass), SNMP_SEC_LEVEL_AUTHPRIV);
	assert_true(captured_auth_key_len > 0);
	assert_true(contains_nonzero(captured_auth_key, captured_auth_key_len));
	assert_true(captured_priv_key_len > 0);
	assert_true(contains_nonzero(captured_priv_key, captured_priv_key_len));
}

/* USM has no privacy without authentication. Opening this as noAuthNoPriv
   would leave the operator believing the traffic is encrypted, so it is
   refused. The old code also refused, but by failing key derivation with a
   message about passphrase length that named neither cause nor remedy. */
static void test_privacy_without_auth_is_refused(void **state) {
	char *auth = available_auth_protocol();
	char empty[] = "";
	char *priv = available_priv_protocol();
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL || priv == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, empty, priv, ppass), -1);
}

/* An unrecognised protocol is a configuration error at any level. Deciding the
   level first and validating only on the authenticated path let a typo through
   as noAuthNoPriv, because a device with no passphrase never reached the check. */
static void test_unknown_auth_protocol_is_refused_even_without_a_password(void **state) {
	char bogus[] = "MD6";
	char empty[] = "";
	char none[] = "[None]";

	(void) state;
	assert_int_equal(level_for(bogus, empty, none, empty), -1);
}

static void test_unknown_auth_protocol_is_refused_with_a_password(void **state) {
	char bogus[] = "MD6";
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";

	(void) state;
	assert_int_equal(level_for(bogus, pw, none, empty), -1);
}

static void test_empty_auth_protocol_with_password_is_refused(void **state) {
	char empty[] = "";
	char pw[] = "authpass123";
	char none[] = "[None]";

	(void) state;
	assert_int_equal(level_for(empty, pw, none, empty), -1);
}

static void test_none_auth_protocol_with_password_uses_noauth(void **state) {
	char none[] = "[None]";
	char pw[] = "authpass123";
	char empty[] = "";

	(void) state;
	assert_int_equal(level_for(none, pw, none, empty), SNMP_SEC_LEVEL_NOAUTH);
}

static void test_auth_protocol_without_password_uses_noauth(void **state) {
	char *auth = available_auth_protocol();
	char empty[] = "";
	char none[] = "[None]";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, empty, none, empty), SNMP_SEC_LEVEL_NOAUTH);
}

static void test_invalid_privacy_protocol_is_refused(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char bogus[] = "ROT13";
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, bogus, ppass), -1);
}

static void test_auth_key_matches_with_and_without_privacy(void **state) {
	char *auth = available_auth_protocol();
	char *priv = available_priv_protocol();
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";
	char ppass[] = "privpass123";
	unsigned char authnopriv_key[USM_AUTH_KU_LEN];
	size_t authnopriv_len;

	(void) state;
	if (auth == NULL || priv == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, none, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
	authnopriv_len = captured_auth_key_len;
	memcpy(authnopriv_key, captured_auth_key, authnopriv_len);
	assert_int_equal(level_for(auth, pw, priv, ppass), SNMP_SEC_LEVEL_AUTHPRIV);
	assert_int_equal(captured_auth_key_len, authnopriv_len);
	assert_memory_equal(captured_auth_key, authnopriv_key, authnopriv_len);
}

static void test_privacy_protocol_without_passphrase_uses_authnopriv(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char *priv = available_priv_protocol();
	char empty[] = "";

	(void) state;
	if (auth == NULL || priv == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, priv, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
}

static void test_privacy_passphrase_without_protocol_uses_authnopriv(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char none[] = "[None]";
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, none, ppass), SNMP_SEC_LEVEL_AUTHNOPRIV);
}

static void test_privacy_passphrase_with_empty_protocol_is_refused(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char empty[] = "";
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, empty, ppass), -1);
}

static void test_stale_privacy_passphrase_without_auth_uses_noauth(void **state) {
	char *auth = available_auth_protocol();
	char empty[] = "";
	char none[] = "[None]";
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, empty, none, ppass), SNMP_SEC_LEVEL_NOAUTH);
}

static void test_session_construction_does_not_modify_caller_passphrases(void **state) {
	char *auth = available_auth_protocol();
	char *priv = available_priv_protocol();
	char pw[] = "authpass123";
	char ppass[] = "privpass123";

	(void) state;
	if (auth == NULL || priv == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, priv, ppass), SNMP_SEC_LEVEL_AUTHPRIV);
	assert_string_equal(pw, "authpass123");
	assert_string_equal(ppass, "privpass123");
}

static void test_authnopriv_does_not_modify_caller_password(void **state) {
	char *auth = available_auth_protocol();
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, none, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_string_equal(pw, "authpass123");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_value_presence_contract, session_reset),
		cmocka_unit_test_setup(test_security_level_contract, session_reset),
		cmocka_unit_test_setup(test_no_credentials_is_noauthnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_without_privacy_is_authnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_protocol_oids_match_the_selected_algorithms, session_reset),
		cmocka_unit_test_setup(test_auth_with_privacy_is_authpriv, session_reset),
		cmocka_unit_test_setup(test_privacy_without_auth_is_refused, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_even_without_a_password, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_with_a_password, session_reset),
		cmocka_unit_test_setup(test_empty_auth_protocol_with_password_is_refused, session_reset),
		cmocka_unit_test_setup(test_none_auth_protocol_with_password_uses_noauth, session_reset),
		cmocka_unit_test_setup(test_auth_protocol_without_password_uses_noauth, session_reset),
		cmocka_unit_test_setup(test_invalid_privacy_protocol_is_refused, session_reset),
		cmocka_unit_test_setup(test_auth_key_matches_with_and_without_privacy, session_reset),
		cmocka_unit_test_setup(test_privacy_protocol_without_passphrase_uses_authnopriv, session_reset),
		cmocka_unit_test_setup(test_privacy_passphrase_without_protocol_uses_authnopriv, session_reset),
		cmocka_unit_test_setup(test_privacy_passphrase_with_empty_protocol_is_refused, session_reset),
		cmocka_unit_test_setup(test_stale_privacy_passphrase_without_auth_uses_noauth, session_reset),
		cmocka_unit_test_setup(test_session_construction_does_not_modify_caller_passphrases, session_reset),
		cmocka_unit_test_setup(test_authnopriv_does_not_modify_caller_password, session_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
