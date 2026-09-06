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
static unsigned char captured_auth_key[USM_AUTH_KU_LEN];
static unsigned char captured_priv_key[USM_PRIV_KU_LEN];
static oid captured_auth_proto[MAX_OID_LEN];

static void *capture_snmp_sess_open(struct snmp_session *session);

#define snmp_sess_open capture_snmp_sess_open
#include "../../snmp.c"
#undef snmp_sess_open

static void *capture_snmp_sess_open(struct snmp_session *session) {
	captured_security_level = session->securityLevel;
	captured_auth_key_len = session->securityAuthKeyLen;
	captured_priv_key_len = session->securityPrivKeyLen;
	captured_auth_proto_len = session->securityAuthProtoLen;
	assert_true(captured_auth_key_len <= sizeof(captured_auth_key));
	assert_true(captured_priv_key_len <= sizeof(captured_priv_key));
	assert_true(captured_auth_proto_len <= MAX_OID_LEN);
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
	memset(captured_auth_key, 0, sizeof(captured_auth_key));
	memset(captured_priv_key, 0, sizeof(captured_priv_key));
	memset(captured_auth_proto, 0, sizeof(captured_auth_proto));
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
	assert_false(spine_snmpv3_value_is_set(NULL));
	assert_false(spine_snmpv3_value_is_set(""));
	assert_false(spine_snmpv3_value_is_set("[None]"));
	assert_true(spine_snmpv3_value_is_set("SHA"));
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
	const oid *expected;
	size_t expected_len;

	(void) state;
	if (auth == NULL) {
		skip();
	}
	assert_int_equal(level_for(auth, pw, none, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_true(captured_auth_key_len > 0);
	assert_true(contains_nonzero(captured_auth_key, captured_auth_key_len));
	expected = sc_get_auth_oid(usm_lookup_auth_type(auth), &expected_len);
	assert_non_null(expected);
	assert_int_equal(captured_auth_proto_len, expected_len);
	assert_int_equal(snmp_oid_compare(captured_auth_proto, captured_auth_proto_len,
		expected, expected_len), 0);
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

static void test_empty_auth_protocol_with_password_downgrades(void **state) {
	char empty[] = "";
	char pw[] = "authpass123";
	char none[] = "[None]";

	(void) state;
	assert_int_equal(level_for(empty, pw, none, empty), SNMP_SEC_LEVEL_NOAUTH);
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

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_value_presence_contract, session_reset),
		cmocka_unit_test_setup(test_security_level_contract, session_reset),
		cmocka_unit_test_setup(test_no_credentials_is_noauthnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_without_privacy_is_authnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_with_privacy_is_authpriv, session_reset),
		cmocka_unit_test_setup(test_privacy_without_auth_is_refused, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_even_without_a_password, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_with_a_password, session_reset),
		cmocka_unit_test_setup(test_empty_auth_protocol_with_password_downgrades, session_reset),
		cmocka_unit_test_setup(test_privacy_protocol_without_passphrase_uses_authnopriv, session_reset),
		cmocka_unit_test_setup(test_privacy_passphrase_without_protocol_uses_authnopriv, session_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
