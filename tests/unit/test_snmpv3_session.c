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

static void *capture_snmp_sess_open(struct snmp_session *session);

#define snmp_sess_open capture_snmp_sess_open
#include "../../snmp.c"
#undef snmp_sess_open

static void *capture_snmp_sess_open(struct snmp_session *session) {
	captured_security_level = session->securityLevel;
	return (void *)(uintptr_t) 1;
}

static int session_reset(void **state) {
	(void) state;
	config_defaults();
	init_mutexes();
	set.snmp_retries = 1;
	captured_security_level = -1;
	return 0;
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
	char sha[] = "SHA";
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";

	(void) state;
	assert_int_equal(level_for(sha, pw, none, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
}

static void test_auth_with_privacy_is_authpriv(void **state) {
	char sha[] = "SHA";
	char pw[] = "authpass123";
	char aes[] = "AES";
	char ppass[] = "privpass123";

	(void) state;
	assert_int_equal(level_for(sha, pw, aes, ppass), SNMP_SEC_LEVEL_AUTHPRIV);
}

/* USM has no privacy without authentication. Opening this as noAuthNoPriv
   would leave the operator believing the traffic is encrypted, so it is
   refused. The old code also refused, but by failing key derivation with a
   message about passphrase length that named neither cause nor remedy. */
static void test_privacy_without_auth_is_refused(void **state) {
	char sha[] = "SHA";
	char empty[] = "";
	char aes[] = "AES";
	char ppass[] = "privpass123";

	(void) state;
	assert_int_equal(level_for(sha, empty, aes, ppass), -1);
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

static void test_privacy_protocol_without_passphrase_downgrades(void **state) {
	char sha[] = "SHA";
	char pw[] = "authpass123";
	char aes[] = "AES";
	char empty[] = "";

	(void) state;
	assert_int_equal(level_for(sha, pw, aes, empty), SNMP_SEC_LEVEL_AUTHNOPRIV);
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
		cmocka_unit_test_setup(test_privacy_protocol_without_passphrase_downgrades, session_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
