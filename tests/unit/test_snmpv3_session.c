/* SNMPv3 session construction.
 *
 * spine_snmpv3_security_level() is unit tested elsewhere, but the level it
 * returns is only half the story: the session also has to install the right
 * auth protocol and refuse a configuration it cannot honour. Those decisions
 * live in snmp_host_init(), and until now nothing exercised them.
 *
 * snmp_sess_open() builds the session without contacting anything, so this can
 * assert the resulting securityLevel directly. That is what makes the
 * difference between pinning what the code does and pinning what it should do.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"

static int fail_objid_duplicates;

oid *__real_snmp_duplicate_objid(const oid *objid, size_t objidlen);
oid *__wrap_snmp_duplicate_objid(const oid *objid, size_t objidlen) {
	if (fail_objid_duplicates > 0) {
		fail_objid_duplicates--;
		return NULL;
	}
	return __real_snmp_duplicate_objid(objid, objidlen);
}

static int session_reset(void **state) {
	(void) state;
	config_defaults();
	set.snmp_retries = 1;
	fail_objid_duplicates = 0;
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
	struct snmp_session *s;
	void *sessp;
	int level;

	sessp = snmp_host_init(1, host, 3, NULL, user, auth_password, auth_protocol,
		priv_passphrase, priv_protocol, ctx, eid, 161, 500);

	if (sessp == NULL) {
		return -1;
	}

	s = snmp_sess_session(sessp);
	level = s->securityLevel;
	snmp_sess_close(sessp);

	return level;
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

static void test_auth_without_privacy_falls_back_after_proto_allocation_failure(void **state) {
	char sha[] = "SHA";
	char pw[] = "authpass123";
	char none[] = "[None]";
	char empty[] = "";

	(void) state;
	/* Fail both the configured-protocol copy and net-snmp's configured default;
	 * the probed explicit SHA-1 fallback must keep authNoPriv usable. */
	fail_objid_duplicates = 2;
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

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_no_credentials_is_noauthnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_without_privacy_is_authnopriv, session_reset),
		cmocka_unit_test_setup(test_auth_without_privacy_falls_back_after_proto_allocation_failure, session_reset),
		cmocka_unit_test_setup(test_auth_with_privacy_is_authpriv, session_reset),
		cmocka_unit_test_setup(test_privacy_without_auth_is_refused, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_even_without_a_password, session_reset),
		cmocka_unit_test_setup(test_unknown_auth_protocol_is_refused_with_a_password, session_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
