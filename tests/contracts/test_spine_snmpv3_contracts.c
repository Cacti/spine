/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"
#include <limits.h>

/* Independent SHA-1 Ku oracle from RFC3414 Appendix A.3.2, not a duplicate
 * implementation or a second call to the production key-generation API:
 * https://www.rfc-editor.org/rfc/rfc3414.html#appendix-A.3.2 */
static const unsigned char maplesyrup_sha_key[] = {
	0x9f, 0xb5, 0xcc, 0x03, 0x81, 0x49, 0x7b, 0x37, 0x93, 0x52,
	0x89, 0x39, 0xff, 0x78, 0x8d, 0x5d, 0x79, 0x14, 0x52, 0x11};

static snmp_connection_t session_options(char *hostname, char *username) {
	return (snmp_connection_t){
		.host_id = 46, .hostname = hostname, .snmp_version = 3, .snmp_community = "", .snmp_username = username, .snmp_password = "maplesyrup", .snmp_auth_protocol = "SHA", .snmp_priv_passphrase = "", .snmp_priv_protocol = "[None]", .snmp_context = "", .snmp_engine_id = "", .snmp_port = 1162, .snmp_timeout = 500};
}

void test_additional_snmp_session_boundaries(void) {
	config_t previous = set;
	set.snmp.snmp_retries = 0;
	/* Runs inside the default suite's single Net-SNMP init/shutdown lifecycle. */
	snmp_connection_t options = session_options("127.0.0.1", "regression-v3-vector-auth");
	void *handle = snmp_host_init(&options);
	assert(handle != NULL);
	const struct snmp_session *session = snmp_sess_session(handle);
	assert(session != NULL && session->securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert(session->securityAuthKeyLen == sizeof(maplesyrup_sha_key));
	assert(memcmp(session->securityAuthKey, maplesyrup_sha_key, sizeof(maplesyrup_sha_key)) == 0);
	assert(session->securityPrivKeyLen == 0);
	snmp_host_cleanup(handle);
	options.snmp_username = "regression-v3-vector-priv";
	options.snmp_priv_protocol = "AES";
	options.snmp_priv_passphrase = "maplesyrup";
	handle = snmp_host_init(&options);
	assert(handle != NULL);
	session = snmp_sess_session(handle);
	assert(session != NULL && session->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV);
	assert(session->securityAuthKeyLen == sizeof(maplesyrup_sha_key));
	assert(session->securityPrivKeyLen == sizeof(maplesyrup_sha_key));
	assert(memcmp(session->securityAuthKey, maplesyrup_sha_key, sizeof(maplesyrup_sha_key)) == 0);
	assert(memcmp(session->securityPrivKey, maplesyrup_sha_key, sizeof(maplesyrup_sha_key)) == 0);
	snmp_host_cleanup(handle);
	options.snmp_priv_protocol = "[None]";
	options.snmp_priv_passphrase = "";
	options.snmp_password = "short";
	assert(snmp_host_init(&options) == NULL);
	options.snmp_username = "regression-v3-vector-noauth";
	options.snmp_password = "";
	handle = snmp_host_init(&options);
	assert(handle != NULL);
	session = snmp_sess_session(handle);
	assert(session != NULL && session->securityLevel == SNMP_SEC_LEVEL_NOAUTH);
	assert(session->securityAuthKeyLen == 0 && session->securityPrivKeyLen == 0);
	snmp_host_cleanup(handle);

	options.snmp_version = 2;
	options.snmp_community = "regression";
	const int milliseconds[] = {1, 500, INT_MAX / 1000, INT_MAX / 1000 + 1, INT_MAX};
	for (size_t index = 0; index < sizeof(milliseconds) / sizeof(milliseconds[0]); index++) {
		options.snmp_timeout = milliseconds[index];
		handle = snmp_host_init(&options);
#if LONG_MAX / 1000L < INT_MAX
		if (milliseconds[index] > LONG_MAX / 1000L) {
			assert(handle == NULL);
			continue;
		}
#endif
		assert(handle != NULL);
		session = snmp_sess_session(handle);
		assert(session != NULL && session->timeout == (long) milliseconds[index] * 1000L);
		snmp_host_cleanup(handle);
	}
	options.snmp_timeout = 0;
	assert(snmp_host_init(&options) == NULL);
	options.snmp_timeout = -1;
	assert(snmp_host_init(&options) == NULL);
	options.snmp_timeout = INT_MIN;
	assert(snmp_host_init(&options) == NULL);
	set = previous;
	puts("production SNMPv3 key and timeout boundary regressions passed");
}

static void assert_v3_response(const snmp_connection_t *options, bool admitted, bool access_denied, int level) {
	/* Net-SNMP has a process-global USM user cache. Isolate every credential
	 * case so a previous admitted session cannot satisfy a later rejected one. */
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(4);
		host_t host = {0};
		host.id = options->host_id;
		host.snmp.session = snmp_host_init(options);
		assert(host.snmp.session != NULL);
		const struct snmp_session *session = snmp_sess_session(host.snmp.session);
		assert(session != NULL && session->securityLevel == level);
		char *response = snmp_get(&host, ".1.3.6.1.2.1.1.6.0");
		assert(response != NULL);
		if (admitted) {
			assert(strcmp(response, "isolated-regression-v3-agent") == 0);
			assert(!host.ignore_host);
		} else if (access_denied) {
			/* Authenticated VACM refusal is a transport-success agent error.
			 * Preserve the existing empty-data availability contract. */
			assert(response[0] == '\0');
			assert(host.snmp.status == STAT_SUCCESS && !host.ignore_host);
		} else {
			assert(IS_UNDEFINED(response));
			assert(host.ignore_host);
		}
		free(response);
		snmp_host_cleanup(host.snmp.session);
		snmp_spine_close();
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void test_snmpv3_agent_contracts(void) {
	char *agent = getenv("SPINE_TEST_SNMPV3_HOST");
	assert(agent != NULL && agent[0] != '\0');
	config_t previous = set;
	set.snmp.snmp_retries = 0;
	snmp_spine_init();
	snmp_connection_t options = session_options(agent, "regression-v3-noauth");
	options.snmp_password = "";
	assert_v3_response(&options, TRUE, FALSE, SNMP_SEC_LEVEL_NOAUTH);
	options.snmp_username = "regression-v3-auth";
	options.snmp_password = "maplesyrup";
	assert_v3_response(&options, TRUE, FALSE, SNMP_SEC_LEVEL_AUTHNOPRIV);
	options.snmp_password = "regression-wrong-auth";
	assert_v3_response(&options, FALSE, FALSE, SNMP_SEC_LEVEL_AUTHNOPRIV);
	options.snmp_username = "regression-v3-priv";
	options.snmp_password = "maplesyrup";
	options.snmp_priv_protocol = "AES";
	options.snmp_priv_passphrase = "regression-privacy";
	assert_v3_response(&options, TRUE, FALSE, SNMP_SEC_LEVEL_AUTHPRIV);
	options.snmp_priv_passphrase = "regression-wrong-privacy";
	assert_v3_response(&options, FALSE, FALSE, SNMP_SEC_LEVEL_AUTHPRIV);
	options.snmp_priv_protocol = "[None]";
	options.snmp_priv_passphrase = "";
	assert_v3_response(&options, FALSE, TRUE, SNMP_SEC_LEVEL_AUTHNOPRIV); /* VACM requires privacy. */
	snmp_spine_close();
	set = previous;
	puts("production live SNMPv3 authentication and privacy regressions passed");
}
