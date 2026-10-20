/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* SNMP request, response and session failure paths.
 *
 * Like test_snmpv3_session, this compiles the shipped session.c, requests.c
 * and response.c into the test and intercepts the Net-SNMP calls they make.
 * The interception lets a test script the transport outcome, the reply PDU
 * and the library failures that a live agent cannot be made to produce.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <limits.h>
#include <string.h>
#include <stdlib.h>

#include "internal/common.h"
#include "app/spine.h"
#include "poller/poller.h"

static int fail_pdu_create;
static int fail_add_null_var;
static int session_liberr;
static int fail_ascii_string;
static size_t failing_calloc;
static int null_default_protocols;
static int fail_auth_oid;
static int fail_priv_oid;
static int fail_no_priv_duplicate;
static int fail_session_open;
static int scripted_status;
static int scripted_calls;
static bool scripted_response;
static int response_variables;
static long response_errstat;
static long response_errindex;
static bool response_nameless;
static bool response_long_name;
static unsigned char captured_engine_id[64];
static size_t captured_engine_id_len;

static struct snmp_pdu *controlled_pdu_create(int command) {
	if (fail_pdu_create) {
		fail_pdu_create = FALSE;
		return NULL;
	}
	return snmp_pdu_create(command);
}

static netsnmp_variable_list *controlled_add_null_var(struct snmp_pdu *pdu, const oid *name, size_t length) {
	if (fail_add_null_var) {
		fail_add_null_var = FALSE;
		return NULL;
	}
	return snmp_add_null_var(pdu, name, length);
}

static void controlled_sess_error(void *session, int *liberr, int *syserr, char **errstr) {
	(void) session;
	*liberr = session_liberr;
	*syserr = 0;
	*errstr = strdup("scripted session error");
}

static int controlled_ascii_string(char *buffer, size_t capacity, const u_char *input, size_t length) {
	if (fail_ascii_string) return -1;
	return snprint_asciistring(buffer, capacity, input, length);
}

static void *controlled_calloc(size_t count, size_t size) {
	if (count == failing_calloc && failing_calloc != 0) {
		failing_calloc = 0;
		return NULL;
	}
	return calloc(count, size);
}

static const oid *controlled_default_authtype(size_t *length) {
	if (null_default_protocols) {
		*length = 0;
		return NULL;
	}
	return get_default_authtype(length);
}

static const oid *controlled_default_privtype(size_t *length) {
	if (null_default_protocols) {
		*length = 0;
		return NULL;
	}
	return get_default_privtype(length);
}

static const oid *controlled_auth_oid(int type, size_t *length) {
	if (fail_auth_oid) return NULL;
	return sc_get_auth_oid(type, length);
}

static const oid *controlled_priv_oid(int type, size_t *length) {
	if (fail_priv_oid) return NULL;
	return sc_get_priv_oid(type, length);
}

static oid *controlled_duplicate_objid(const oid *source, size_t length) {
	if (fail_no_priv_duplicate && source == usmNoPrivProtocol) return NULL;
	return snmp_duplicate_objid(source, length);
}

static void *controlled_sess_open(struct snmp_session *session) {
	if (fail_session_open) return NULL;
	captured_engine_id_len = session->contextEngineIDLen;
	if (captured_engine_id_len > 0 && captured_engine_id_len <= sizeof(captured_engine_id)) {
		memcpy(captured_engine_id, session->contextEngineID, captured_engine_id_len);
	}
	return (void *) (uintptr_t) 1;
}

static int controlled_sess_close(void *session) {
	(void) session;
	return 1;
}

static struct snmp_session *controlled_sess_session(void *session) {
	(void) session;
	return NULL;
}

static int controlled_synch_response(void *session, struct snmp_pdu *request, struct snmp_pdu **response) {
	static const oid base[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
	long value = 42;
	int index;

	(void) session;
	scripted_calls++;
	/* Net-SNMP consumes the request even when the send fails. */
	snmp_free_pdu(request);
	*response = NULL;
	if (!scripted_response) return scripted_status;
	*response = snmp_pdu_create(SNMP_MSG_RESPONSE);
	assert_non_null(*response);
	(*response)->errstat = response_errstat;
	(*response)->errindex = response_errindex;
	for (index = 0; index < response_variables; index++) {
		oid name[sizeof(base) / sizeof(base[0])];

		memcpy(name, base, sizeof(name));
		name[sizeof(name) / sizeof(name[0]) - 2] += (oid) index;
		assert_non_null(snmp_pdu_add_variable(*response, name, sizeof(name) / sizeof(name[0]),
			ASN_INTEGER, (const u_char *) &value, sizeof(value)));
	}
	if (response_nameless && (*response)->variables != NULL) {
		netsnmp_variable_list *variable = (*response)->variables;

		if (variable->name != variable->name_loc) SNMP_FREE(variable->name);
		variable->name = NULL;
		variable->name_length = 0;
	}
	if (response_long_name && (*response)->variables != NULL) {
		netsnmp_variable_list *variable = (*response)->variables;

		if (variable->name != variable->name_loc) SNMP_FREE(variable->name);
		variable->name = calloc(MAX_OID_LEN + 1, sizeof(oid));
		assert_non_null(variable->name);
		variable->name_length = MAX_OID_LEN + 1;
	}
	return scripted_status;
}

#define snmp_pdu_create controlled_pdu_create
#define snmp_add_null_var controlled_add_null_var
#define snmp_sess_error controlled_sess_error
#define snmp_sess_open controlled_sess_open
#define snmp_sess_close controlled_sess_close
#define snmp_sess_session controlled_sess_session
#define snmp_sess_synch_response controlled_synch_response
#define snprint_asciistring controlled_ascii_string
#define calloc controlled_calloc
#define get_default_authtype controlled_default_authtype
#define get_default_privtype controlled_default_privtype
#define sc_get_auth_oid controlled_auth_oid
#define sc_get_priv_oid controlled_priv_oid
#define snmp_duplicate_objid controlled_duplicate_objid
#include "../../src/snmp/session.c"
#include "../../src/snmp/requests.c"
#include "../../src/snmp/response.c"
#undef snmp_duplicate_objid
#undef sc_get_priv_oid
#undef sc_get_auth_oid
#undef get_default_privtype
#undef get_default_authtype
#undef calloc
#undef snprint_asciistring
#undef snmp_sess_synch_response
#undef snmp_sess_session
#undef snmp_sess_close
#undef snmp_sess_open
#undef snmp_sess_error
#undef snmp_add_null_var
#undef snmp_pdu_create

static const char sys_descr_oid[] = ".1.3.6.1.2.1.1.1.0";

static int snmp_reset(void **state) {
	(void) state;
	config_defaults();
	init_mutexes();
	set.snmp.snmp_retries = 1;
	fail_pdu_create = FALSE;
	fail_add_null_var = FALSE;
	session_liberr = 0;
	fail_ascii_string = FALSE;
	failing_calloc = 0;
	null_default_protocols = FALSE;
	fail_auth_oid = FALSE;
	fail_priv_oid = FALSE;
	fail_no_priv_duplicate = FALSE;
	fail_session_open = FALSE;
	scripted_status = STAT_SUCCESS;
	scripted_calls = 0;
	scripted_response = FALSE;
	response_variables = 0;
	response_errstat = SNMP_ERR_NOERROR;
	response_errindex = 0;
	response_nameless = FALSE;
	response_long_name = FALSE;
	captured_engine_id_len = 0;
	return 0;
}

static void test_pdu_allocation_failure_reads_as_unknown(void **state) {
	host_t host = {0};
	char oid_text[sizeof(sys_descr_oid)];
	char *result;

	(void) state;
	memcpy(oid_text, sys_descr_oid, sizeof(oid_text));
	host.snmp.session = (void *) (uintptr_t) 1;
	fail_pdu_create = TRUE;

	result = snmp_get(&host, oid_text);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(host.snmp.status, STAT_ERROR);
	assert_true(host.ignore_host);
	assert_int_equal(scripted_calls, 0);
}

static void test_varbind_allocation_failure_reads_as_unknown(void **state) {
	host_t host = {0};
	char oid_text[sizeof(sys_descr_oid)];
	char *result;

	(void) state;
	memcpy(oid_text, sys_descr_oid, sizeof(oid_text));
	host.snmp.session = (void *) (uintptr_t) 1;
	session_liberr = SNMPERR_GENERR;
	fail_add_null_var = TRUE;

	result = snmp_get(&host, oid_text);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(host.snmp.status, STAT_ERROR);
	assert_true(host.ignore_host);
	assert_int_equal(scripted_calls, 0);
}

/* An unrecognised transport status is reported as such and not decoded as a
 * session error. */
static void test_unrecognised_transport_status_is_not_decoded(void **state) {
	host_t host = {0};
	char oid_text[sizeof(sys_descr_oid)];
	char *result;

	(void) state;
	memcpy(oid_text, sys_descr_oid, sizeof(oid_text));
	host.snmp.session = (void *) (uintptr_t) 1;
	scripted_status = 77;

	result = snmp_get(&host, oid_text);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(host.snmp.status, 77);
	assert_true(host.ignore_host);
}

typedef struct {
	int liberr;
	bool recoverable;
} usm_error_t;

static const usm_error_t usm_errors[] = {
#if defined(SNMPERR_NOT_IN_TIME_WINDOW)
	{SNMPERR_NOT_IN_TIME_WINDOW, TRUE},
#elif defined(SNMPERR_USM_NOTINTIMEWINDOW)
	{SNMPERR_USM_NOTINTIMEWINDOW, TRUE},
#endif
#if defined(SNMPERR_UNKNOWN_ENG_ID)
	{SNMPERR_UNKNOWN_ENG_ID, FALSE},
#elif defined(SNMPERR_USM_UNKNOWNENGINEID)
	{SNMPERR_USM_UNKNOWNENGINEID, FALSE},
#endif
#if defined(SNMPERR_UNKNOWN_USER_NAME)
	{SNMPERR_UNKNOWN_USER_NAME, FALSE},
#elif defined(SNMPERR_USM_UNKNOWNSECURITYNAME)
	{SNMPERR_USM_UNKNOWNSECURITYNAME, FALSE},
#endif
#if defined(SNMPERR_AUTHENTICATION_FAILURE)
	{SNMPERR_AUTHENTICATION_FAILURE, FALSE},
#elif defined(SNMPERR_USM_AUTHENTICATIONFAILURE)
	{SNMPERR_USM_AUTHENTICATIONFAILURE, FALSE},
#endif
#if defined(SNMPERR_DECRYPTION_ERR)
	{SNMPERR_DECRYPTION_ERR, FALSE},
#elif defined(SNMPERR_USM_DECRYPTIONERROR)
	{SNMPERR_USM_DECRYPTIONERROR, FALSE},
#endif
#if defined(SNMPERR_UNSUPPORTED_SEC_LEVEL)
	{SNMPERR_UNSUPPORTED_SEC_LEVEL, FALSE},
#elif defined(SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL)
	{SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL, FALSE},
#endif
	{SNMPERR_GENERR, FALSE}};

/* Engine time drift recovers on the next request and must not take the host
 * out of polling; every other USM report is a failed request. */
static void test_usm_reports_are_classified(void **state) {
	char oid_text[sizeof(sys_descr_oid)];
	size_t index;
	int operation;

	(void) state;
	memcpy(oid_text, sys_descr_oid, sizeof(oid_text));
	scripted_status = STAT_ERROR;
	for (index = 0; index < sizeof(usm_errors) / sizeof(usm_errors[0]); index++) {
		for (operation = 0; operation < 2; operation++) {
			host_t host = {0};
			char *result;

			host.snmp.session = (void *) (uintptr_t) 1;
			session_liberr = usm_errors[index].liberr;
			print_message("liberr=%d operation=%d\n", session_liberr, operation);
			result = operation == 0 ? snmp_get(&host, oid_text) : snmp_getnext(&host, oid_text);
			assert_string_equal(result, "U");
			free(result);
			assert_int_equal(host.snmp.status, usm_errors[index].recoverable ? STAT_SUCCESS : STAT_ERROR);
			assert_int_equal(host.ignore_host, !usm_errors[index].recoverable);
		}
	}
}

static void test_count_stops_on_a_varbind_without_a_name(void **state) {
	host_t host = {0};
	char root[] = ".1.3.6.1.2.1.1";

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	scripted_response = TRUE;
	response_variables = 1;
	response_nameless = TRUE;

	assert_int_equal(snmp_count(&host, root), -1);
	assert_false(host.ignore_host);
	assert_int_equal(scripted_calls, 1);
}

static void test_count_stops_on_an_oversized_oid(void **state) {
	host_t host = {0};
	char root[] = ".1.3.6.1.2.1.1";

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	scripted_response = TRUE;
	response_variables = 1;
	response_long_name = TRUE;

	assert_int_equal(snmp_count(&host, root), -1);
	assert_false(host.ignore_host);
}

static void test_count_refuses_to_overflow(void **state) {
	static const oid root[] = {1, 3, 6, 1, 2, 1};
	static const oid entry[] = {1, 3, 6, 1, 2, 1, 1};
	netsnmp_variable_list variable;
	snmp_walk_t walk;

	(void) state;
	memset(&walk, 0, sizeof(walk));
	memcpy(walk.root, root, sizeof(root));
	walk.root_length = sizeof(root) / sizeof(root[0]);
	walk.count = INT_MAX;
	memset(&variable, 0, sizeof(variable));
	variable.name = (oid *) entry;
	variable.name_length = sizeof(entry) / sizeof(entry[0]);
	variable.type = ASN_INTEGER;

	assert_false(snmp_count_advance(&walk, &variable));
	assert_true(walk.failed);
	assert_int_equal(walk.count, INT_MAX);
}

static void test_count_needs_a_session_and_a_parsable_root(void **state) {
	host_t host = {0};
	char root[] = ".1.3.6.1.2.1.1";
	char unparsable[] = "not-an-oid";

	(void) state;
	assert_int_equal(snmp_count(&host, root), -1);
	assert_true(host.ignore_host);

	memset(&host, 0, sizeof(host));
	host.snmp.session = (void *) (uintptr_t) 1;
	assert_int_equal(snmp_count(&host, unparsable), -1);
	assert_false(host.ignore_host);
	assert_int_equal(scripted_calls, 0);
}

static void prepare_multi(snmp_oids_t *oids, target_t *items, const char *first, const char *second) {
	memset(oids, 0, 2 * sizeof(*oids));
	memset(items, 0, 2 * sizeof(*items));
	snprintf(oids[0].oid, sizeof(oids[0].oid), "%s", first);
	snprintf(oids[1].oid, sizeof(oids[1].oid), "%s", second);
	oids[0].array_position = 0;
	oids[1].array_position = 1;
	items[0].local_data_id = 10;
	items[1].local_data_id = 11;
}

static void test_multi_request_with_no_usable_oid_is_not_sent(void **state) {
	host_t host = {0};
	target_t items[2];
	snmp_oids_t oids[2];

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	prepare_multi(oids, items, "not-an-oid", "also-not-an-oid");

	snmp_get_multi(&host, items, oids, 2);
	assert_string_equal(oids[0].result, "U");
	assert_string_equal(oids[1].result, "U");
	assert_int_equal(host.snmp.status, STAT_ERROR);
	assert_int_equal(scripted_calls, 0);
}

static void test_multi_request_drops_an_oid_it_cannot_add(void **state) {
	host_t host = {0};
	target_t items[2];
	snmp_oids_t oids[2];

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	prepare_multi(oids, items, ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0");
	scripted_response = TRUE;
	response_variables = 1;
	fail_add_null_var = TRUE;

	snmp_get_multi(&host, items, oids, 2);
	assert_string_equal(oids[0].result, "U");
	assert_string_equal(oids[1].result, "42");
	assert_int_equal(scripted_calls, 1);
}

static void test_multi_values_missing_from_the_reply_are_unknown(void **state) {
	host_t host = {0};
	target_t items[2];
	snmp_oids_t oids[2];

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	prepare_multi(oids, items, ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0");
	scripted_response = TRUE;
	response_variables = 1;

	snmp_get_multi(&host, items, oids, 2);
	assert_string_equal(oids[0].result, "42");
	assert_string_equal(oids[1].result, "U");
}

static void test_multi_success_without_a_reply_is_unknown(void **state) {
	host_t host = {0};
	target_t items[2];
	snmp_oids_t oids[2];

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	prepare_multi(oids, items, ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0");

	snmp_get_multi(&host, items, oids, 2);
	assert_string_equal(oids[0].result, "U");
	assert_string_equal(oids[1].result, "U");
	assert_int_equal(scripted_calls, 1);
}

/* A PDU-level error names no OID (errindex 0), and an index beyond the
 * request names none we can drop; either way no value is trusted. */
static void test_multi_pdu_error_without_a_failing_oid_is_unknown(void **state) {
	const long indexes[] = {0, 9};
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(indexes) / sizeof(indexes[0]); index++) {
		host_t host = {0};
		target_t items[2];
		snmp_oids_t oids[2];

		host.snmp.session = (void *) (uintptr_t) 1;
		prepare_multi(oids, items, ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0");
		scripted_response = TRUE;
		response_variables = 2;
		response_errstat = SNMP_ERR_GENERR;
		response_errindex = indexes[index];

		snmp_get_multi(&host, items, oids, 2);
		assert_string_equal(oids[0].result, "U");
		assert_string_equal(oids[1].result, "U");
	}
}

/* Each v1 retry drops one OID, so a single OID that the agent rejects leaves
 * nothing to resend. */
static void test_multi_retry_budget_is_bounded_by_the_oid_count(void **state) {
	host_t host = {0};
	target_t items[2];
	snmp_oids_t oids[2];

	(void) state;
	host.snmp.session = (void *) (uintptr_t) 1;
	prepare_multi(oids, items, ".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.1.3.0");
	scripted_response = TRUE;
	response_variables = 2;
	response_errstat = SNMP_ERR_NOSUCHNAME;
	response_errindex = 1;

	snmp_get_multi(&host, items, oids, 1);
	assert_string_equal(oids[0].result, "U");
	assert_int_equal(scripted_calls, 1);
}

static void make_variable(netsnmp_variable_list *variable, u_char type, const oid *name, size_t length) {
	memset(variable, 0, sizeof(*variable));
	variable->type = type;
	variable->name = (oid *) name;
	variable->name_length = length;
}

static void test_missing_objects_are_unknown_unless_they_are_system_oids(void **state) {
	static const oid name[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
	netsnmp_variable_list variable;
	host_t host = {.id = 1};
	char output[RESULTS_BUFFER];

	(void) state;
	make_variable(&variable, SNMP_NOSUCHOBJECT, name, sizeof(name) / sizeof(name[0]));

	/* sysDescr is formatted as the agent reported it, with the exception text */
	assert_int_equal(snmp_get_variable(&host, sys_descr_oid, &variable, output), STAT_SUCCESS);
	assert_non_null(strstr(output, "No Such Object"));

	assert_int_equal(snmp_get_variable(&host, ".1.3.6.1.2.1.2.1.0", &variable, output), STAT_ERROR);
	assert_string_equal(output, "U");
}

static void test_missing_instances_are_unknown(void **state) {
	static const oid name[] = {1, 3, 6, 1, 6, 3, 10, 2, 1, 3, 0};
	netsnmp_variable_list variable;
	host_t host = {.id = 1};
	char output[RESULTS_BUFFER];

	(void) state;
	make_variable(&variable, SNMP_NOSUCHINSTANCE, name, sizeof(name) / sizeof(name[0]));

	assert_int_equal(snmp_get_variable(&host, ".1.3.6.1.6.3.10.2.1.3.0", &variable, output), STAT_ERROR);
	assert_string_equal(output, "U");
	assert_int_equal(snmp_get_variable(&host, ".1.3.6.1.2.1.2.1.0", &variable, output), STAT_ERROR);
	assert_string_equal(output, "U");
}

static void test_exception_check_tolerates_a_missing_varbind(void **state) {
	(void) state;
	assert_false(snmp_varbind_is_exception(NULL));
}

static void test_unprintable_ascii_value_is_an_error(void **state) {
	static const oid name[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
	netsnmp_variable_list variable;
	long value = 42;
	char output[RESULTS_BUFFER];

	(void) state;
	make_variable(&variable, ASN_INTEGER, name, sizeof(name) / sizeof(name[0]));
	variable.val.integer = &value;
	variable.val_len = sizeof(value);
	fail_ascii_string = TRUE;

	assert_int_equal(snmp_format_scalar(output, &variable, TRUE), STAT_ERROR);
	assert_string_equal(output, "U");
	fail_ascii_string = FALSE;
	assert_int_equal(snmp_format_scalar(output, &variable, TRUE), STAT_SUCCESS);
	assert_string_equal(output, "42");
}

static void test_value_formatting_without_scratch_memory_is_unknown(void **state) {
	netsnmp_variable_list variable;
	char output[77] = "unchanged";

	(void) state;
	memset(&variable, 0, sizeof(variable));
	failing_calloc = sizeof(output);

	snmp_snprint_value(output, sizeof(output), NULL, 0, &variable);
	assert_string_equal(output, "U");
}

static void init_v3_options(snmp_connection_t *options, char *auth, const char *auth_password,
	char *priv, const char *priv_passphrase) {
	static char host[] = "127.0.0.1";
	static char user[] = "snmpuser";
	static char context[] = "";
	static char engine[] = "";

	memset(options, 0, sizeof(*options));
	options->host_id = 1;
	options->hostname = host;
	options->snmp_version = 3;
	options->snmp_username = user;
	options->snmp_password = auth_password;
	options->snmp_auth_protocol = auth;
	options->snmp_priv_passphrase = priv_passphrase;
	options->snmp_priv_protocol = priv;
	options->snmp_context = context;
	options->snmp_engine_id = engine;
	options->snmp_port = 161;
	options->snmp_timeout = 500;
}

static void test_security_keys_fall_back_to_the_library_defaults(void **state) {
	struct snmp_session session;
	int pass;

	(void) state;
	for (pass = 0; pass < 2; pass++) {
		snmp_sess_init(&session);
		session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
		session.securityAuthProto = NULL;
		session.securityPrivProto = NULL;
		/* the second pass has no configured default either, so the
		 * compiled-in protocols stand in */
		null_default_protocols = pass == 1;

		assert_true(snmp_set_security_keys(&session, 1, "authpass12345", "privpass12345"));
		assert_non_null(session.securityAuthProto);
		assert_true(session.securityAuthProtoLen > 0);
		assert_non_null(session.securityPrivProto);
		assert_true(session.securityPrivProtoLen > 0);
		assert_true(session.securityAuthKeyLen > 0);
		assert_true(session.securityPrivKeyLen > 0);
		free(session.securityAuthProto);
		free(session.securityPrivProto);
	}
}

static void test_session_refused_when_a_protocol_oid_is_unavailable(void **state) {
	snmp_connection_t options;
	char sha[] = "SHA";
	char aes[] = "AES";
	char none[] = "[None]";

	(void) state;
	if (usm_lookup_auth_type(sha) <= 0 || usm_lookup_priv_type(aes) < 0) skip();

	init_v3_options(&options, sha, "authpass123", none, "");
	fail_auth_oid = TRUE;
	assert_null(snmp_host_init(&options));
	fail_auth_oid = FALSE;

	init_v3_options(&options, none, "", none, "");
	fail_no_priv_duplicate = TRUE;
	assert_null(snmp_host_init(&options));
	fail_no_priv_duplicate = FALSE;

	init_v3_options(&options, sha, "authpass123", aes, "privpass123");
	fail_priv_oid = TRUE;
	assert_null(snmp_host_init(&options));
	fail_priv_oid = FALSE;
}

static void test_engine_id_is_passed_to_the_session(void **state) {
	snmp_connection_t options;
	char none[] = "[None]";
	char engine[] = "800000090300001122334455";

	(void) state;
	init_v3_options(&options, none, "", none, "");
	options.snmp_engine_id = engine;

	assert_non_null(snmp_host_init(&options));
	assert_int_equal(captured_engine_id_len, strlen(engine));
	assert_memory_equal(captured_engine_id, engine, strlen(engine));
}

static void test_failed_session_open_returns_no_session(void **state) {
	snmp_connection_t options;
	char none[] = "[None]";

	(void) state;
	init_v3_options(&options, none, "", none, "");
	fail_session_open = TRUE;

	assert_null(snmp_host_init(&options));
}

static int snmp_group_setup(void **state) {
	(void) state;
	/* OID parsing needs the MIB subsystem the daemon initializes at startup */
	snmp_spine_init();
	return 0;
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_pdu_allocation_failure_reads_as_unknown, snmp_reset),
		cmocka_unit_test_setup(test_varbind_allocation_failure_reads_as_unknown, snmp_reset),
		cmocka_unit_test_setup(test_unrecognised_transport_status_is_not_decoded, snmp_reset),
		cmocka_unit_test_setup(test_usm_reports_are_classified, snmp_reset),
		cmocka_unit_test_setup(test_count_stops_on_a_varbind_without_a_name, snmp_reset),
		cmocka_unit_test_setup(test_count_stops_on_an_oversized_oid, snmp_reset),
		cmocka_unit_test_setup(test_count_refuses_to_overflow, snmp_reset),
		cmocka_unit_test_setup(test_count_needs_a_session_and_a_parsable_root, snmp_reset),
		cmocka_unit_test_setup(test_multi_request_with_no_usable_oid_is_not_sent, snmp_reset),
		cmocka_unit_test_setup(test_multi_request_drops_an_oid_it_cannot_add, snmp_reset),
		cmocka_unit_test_setup(test_multi_values_missing_from_the_reply_are_unknown, snmp_reset),
		cmocka_unit_test_setup(test_multi_success_without_a_reply_is_unknown, snmp_reset),
		cmocka_unit_test_setup(test_multi_pdu_error_without_a_failing_oid_is_unknown, snmp_reset),
		cmocka_unit_test_setup(test_multi_retry_budget_is_bounded_by_the_oid_count, snmp_reset),
		cmocka_unit_test_setup(test_missing_objects_are_unknown_unless_they_are_system_oids, snmp_reset),
		cmocka_unit_test_setup(test_missing_instances_are_unknown, snmp_reset),
		cmocka_unit_test_setup(test_exception_check_tolerates_a_missing_varbind, snmp_reset),
		cmocka_unit_test_setup(test_unprintable_ascii_value_is_an_error, snmp_reset),
		cmocka_unit_test_setup(test_value_formatting_without_scratch_memory_is_unknown, snmp_reset),
		cmocka_unit_test_setup(test_security_keys_fall_back_to_the_library_defaults, snmp_reset),
		cmocka_unit_test_setup(test_session_refused_when_a_protocol_oid_is_unavailable, snmp_reset),
		cmocka_unit_test_setup(test_engine_id_is_passed_to_the_session, snmp_reset),
		cmocka_unit_test_setup(test_failed_session_open_returns_no_session, snmp_reset),
	};

	return cmocka_run_group_tests(tests, snmp_group_setup, NULL);
}
