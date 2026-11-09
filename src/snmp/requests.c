/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"
#include "snmp/response.h"
#include <limits.h>
#include <net-snmp/library/large_fd_set.h>

/* Net-SNMP's README.thread makes the single-session API (snmp_sess_*) safe
 * when one thread drives each session, which is how spine uses it, but warns
 * that SNMPv3 was never made thread-safe. USM keeps its user list and the
 * per-engine boots/time cache in process globals, and every v3 message build
 * (send, retransmit) and parse (read) uses them. v1/v2c messages never reach
 * USM, so they run without LOCK_SNMP.
 *
 * A v3 request holds the lock only while Net-SNMP is inside USM, and waits
 * for the reply in select() without it. Holding it across the wait made every
 * v3 request in the process single-threaded, and let one slow or dead device
 * stall every other thread for timeout x (retries + 1). */
typedef struct {
	long reqid;
	int status;
	bool waiting;
	struct snmp_pdu *pdu;
} snmp_wait_t;

/*! \fn static int snmp_wait_input(int op, netsnmp_session *session, int reqid, netsnmp_pdu *pdu, void *magic)
 *  \brief records the outcome of the request a v3 wait is waiting for.
 *
 *  This follows Net-SNMP's internal snmp_synch_input() so that a v3 request
 *  returns what snmp_sess_synch_response() would. It runs inside
 *  snmp_sess_read2() or snmp_sess_timeout(), so the caller holds LOCK_SNMP.
 *
 *  \return 1 when the PDU was consumed, 0 when it belongs to another request
 */
static int snmp_wait_input(int op, netsnmp_session *session, int reqid, netsnmp_pdu *pdu, void *magic) {
	snmp_wait_t *wait = (snmp_wait_t *) magic;

	if (reqid != wait->reqid && pdu != NULL && pdu->command != SNMP_MSG_REPORT) return 0;
	wait->waiting = FALSE;

	if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE && pdu != NULL) {
		if (pdu->command == SNMP_MSG_REPORT) {
			int report = snmpv3_get_report_type(pdu);

			/* Net-SNMP resends after an engine time resync, so keep waiting. */
#if defined(SNMPERR_NOT_IN_TIME_WINDOW)
			if (SNMPV3_IGNORE_UNAUTH_REPORTS || report == SNMPERR_NOT_IN_TIME_WINDOW) wait->waiting = TRUE;
#elif defined(SNMPERR_USM_NOTINTIMEWINDOW)
			if (report == SNMPERR_USM_NOTINTIMEWINDOW) wait->waiting = TRUE;
#endif
			wait->pdu = NULL;
			wait->status = STAT_ERROR;
			session->s_snmp_errno = report;
		} else if (pdu->command == SNMP_MSG_RESPONSE) {
			wait->pdu = snmp_clone_pdu(pdu);
			wait->status = STAT_SUCCESS;
			session->s_snmp_errno = SNMPERR_SUCCESS;
		} else {
			wait->status = STAT_ERROR;
			session->s_snmp_errno = SNMPERR_PROTOCOL;
			return 0;
		}
	} else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
		wait->pdu = NULL;
		wait->status = STAT_TIMEOUT;
		session->s_snmp_errno = SNMPERR_TIMEOUT;
	} else if (op == NETSNMP_CALLBACK_OP_SEC_ERROR) {
		wait->pdu = NULL;
		/* Keep an error that is already recorded. */
		if (wait->status == STAT_SUCCESS) {
			wait->status = STAT_ERROR;
			session->s_snmp_errno = SNMPERR_GENERR;
		}
	} else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
		wait->pdu = NULL;
		wait->status = STAT_ERROR;
		session->s_snmp_errno = SNMPERR_ABORT;
	}
	return 1;
}

/*! \fn static int snmp_v3_response(void *sessp, netsnmp_session *session, struct snmp_pdu *request, struct snmp_pdu **response)
 *  \brief sends one v3 request and waits for its reply, locking only USM work.
 *
 *  This is snmp_sess_synch_response() with LOCK_SNMP around the send, read and
 *  timeout calls. snmp_sess_select_info2_flags() and select() only read this
 *  session's own pending-request list, which no other thread uses.
 *
 *  \return STAT_SUCCESS, STAT_TIMEOUT or STAT_ERROR, as Net-SNMP reports them
 */
static int snmp_v3_response(void *sessp, netsnmp_session *session, struct snmp_pdu *request,
	struct snmp_pdu **response) {
	snmp_wait_t wait = {0, STAT_SUCCESS, FALSE, NULL};
	snmp_callback saved_callback = session->callback;
	void *saved_magic = session->callback_magic;
	netsnmp_large_fd_set fdset;
	struct timeval timeout;
	struct timeval *wait_timeout;
	int numfds;
	int block;
	int count;
	int select_errno;

	session->callback = snmp_wait_input;
	session->callback_magic = &wait;

	thread_mutex_lock(LOCK_SNMP);
	if (snmp_sess_send(sessp, request) == 0) {
		snmp_free_pdu(request);
		wait.status = STAT_ERROR;
	} else {
		/* The session now owns request until its reply or timeout, and only
		 * this thread can complete it. */
		wait.reqid = request->reqid;
		wait.waiting = TRUE;
	}
	thread_mutex_unlock(LOCK_SNMP);

	while (wait.waiting) {
		/* A fresh set starts empty. NETSNMP_LARGE_FD_ZERO() needs fds_bits,
		 * which glibc hides without _XOPEN_SOURCE. */
		netsnmp_large_fd_set_init(&fdset, FD_SETSIZE);
		numfds = 0;
		block = NETSNMP_SNMPBLOCK;
		timerclear(&timeout);
		wait_timeout = &timeout;
		snmp_sess_select_info2_flags(sessp, &numfds, &fdset, &timeout, &block, NETSNMP_SELECT_NOALARMS);
		if (block == 1) wait_timeout = NULL;

		count = netsnmp_large_fd_set_select(numfds, &fdset, NULL, NULL, wait_timeout);
		select_errno = errno;
		if (count > 0) {
			thread_mutex_lock(LOCK_SNMP);
			snmp_sess_read2(sessp, &fdset);
			thread_mutex_unlock(LOCK_SNMP);
		} else if (count == 0) {
			thread_mutex_lock(LOCK_SNMP);
			snmp_sess_timeout(sessp);
			thread_mutex_unlock(LOCK_SNMP);
		} else if (select_errno != EINTR) {
			session->s_snmp_errno = SNMPERR_GENERR;
			session->s_errno = select_errno;
			wait.status = STAT_ERROR;
			wait.waiting = FALSE;
		}
		netsnmp_large_fd_set_cleanup(&fdset);
	}

	*response = wait.pdu;
	session->callback = saved_callback;
	session->callback_magic = saved_magic;
	return wait.status;
}

/*! \fn static int snmp_synchronized_response(const host_t *host, struct snmp_pdu *request, struct snmp_pdu **response)
 *  \brief sends one request on the host's session and waits for the reply.
 *
 *  Net-SNMP owns and frees request in every case. Cancellation is disabled
 *  for a v3 request, which owns LOCK_SNMP between waits and points the
 *  session's callback at this stack frame.
 *
 *  \return the Net-SNMP transaction status
 */
static int snmp_synchronized_response(const host_t *host, struct snmp_pdu *request,
	struct snmp_pdu **response) {
	int status;
	int cancellation_state;
	netsnmp_session *session = snmp_sess_session(host->snmp.session);

	if (session == NULL || session->version != SNMP_VERSION_3) {
		return snmp_sess_synch_response(host->snmp.session, request, response);
	}

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation_state);
	status = snmp_v3_response(host->snmp.session, session, request, response);
	pthread_setcancelstate(cancellation_state, NULL);
	return status;
}

typedef struct {
	struct snmp_pdu *response;
	int status;
	bool valid_oid;
} snmp_reply_t;

static snmp_reply_t snmp_request_parsed(host_t *host, const oid *name, size_t length, int command) {
	snmp_reply_t reply = {NULL, STAT_DESCRIP_ERROR, TRUE};
	if (host->snmp.session == NULL) return reply;
	struct snmp_pdu *request = snmp_pdu_create(command);
	if (request == NULL) {
		SPINE_LOG(("ERROR: Unable to create SNMP PDU"));
		host->snmp.status = reply.status;
		return reply;
	}
	if (snmp_add_null_var(request, name, length) == NULL) {
		snmp_free_pdu(request);
		reply.status = STAT_ERROR;
		host->snmp.status = reply.status;
		return reply;
	}
	/* Net-SNMP owns and frees request after the synchronous call, including
	 * a failed send; the caller owns only the returned response. */
	reply.status = snmp_synchronized_response(host, request, &reply.response);
	host->snmp.status = reply.status;
	return reply;
}

static snmp_reply_t snmp_single_request(host_t *host, char *text_oid, int command) {
	snmp_reply_t reply = {NULL, STAT_DESCRIP_ERROR, TRUE};
	if (host->snmp.session == NULL) return reply;
	oid parsed[MAX_OID_LEN];
	size_t length = MAX_OID_LEN;
	if (!snmp_parse_oid(text_oid, parsed, &length)) {
		SPINE_LOG(("Device[%i] ERROR: Problems parsing SNMP OID %s", host->id, text_oid));
		reply.status = STAT_ERROR;
		reply.valid_oid = FALSE;
		host->snmp.status = reply.status;
		return reply;
	}
	return snmp_request_parsed(host, parsed, length, command);
}




/* Decode a USM report instead of logging a generic error. New constant names
 * (SNMPERR_NOT_IN_TIME_WINDOW etc.) arrived in Net-SNMP 5.8 and the old ones
 * (SNMPERR_USM_NOTINTIMEWINDOW etc.) in 5.7; on older versions every USM error
 * falls through to the default case. notInTimeWindow is engine time drift and
 * recovers on the next request, so it does not mark the host down. */
static int snmp_decode_session_error(host_t *host, const char *text_oid, const char *operation, int status, char *output) {
	int liberr = 0;
	int syserr = 0;
	char *errstr = NULL;

	if (status != STAT_ERROR || host->snmp.session == NULL) {
		SPINE_LOG_HIGH(("ERROR: Unknown error getting oid '%s' for Device[%i] with Status[%d]", text_oid, host->id, status));
		return status;
	}

	snmp_sess_error(host->snmp.session, &liberr, &syserr, &errstr);
	SPINE_LOG_DEBUG(("Device[%i] DEBUG: SNMP %ssession error for oid '%s': %s (liberr=%d)",
		host->id, operation, text_oid, errstr ? errstr : "unknown", liberr));
	SNMP_FREE(errstr);

	switch (liberr) {
#if defined(SNMPERR_NOT_IN_TIME_WINDOW) || defined(SNMPERR_USM_NOTINTIMEWINDOW)
#if defined(SNMPERR_NOT_IN_TIME_WINDOW)
		case SNMPERR_NOT_IN_TIME_WINDOW:
#else
		case SNMPERR_USM_NOTINTIMEWINDOW:
#endif
			SPINE_LOG_MEDIUM(("WARNING: Device[%i] USM notInTimeWindow for %soid '%s' -- engine time drift (recoverable)",
				host->id, operation, text_oid));
			SET_UNDEFINED(output);
			host->snmp.status = STAT_SUCCESS;
			return STAT_SUCCESS;
#endif
#if defined(SNMPERR_UNKNOWN_ENG_ID) || defined(SNMPERR_USM_UNKNOWNENGINEID)
#if defined(SNMPERR_UNKNOWN_ENG_ID)
		case SNMPERR_UNKNOWN_ENG_ID:
#else
		case SNMPERR_USM_UNKNOWNENGINEID:
#endif
			SPINE_LOG_HIGH(("ERROR: Device[%i] USM unknownEngineID for %soid '%s'", host->id, operation, text_oid));
			break;
#endif
#if defined(SNMPERR_UNKNOWN_USER_NAME) || defined(SNMPERR_USM_UNKNOWNSECURITYNAME)
#if defined(SNMPERR_UNKNOWN_USER_NAME)
		case SNMPERR_UNKNOWN_USER_NAME:
#else
		case SNMPERR_USM_UNKNOWNSECURITYNAME:
#endif
			SPINE_LOG_HIGH(("ERROR: Device[%i] USM unknownSecurityName for %soid '%s'", host->id, operation, text_oid));
			break;
#endif
#if defined(SNMPERR_AUTHENTICATION_FAILURE) || defined(SNMPERR_USM_AUTHENTICATIONFAILURE)
#if defined(SNMPERR_AUTHENTICATION_FAILURE)
		case SNMPERR_AUTHENTICATION_FAILURE:
#else
		case SNMPERR_USM_AUTHENTICATIONFAILURE:
#endif
			SPINE_LOG_HIGH(("ERROR: Device[%i] USM authenticationFailure for %soid '%s'", host->id, operation, text_oid));
			break;
#endif
#if defined(SNMPERR_DECRYPTION_ERR) || defined(SNMPERR_USM_DECRYPTIONERROR)
#if defined(SNMPERR_DECRYPTION_ERR)
		case SNMPERR_DECRYPTION_ERR:
#else
		case SNMPERR_USM_DECRYPTIONERROR:
#endif
			SPINE_LOG_HIGH(("ERROR: Device[%i] USM decryptionError for %soid '%s'", host->id, operation, text_oid));
			break;
#endif
#if defined(SNMPERR_UNSUPPORTED_SEC_LEVEL) || defined(SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL)
#if defined(SNMPERR_UNSUPPORTED_SEC_LEVEL)
		case SNMPERR_UNSUPPORTED_SEC_LEVEL:
#else
		case SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL:
#endif
			SPINE_LOG_HIGH(("ERROR: Device[%i] USM unsupportedSecurityLevel for %soid '%s'", host->id, operation, text_oid));
			break;
#endif
		default:
			SPINE_LOG_HIGH(("ERROR: Unknown error getting oid '%s' for Device[%i] with Status[%d] Errno[%d]",
				text_oid, host->id, status, liberr));
			break;
	}

	return status;
}

static int snmp_get_response(host_t *host, const char *text_oid, const snmp_reply_t *reply, char *output) {
	if (reply->status == STAT_DESCRIP_ERROR) {
		SET_UNDEFINED(output);
		return STAT_ERROR;
	}
	if (reply->status == STAT_SUCCESS) {
		if (reply->response == NULL) {
			SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get"));
			SET_UNDEFINED(output);
			return STAT_ERROR;
		}
		if (reply->response->errstat == SNMP_ERR_NOERROR && reply->response->variables != NULL && reply->response->variables->name != NULL) {
			return snmp_get_variable(host, text_oid, reply->response->variables, output);
		}
		/* An agent error (noSuchName, genErr, ...) or a reply without a usable
		 * varbind still proves the agent is reachable, so availability keeps
		 * the transport-success status. The value is unknown: an empty string
		 * would be stored as data, and a reindex assertion would take it as
		 * a new baseline (=) or as 0 (<) and reindex again. */
		SPINE_LOG_HIGH(("ERROR: Failed to get oid '%s' for Device[%i] with Response[%ld]", text_oid, host->id, reply->response->errstat));
		SET_UNDEFINED(output);
		return STAT_SUCCESS;
	}
	if (reply->response != NULL && reply->response->variables != NULL) {
		SET_UNDEFINED(output);
		SPINE_LOG_HIGH(("ERROR: Agent error getting oid '%s' for Device[%i] with Status[%d]", text_oid, host->id, reply->status));
		return STAT_ERROR;
	}
	if (reply->status == STAT_TIMEOUT) {
		SPINE_LOG_HIGH(("ERROR: Timeout getting oid '%s' for Device[%i] with Status[%d]", text_oid, host->id, reply->status));
		return reply->status;
	}
	return snmp_decode_session_error(host, text_oid, "", reply->status, output);
}

/*! \fn char *snmp_get_base(host_t *current_host, char *snmp_oid, bool should_fail)
 *  \brief performs a single snmp_get for a specific snmp OID
 *
 *	This function will poll a specific snmp OID for a host.  The host snmp
 *  session must already be established.
 *
 *  \return returns the character representation of the snmp OID, or "U" if
 *  unsuccessful.
 *
 */
char *snmp_get_base(host_t *host, char *text_oid, bool should_fail) {
	char *output = calloc(RESULTS_BUFFER, 1);
	if (output == NULL) die("ERROR: Fatal malloc error: snmp.c snmp_get!");
	if (host->ignore_host) {
		SPINE_LOG_HIGH(("WARNING: Skipped oid '%s' for Device[%i] as host ignore flag is active", text_oid, host->id));
		SET_UNDEFINED(output);
		return output;
	}
	snmp_reply_t reply = snmp_single_request(host, text_oid, SNMP_MSG_GET);
	if (!reply.valid_oid) {
		SET_UNDEFINED(output);
		return output;
	}
	int status = reply.status;
	if (host->snmp.session != NULL) status = snmp_get_response(host, text_oid, &reply, output);
	if (reply.response != NULL) snmp_free_pdu(reply.response);
	host->snmp.status = status;
	/* A failed read is unknown even when the caller tolerates the failure;
	 * an empty string would be stored as if the agent had sent it. */
	if (status != STAT_SUCCESS) {
		if (should_fail) host->ignore_host = TRUE;
		SET_UNDEFINED(output);
	}
	return output;
}

char *snmp_get(host_t *host, char *text_oid) {
	return snmp_get_base(host, text_oid, TRUE);
}

/* System OIDs may legitimately be absent; a NoSuchObject there must not
 * mark the host ignored and suppress the rest of its polling. */
char *snmp_get_allow_fail(host_t *host, char *text_oid) {
	return snmp_get_base(host, text_oid, FALSE);
}

char *snmp_getnext(host_t *host, char *text_oid) {
	char *output = calloc(RESULTS_BUFFER, 1);
	if (output == NULL) die("ERROR: Fatal malloc error: snmp.c snmp_getnext!");
	snmp_reply_t reply = snmp_single_request(host, text_oid, SNMP_MSG_GETNEXT);
	if (!reply.valid_oid) {
		SET_UNDEFINED(output);
		return output;
	}
	int status = reply.status;
	if (status == STAT_SUCCESS) {
		if (reply.response == NULL) {
			SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_getnext"));
			status = STAT_ERROR;
		} else if (reply.response->errstat == SNMP_ERR_NOERROR) {
			const struct variable_list *variable = reply.response->variables;
			if (variable != NULL && snmp_varbind_is_exception(variable)) {
				/* endOfMibView and noSuch* come from a reachable agent: the
				 * value is unknown, the host is not. */
				SET_UNDEFINED(output);
			} else {
				status = variable == NULL ? STAT_ERROR : snmp_format_scalar(output, variable, TRUE);
			}
		} else {
			/* As in snmp_get_base(): reachable agent, unknown value. */
			SET_UNDEFINED(output);
		}
	} else if (status == STAT_TIMEOUT) {
		SPINE_LOG_HIGH(("ERROR: Timeout getting oid '%s' for Device[%i] with Status[%d]", text_oid, host->id, status));
	} else if (status == STAT_ERROR) {
		status = snmp_decode_session_error(host, text_oid, "getnext ", status, output);
	}
	if (reply.response != NULL) snmp_free_pdu(reply.response);
	host->snmp.status = status;
	if (status != STAT_SUCCESS) {
		host->ignore_host = TRUE;
		SET_UNDEFINED(output);
	}
	return output;
}

typedef struct {
	oid root[MAX_OID_LEN];
	size_t root_length;
	oid current[MAX_OID_LEN];
	size_t current_length;
	int count;
	bool failed;
} snmp_walk_t;

static bool snmp_count_advance(snmp_walk_t *walk, const struct variable_list *variable) {
	if (variable->name == NULL || variable->name_length > MAX_OID_LEN) {
		walk->failed = TRUE;
		return FALSE;
	}
	if (variable->name_length < walk->root_length || memcmp(walk->root, variable->name, walk->root_length * sizeof(oid)) != 0) return FALSE;
	if (walk->count == INT_MAX) {
		SPINE_LOG(("ERROR: SNMP table count exceeds supported integer range"));
		walk->failed = TRUE;
		return FALSE;
	}
	/* The walk terminator is not a table entry, so it does not count. */
	if (variable->type == SNMP_ENDOFMIBVIEW || variable->type == SNMP_NOSUCHOBJECT || variable->type == SNMP_NOSUCHINSTANCE) return FALSE;
	walk->count++;
	if (snmp_oid_compare(walk->current, walk->current_length, variable->name, variable->name_length) >= 0) {
		SPINE_LOG(("ERROR: OID not increasing"));
		walk->failed = TRUE;
		return FALSE;
	}
	memcpy(walk->current, variable->name, variable->name_length * sizeof(oid));
	walk->current_length = variable->name_length;
	return TRUE;
}

static bool snmp_count_response(snmp_walk_t *walk, const snmp_reply_t *reply) {
	/* SNMPv1 has no endOfMibView variable type; it reports the normal end of a
	 * GETNEXT walk as a PDU-level noSuchName instead. */
	if (reply->status == STAT_SUCCESS && reply->response != NULL && reply->response->errstat == SNMP_ERR_NOSUCHNAME) return FALSE;
	if (reply->status != STAT_SUCCESS || reply->response == NULL || reply->response->errstat != SNMP_ERR_NOERROR || reply->response->variables == NULL) {
		SPINE_LOG(("ERROR: %s detected in Cacti snmp_count", reply->status == STAT_TIMEOUT ? "Timeout" : "Invalid SNMP response"));
		walk->failed = TRUE;
		return FALSE;
	}
	for (const struct variable_list *variable = reply->response->variables; variable != NULL; variable = variable->next_variable) {
		if (!snmp_count_advance(walk, variable)) return FALSE;
	}
	return TRUE;
}

/*! \fn char *snmp_count(host_t *current_host, char *snmp_oid)
 *  \brief counts entries of snmp table specified by a specific snmp OID
 *
 *	This function will poll a specific snmp OID for a host.  The host snmp
 *  session must already be established.
 *
 *  \return returns count of table entries
 *
 */
int snmp_count(host_t *host, char *text_oid) {
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("DEBUG: walk starts at OID %s", text_oid));
	if (host->snmp.session == NULL) {
		host->ignore_host = TRUE;
		return -1;
	}
	snmp_walk_t walk = {0};
	walk.root_length = MAX_OID_LEN;
	if (!snmp_parse_oid(text_oid, walk.root, &walk.root_length)) {
		SPINE_LOG(("Device[%i] ERROR: SNMP Count Problems parsing SNMP OID %s", host->id, text_oid));
		return -1;
	}
	memcpy(walk.current, walk.root, walk.root_length * sizeof(oid));
	walk.current_length = walk.root_length;
	bool more = TRUE;
	while (more) {
		snmp_reply_t reply = snmp_request_parsed(host, walk.current, walk.current_length, SNMP_MSG_GETNEXT);
		more = snmp_count_response(&walk, &reply);
		if (reply.response != NULL) snmp_free_pdu(reply.response);
	}
	/* host->snmp.status holds the last transport outcome. An agent that
	 * answered with an error or a broken walk is still reachable, so only
	 * this count becomes U and the rest of the host keeps polling. */
	if (walk.failed && host->snmp.status != STAT_SUCCESS) host->ignore_host = TRUE;
	/* A negative count tells the caller this walk never produced a usable
	 * result, so it is not mistaken for a legitimate zero-item count. */
	return walk.failed ? -1 : walk.count;
}

static void snmp_multi_undefined(snmp_oids_t *oids, int count) {
	for (int index = 0; index < count; index++) SET_UNDEFINED(oids[index].result);
}

static struct snmp_pdu *snmp_multi_request(const host_t *host, const target_t *items, snmp_oids_t *oids, int count) {
	struct snmp_pdu *request = snmp_pdu_create(SNMP_MSG_GET);
	if (request == NULL) return NULL;
	for (int index = 0; index < count; index++) {
		if (IS_UNDEFINED(oids[index].result)) continue;
		oid name[MAX_OID_LEN];
		size_t length = MAX_OID_LEN;
		if (!snmp_parse_oid(oids[index].oid, name, &length)) {
			SPINE_LOG(("Device[%i] DS[%i] ERROR: Problems parsing Multi SNMP OID! (oid: %s), Set MAX_OIDS to 1 for this host to isolate bad OID", host->id, items[oids[index].array_position].local_data_id, oids[index].oid));
			SET_UNDEFINED(oids[index].result);
		} else if (snmp_add_null_var(request, name, length) == NULL) {
			SET_UNDEFINED(oids[index].result);
		}
	}
	if (request->variables == NULL) {
		snmp_free_pdu(request);
		return NULL;
	}
	return request;
}

static bool snmp_multi_error_index(snmp_oids_t *oids, int count, long error_index) {
	long current = 0;
	for (int index = 0; index < count; index++) {
		if (IS_UNDEFINED(oids[index].result)) continue;
		if (++current == error_index) {
			SET_UNDEFINED(oids[index].result);
			return TRUE;
		}
	}
	return FALSE;
}

/*! \fn int snmp_varbind_is_exception(const struct variable_list *vars)
 *  \brief report whether a varbind carries a per-OID exception rather than data
 *
 *  Under SNMPv2c an agent reports a single unanswerable OID as an inline
 *  exception varbind while the PDU errstat stays SNMP_ERR_NOERROR. Passing one
 *  to snprint_value() renders the exception as text, which then gets stored as
 *  though it were a real value.
 *
 *  \return TRUE when the varbind is an exception
 */


/*! \fn static const struct variable_list *snmp_multi_match(const struct variable_list *positional, const struct variable_list *variables, const char *text_oid)
 *  \brief finds the reply varbind that names a requested OID.
 *
 *  Agents normally answer in request order, so the varbind at the request's
 *  position is tried first. An agent that reorders or drops varbinds would
 *  otherwise have one OID's value stored against another data source.
 *
 *  \return the matching varbind, or NULL when the reply does not name it
 */
static const struct variable_list *snmp_multi_match(const struct variable_list *positional,
	const struct variable_list *variables, const char *text_oid) {
	oid name[MAX_OID_LEN];
	size_t length = MAX_OID_LEN;

	if (!snmp_parse_oid(text_oid, name, &length)) return NULL;
	if (positional != NULL && positional->name != NULL &&
		snmp_oid_compare(positional->name, positional->name_length, name, length) == 0) {
		return positional;
	}
	for (const struct variable_list *variable = variables; variable != NULL; variable = variable->next_variable) {
		if (variable->name != NULL && snmp_oid_compare(variable->name, variable->name_length, name, length) == 0) {
			return variable;
		}
	}
	return NULL;
}

static void snmp_multi_values(const host_t *host, snmp_oids_t *oids, int count, const struct variable_list *variables) {
	const struct variable_list *positional = variables;

	for (int index = 0; index < count; index++) {
		const struct variable_list *variable;

		if (IS_UNDEFINED(oids[index].result)) continue;
		variable = snmp_multi_match(positional, variables, oids[index].oid);
		if (positional != NULL) positional = positional->next_variable;
		if (variable == NULL) {
			SPINE_LOG_HIGH(("Device[%i] WARNING: SNMP reply does not name OID '%s'", host->id, oids[index].oid));
			SET_UNDEFINED(oids[index].result);
			continue;
		}
		if (snmp_varbind_is_exception(variable)) {
			SPINE_LOG_HIGH(("Device[%i] WARNING: No SNMP data returned for OID '%s'", host->id, oids[index].oid));
			SET_UNDEFINED(oids[index].result);
		} else {
			snmp_format_scalar(oids[index].result, variable, FALSE);
		}
	}
}

/*! \fn char *snmp_get_multi(host_t *current_host, const target_t *poller_items, snmp_oids_t *snmp_oids, int num_oids)
 *  \brief performs multiple OID snmp_get's in a single network call
 *
 *	This function will a group of snmp OID's for a host.  The host snmp
 *  session must already be established.  The function will modify elements of
 *  the snmp_oids array with the results from the snmp api call.
 *
 */
void snmp_get_multi(host_t *host, const target_t *items, snmp_oids_t *oids, int count) {
	if (count <= 0) return;
	if (host == NULL || items == NULL || oids == NULL) die("ERROR: Invalid multi-SNMP request storage");
	if (host->snmp.session == NULL) {
		/* A failed mid-loop session rebuild fails the group as one host error. */
		host->ignore_host = TRUE;
		snmp_multi_undefined(oids, count);
		host->snmp.status = STAT_DESCRIP_ERROR;
		return;
	}
	struct snmp_pdu *request = snmp_multi_request(host, items, oids, count);
	if (request == NULL) {
		snmp_multi_undefined(oids, count);
		host->snmp.status = STAT_ERROR;
		return;
	}
	int status = STAT_DESCRIP_ERROR;
	/* Every v1 retry removes one valid OID, so at most count requests are
	 * possible. The synchronous call consumes each submitted request. */
	int attempt = 0;
	while (request != NULL && attempt < count) {
		attempt++;
		struct snmp_pdu *response = NULL;
		status = snmp_synchronized_response(host, request, &response);
		request = NULL;
		host->snmp.status = status;
		if (status == STAT_SUCCESS) {
			if (response == NULL) {
				SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get_multi"));
				status = STAT_ERROR;
				snmp_multi_undefined(oids, count);
			} else if (response->errstat == SNMP_ERR_NOERROR) {
				snmp_multi_values(host, oids, count, response->variables);
			} else if (snmp_multi_error_index(oids, count, response->errindex)) {
				request = snmp_fix_pdu(response, SNMP_MSG_GET);
			} else {
				if (response->errindex == 0) {
					/* RFC 3416 4.2: a PDU-level error names no failing OID. */
					SPINE_LOG_HIGH(("Device[%i] WARNING: snmp_get_multi PDU error (errstat=%ld, errindex=0), all OIDs set undefined",
						host->id, (long) response->errstat));
				}
				status = STAT_ERROR;
				snmp_multi_undefined(oids, count);
			}
		}
		if (response != NULL) snmp_free_pdu(response);
	}
	if (request != NULL) {
		snmp_free_pdu(request);
		status = STAT_ERROR;
		snmp_multi_undefined(oids, count);
	}
	if (status == STAT_TIMEOUT) {
		host->ignore_host = TRUE;
		snmp_multi_undefined(oids, count);
	}
}
