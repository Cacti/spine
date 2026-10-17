/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "internal/common.h"
#include "app/spine.h"
#include "snmp/response.h"
#include <limits.h>

/* USM users and engine state are shared by otherwise independent sessions.
 * V1/v2c retain the single-session API's parallel requests. A v3 transaction
 * is exclusive with session construction/cleanup and other v3 transactions.
 * Disable cancellation while owning the shared lock. */
static int snmp_synchronized_response(const host_t *host, struct snmp_pdu *request,
	struct snmp_pdu **response) {
	int status;
	int cancellation_state;
	const struct snmp_session *session = snmp_sess_session(host->snmp.session);
	bool serialized = session == NULL || session->version == SNMP_VERSION_3;

	if (serialized) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation_state);
		thread_mutex_lock(LOCK_SNMP);
	}
	status = snmp_sess_synch_response(host->snmp.session, request, response);
	if (serialized) {
		thread_mutex_unlock(LOCK_SNMP);
		pthread_setcancelstate(cancellation_state, NULL);
	}
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
		/* Preserve the legacy transport-success outcome for an agent error:
		 * availability observes host->snmp_status, while data remains empty. */
		SPINE_LOG_HIGH(("ERROR: Failed to get oid '%s' for Device[%i] with Response[%ld]", text_oid, host->id, reply->response->errstat));
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
	if (status != STAT_SUCCESS && should_fail) {
		host->ignore_host = TRUE;
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
			status = variable == NULL || snmp_varbind_is_exception(variable) ? STAT_ERROR : snmp_format_scalar(output, variable, TRUE);
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
	if (walk.failed) {
		host->ignore_host = TRUE;
		if (host->snmp.status == STAT_SUCCESS) host->snmp.status = STAT_ERROR;
	}
	/* A negative count tells the caller this walk never produced a usable
	 * result, so it is not mistaken for a legitimate zero-item count. */
	return walk.failed ? -1 : walk.count;
}

/*! \fn void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, const struct variable_list *variable)
 *
 *  \brief replacement for the buggy net-snmp.org snprint_value function
 *
 *	This function format an output buffer with the correct string representation
 *  of an snmp OID result fetched with snmp_get_multi.  The buffer pointed to by
 *  the function is modified.
 *
 */


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


static void snmp_multi_values(const host_t *host, snmp_oids_t *oids, int count, const struct variable_list *variable) {
	for (int index = 0; index < count; index++) {
		if (IS_UNDEFINED(oids[index].result)) continue;
		if (variable == NULL) {
			SET_UNDEFINED(oids[index].result);
			continue;
		}
		if (snmp_varbind_is_exception(variable)) {
			SPINE_LOG_HIGH(("Device[%i] WARNING: No SNMP data returned for OID '%s'", host->id, oids[index].oid));
			SET_UNDEFINED(oids[index].result);
		} else {
			snmp_format_scalar(oids[index].result, variable, FALSE);
		}
		variable = variable->next_variable;
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
