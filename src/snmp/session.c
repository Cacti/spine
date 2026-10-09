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
#include <limits.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/snmpusm.h>

/* resolve problems in debian */
#ifndef NETSNMP_DS_LIB_DONT_PERSIST_STATE
#define NETSNMP_DS_LIB_DONT_PERSIST_STATE 32
#endif


/*! \fn int spine_snmpv3_protocol_is_set(const char *value)
 *  \brief Whether a Cacti-supplied SNMPv3 protocol field selects anything.
 *
 *  Cacti stores the literal "[None]" when the user picks no protocol.
 */
int spine_snmpv3_protocol_is_set(const char *value) {
	if (value == NULL) {
		return FALSE;
	}

	if (value[0] == '\0') {
		return FALSE;
	}

	if (strcmp(value, "[None]") == 0) {
		return FALSE;
	}

	return TRUE;
}

/*! \fn int spine_snmpv3_passphrase_is_set(const char *value)
 *  \brief Whether a Cacti-supplied SNMPv3 passphrase is nonempty.
 *
 *  Unlike protocol fields, passphrases do not use the "[None]" sentinel. That
 *  text is therefore a valid (if weak) passphrase and must not be discarded.
 */
int spine_snmpv3_passphrase_is_set(const char *value) {
	return value != NULL && value[0] != '\0';
}

/*! \fn int spine_snmpv3_security_level(...)
 *  \brief Pick the SNMPv3 security level from the values Cacti stores.
 *
 *  Authentication needs both a protocol and a password; privacy additionally
 *  needs a privacy protocol and passphrase, and is only meaningful on top of
 *  authentication. The session builder separately refuses half-configured
 *  credential pairs before using this computed level.
 *
 *  \return SNMP_SEC_LEVEL_NOAUTH, SNMP_SEC_LEVEL_AUTHNOPRIV or
 *          SNMP_SEC_LEVEL_AUTHPRIV
 */
int spine_snmpv3_security_level(const char *auth_protocol, const char *auth_password,
	const char *priv_protocol, const char *priv_passphrase) {
	int authenticates;
	int encrypts;

	authenticates = spine_snmpv3_protocol_is_set(auth_protocol) &&
		spine_snmpv3_passphrase_is_set(auth_password);

	encrypts = authenticates &&
		spine_snmpv3_protocol_is_set(priv_protocol) &&
		spine_snmpv3_passphrase_is_set(priv_passphrase);

	if (encrypts) {
		return SNMP_SEC_LEVEL_AUTHPRIV;
	}

	if (authenticates) {
		return SNMP_SEC_LEVEL_AUTHNOPRIV;
	}

	return SNMP_SEC_LEVEL_NOAUTH;
}

/*! \fn void snmp_spine_init()
 *  \brief wrapper function for init_snmp
 *
 *	Initializes snmp for the given application ID
 *
 */
void snmp_spine_init(void) {

/* Only do numeric output */
#ifdef NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM, 1);
#endif

/* Prevent update of the snmpapp.conf file */
#ifdef NETSNMP_DS_LIB_DONT_PERSIST_STATE
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
#endif

/* Prevent update of the snmpapp.conf file */
#ifdef NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
#endif

#ifdef NETSNMP_DS_LIB_DONT_PRINT_UNITS
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PRINT_UNITS, 1);
#endif

	setenv("MIBS", "", 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);

	/* don't check the range of the OID */
	netsnmp_ds_toggle_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_CHECK_RANGE);

#if defined(VERIFY_PACKAGE_VERSION) && defined(PACKAGE_VERSION)
	/* check that the headers we compiled with match the library we linked with */
	SPINE_LOG_DEBUG(("DEBUG: SNMP Header Version is %s", PACKAGE_VERSION));
	SPINE_LOG_DEBUG(("DEBUG: SNMP Library Version is %s", netsnmp_get_version()));

	if (STRMATCH(PACKAGE_VERSION, netsnmp_get_version())) {
		init_snmp("spine");
	} else {
		/* report the error and quit spine */
		die("ERROR: SNMP Library Version Mismatch (%s vs %s)", PACKAGE_VERSION, netsnmp_get_version());
	}
#else
	SPINE_LOG_DEBUG(("DEBUG: Issues with SNMP Header Version information, assuming old version of Net-SNMP."));
	init_snmp("spine");
#endif
}

/*! \fn void snmp_spine_close()
 *  \brief wrapper function for the snmp_shutdown function
 *
 *	Closes the snmp api for the given application ID
 *
 */
void snmp_spine_close(void) {
	snmp_shutdown("spine");
}

static bool snmp_set_security_keys(struct snmp_session *session, int host_id,
	const char *auth_password, const char *priv_password) {
	char *Apsz = NULL;
	char *Xpsz = NULL;
	// Auth Protocol Setup

	Apsz = strdup(auth_password);
	if (Apsz == NULL) die("ERROR: Fatal malloc error: SNMP authentication passphrase");

	// Privacy Protocol Setup

	Xpsz = strdup(priv_password);
	if (Xpsz == NULL) {
		spine_clear_sensitive(Apsz, strlen(Apsz));
		free(Apsz);
		die("ERROR: Fatal malloc error: SNMP privacy passphrase");
	}

	session->securityAuthKeyLen = USM_AUTH_KU_LEN;
	if (session->securityAuthProto == NULL) {
		/*
		 * get .conf set default
		 */
		const oid *def = get_default_authtype(&session->securityAuthProtoLen);
		session->securityAuthProto = snmp_duplicate_objid(def, session->securityAuthProtoLen);
	}

	if (session->securityAuthProto == NULL) {
		session->securityAuthProto = snmp_duplicate_objid(SNMP_DEFAULT_AUTH_PROTO, SNMP_DEFAULT_AUTH_PROTOLEN);
		session->securityAuthProtoLen = SNMP_DEFAULT_AUTH_PROTOLEN;
	}

	if (generate_Ku(session->securityAuthProto,
			(u_int) spine_count_to_int(session->securityAuthProtoLen),
			(u_char *) Apsz, strlen(Apsz),
			session->securityAuthKey,
			&session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
		SPINE_LOG(("SNMP: Device[%i] Error generating SNMPv3 Ku from authentication passphrase.", host_id));
		if (Apsz != NULL) spine_clear_sensitive(Apsz, strlen(Apsz));
		free(Apsz);
		spine_clear_sensitive(Xpsz, strlen(Xpsz));
		free(Xpsz);
		return FALSE;
	}

	if (Apsz != NULL) spine_clear_sensitive(Apsz, strlen(Apsz));
	free(Apsz);
	Apsz = NULL;
	if (session->securityLevel == SNMP_SEC_LEVEL_AUTHNOPRIV) {
		spine_clear_sensitive(Xpsz, strlen(Xpsz));
		free(Xpsz);
		return TRUE;
	}

	session->securityPrivKeyLen = USM_PRIV_KU_LEN;
	if (session->securityPrivProto == NULL) {
		/*
		 * get .conf set default
		 */
		const oid *def = get_default_privtype(&session->securityPrivProtoLen);
		session->securityPrivProto =
			snmp_duplicate_objid(def, session->securityPrivProtoLen);
	}

	if (session->securityPrivProto == NULL) {
#ifdef HAVE_USM_DES_PRIV_PROTOCOL
		session->securityPrivProto = snmp_duplicate_objid(SNMP_DEFAULT_PRIV_PROTO, SNMP_DEFAULT_PRIV_PROTOLEN);
		session->securityPrivProtoLen = SNMP_DEFAULT_PRIV_PROTOLEN;
#else
		/* The header's default macro expands to usmDESPrivProtocol, but some
		 * distributions (e.g. Fedora) ship a net-snmp-config.h that advertises it
		 * without libnetsnmp actually exporting the symbol, which fails to link.
		 * Fall back to AES, which configure confirmed libnetsnmp provides. */
		session->securityPrivProto = snmp_duplicate_objid(usmAESPrivProtocol, OID_LENGTH(usmAESPrivProtocol));
		session->securityPrivProtoLen = OID_LENGTH(usmAESPrivProtocol);
#endif
	}

	if (generate_Ku(session->securityAuthProto,
			(u_int) spine_count_to_int(session->securityAuthProtoLen),
			(u_char *) Xpsz, strlen(Xpsz),
			session->securityPrivKey,
			&session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
		SPINE_LOG(("SNMP: Device[%i] Error generating SNMPv3 Ku from privacy pass phrase.", host_id));
		if (Apsz != NULL) spine_clear_sensitive(Apsz, strlen(Apsz));
		free(Apsz);
		spine_clear_sensitive(Xpsz, strlen(Xpsz));
		free(Xpsz);
		return FALSE;
	}

	spine_clear_sensitive(Xpsz, strlen(Xpsz));
	free(Xpsz);
	Xpsz = NULL;
	return TRUE;
}

static void snmp_host_init_release(struct snmp_session *session, char *auth, char *priv) {
	if (auth != NULL) spine_clear_sensitive(auth, strlen(auth));
	if (priv != NULL) spine_clear_sensitive(priv, strlen(priv));
	free(auth);
	free(priv);
#if SNMP_LOCALNAME == 1
	free(session->localname);
#endif
	free(session->securityAuthProto);
	free(session->securityPrivProto);
	spine_clear_sensitive(session->securityAuthKey, sizeof(session->securityAuthKey));
	spine_clear_sensitive(session->securityPrivKey, sizeof(session->securityPrivKey));
}

static bool snmp_install_auth_protocol(struct snmp_session *session, const snmp_connection_t *options) {
	/* A protocol that is set but unrecognised is a configuration error at any
	 * security level; validating only on the authenticated path would let a
	 * typo through as noAuthNoPriv. Install it whenever it is configured so a
	 * device never falls back to the library default. */
	int auth_type = usm_lookup_auth_type(options->snmp_auth_protocol);
	if (auth_type <= 0) {
		SPINE_LOG(("SNMP: Device[%i] Error auth protocol %s is invalid.", options->host_id, options->snmp_auth_protocol));
		return FALSE;
	}

	const oid *auth_proto = sc_get_auth_oid(auth_type, &session->securityAuthProtoLen);
	free(session->securityAuthProto);
	session->securityAuthProto = auth_proto == NULL ? NULL : snmp_duplicate_objid(auth_proto, session->securityAuthProtoLen);
	if (session->securityAuthProto == NULL) {
		SPINE_LOG(("SNMP: Device[%i] Error installing auth protocol %s.", options->host_id, options->snmp_auth_protocol));
		return FALSE;
	}
	return TRUE;
}

static bool snmp_set_security_protocols(struct snmp_session *session, const snmp_connection_t *options) {
	/* Cacti stores "[None]" when no protocol is selected. Match cmd.php's
	 * effective-level rules for incomplete pairs, but report the downgrade
	 * explicitly so an operator does not mistake it for auth or privacy. */
	int security_level = spine_snmpv3_security_level(options->snmp_auth_protocol, options->snmp_password,
		options->snmp_priv_protocol, options->snmp_priv_passphrase);

	/* Refusals precede downgrade warnings so the log never promises that a
	 * device will be polled when this function is about to reject it. */
	if (spine_snmpv3_passphrase_is_set(options->snmp_password) && options->snmp_auth_protocol[0] == '\0') {
		SPINE_LOG(("SNMP: Device[%i] Error authentication password is set but the authentication protocol is empty.", options->host_id));
		return FALSE;
	}

	if (spine_snmpv3_passphrase_is_set(options->snmp_priv_passphrase) && options->snmp_priv_protocol[0] == '\0') {
		SPINE_LOG(("SNMP: Device[%i] Error privacy passphrase is set but the privacy protocol is empty.", options->host_id));
		return FALSE;
	}

	/* Complete privacy credentials with no usable authentication cannot be
	 * honoured by USM. */
	if (security_level == SNMP_SEC_LEVEL_NOAUTH &&
		spine_snmpv3_protocol_is_set(options->snmp_priv_protocol) &&
		spine_snmpv3_passphrase_is_set(options->snmp_priv_passphrase)) {
		SPINE_LOG(("SNMP: Device[%i] Error privacy passphrase is configured but authentication is unavailable; set an auth protocol and password, or clear the privacy passphrase.", options->host_id));
		return FALSE;
	}

	if (spine_snmpv3_protocol_is_set(options->snmp_auth_protocol) !=
		spine_snmpv3_passphrase_is_set(options->snmp_password)) {
		SPINE_LOG_LOW(("SNMP: Device[%i] WARNING incomplete authentication settings; Cacti's effective security level is noAuthNoPriv.", options->host_id));
	}

	if (spine_snmpv3_protocol_is_set(options->snmp_priv_protocol) !=
		spine_snmpv3_passphrase_is_set(options->snmp_priv_passphrase)) {
		SPINE_LOG_LOW(("SNMP: Device[%i] WARNING incomplete privacy settings; Cacti's effective security level does not include encryption.", options->host_id));
	}

	if (spine_snmpv3_protocol_is_set(options->snmp_auth_protocol) && !snmp_install_auth_protocol(session, options)) {
		return FALSE;
	}

	session->securityLevel = security_level;

	/* Privacy follows the computed level, which requires authentication
	 * before encryption. */
	if (security_level != SNMP_SEC_LEVEL_AUTHPRIV) {
		session->securityPrivProto = snmp_duplicate_objid(usmNoPrivProtocol, OID_LENGTH(usmNoPrivProtocol));
		session->securityPrivProtoLen = OID_LENGTH(usmNoPrivProtocol);
		session->securityPrivKeyLen = 0;
		if (session->securityPrivProto == NULL) {
			session->securityPrivProtoLen = 0;
			SPINE_LOG(("SNMP: Device[%i] Error installing the no-privacy protocol.", options->host_id));
			return FALSE;
		}

		/* authNoPriv needs its authentication key derived here too. */
		if (security_level == SNMP_SEC_LEVEL_AUTHNOPRIV) {
			return snmp_set_security_keys(session, options->host_id, options->snmp_password, options->snmp_priv_passphrase);
		}
		return TRUE;
	}

	int priv_type = usm_lookup_priv_type(options->snmp_priv_protocol);
	if (priv_type < 0) {
		SPINE_LOG(("SNMP: Device[%i] Error privacy protocol %s is invalid.", options->host_id, options->snmp_priv_protocol));
		return FALSE;
	}

	const oid *priv_proto = sc_get_priv_oid(priv_type, &session->securityPrivProtoLen);
	free(session->securityPrivProto);
	session->securityPrivProto = priv_proto == NULL ? NULL : snmp_duplicate_objid(priv_proto, session->securityPrivProtoLen);
	if (session->securityPrivProto == NULL) {
		SPINE_LOG(("SNMP: Device[%i] Error installing privacy protocol %s.", options->host_id, options->snmp_priv_protocol));
		return FALSE;
	}

	return snmp_set_security_keys(session, options->host_id, options->snmp_password, options->snmp_priv_passphrase);
}

/*! \fn void *snmp_host_init(const snmp_connection_t *options)
 *  \brief initializes an owned Net-SNMP session from borrowed connection inputs.
 */
void *snmp_host_init(const snmp_connection_t *options) {
	if (options->snmp_timeout <= 0) {
		SPINE_LOG(("SNMP: Device[%i] Invalid nonpositive timeout.", options->host_id));
		return NULL;
	}
#if LONG_MAX / 1000L < INT_MAX
	if (options->snmp_timeout > LONG_MAX / 1000L) {
		SPINE_LOG(("SNMP: Device[%i] Timeout exceeds Net-SNMP's microsecond range.", options->host_id));
		return NULL;
	}
#endif

	void *sessp = NULL;
	struct snmp_session session;
	char hostnameport[BUFSIZE];

	char *Apsz = NULL;
	char *Xpsz = NULL;
	char *Cpsz = NULL;

	/* initialize SNMP */
	snmp_sess_init(&session);

	/* Bind to snmp_clientaddr if specified */
	size_t len = strlen(set.snmp.snmp_clientaddr);
	if (len > 0 && len <= SMALL_BUFSIZE) {
#if SNMP_LOCALNAME == 1
		session.localname = strdup(set.snmp.snmp_clientaddr);
#endif
	}

/* Prevent update of the snmpapp.conf file */
#ifdef NETSNMP_DS_LIB_DONT_PERSIST_STATE
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
#endif

/* Prevent update of the snmpapp.conf file */
#ifdef NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
#endif

#ifdef NETSNMP_DS_LIB_DONT_PRINT_UNITS
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PRINT_UNITS, 1);
#endif

	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);

	session.securityEngineID = NULL;
	session.securityEngineIDLen = 0;

	session.securityName = NULL;
	session.securityNameLen = 0;

	session.contextEngineID = NULL;
	session.contextEngineIDLen = 0;

	session.contextName = NULL;
	session.contextNameLen = 0;

	session.contextEngineID = NULL;
	session.contextEngineIDLen = 0;

	/* verify snmp version is accurate */
	if (options->snmp_version == 2) {
		session.version = SNMP_VERSION_2c;
		session.securityModel = SNMP_SEC_MODEL_SNMPv2c;
	} else if (options->snmp_version == 1) {
		session.version = SNMP_VERSION_1;
		session.securityModel = SNMP_SEC_MODEL_SNMPv1;
	} else if (options->snmp_version == 3) {
		session.version = SNMP_VERSION_3;
		session.securityModel = USM_SEC_MODEL_NUMBER;
	} else {
		SPINE_LOG(("Device[%i] ERROR: SNMP Version Error for Device '%s'", options->host_id, options->hostname));
		snmp_host_init_release(&session, Apsz, Xpsz);
		return 0;
	}

	snprintf(hostnameport, BUFSIZE, "%s:%i", options->hostname, options->snmp_port);
	session.peername = hostnameport;
	session.retries = set.snmp.snmp_retries;
	session.timeout = ((long) options->snmp_timeout * 1000L); /* net-snmp likes microseconds */

	SPINE_LOG_HIGH(("Device[%i] INFO: SNMP Device '%s' has a timeout of %ld (%d), with %d retries", options->host_id, hostnameport, session.timeout, options->snmp_timeout, session.retries));

	if ((options->snmp_version == 2) || (options->snmp_version == 1)) {
		session.community = (unsigned char *) options->snmp_community;
		session.community_len = strlen(options->snmp_community);
	} else {
		session.community = (unsigned char *) Cpsz;
		session.community_len = 0;

		session.securityName = options->snmp_username;
		session.securityNameLen = strlen(session.securityName);

		if (options->snmp_context && strlen(options->snmp_context)) {
			session.contextName = options->snmp_context;
			session.contextNameLen = strlen(session.contextName);
		}

		if (options->snmp_engine_id && strlen(options->snmp_engine_id)) {
			session.contextEngineID = (unsigned char *) options->snmp_engine_id;
			session.contextEngineIDLen = strlen(options->snmp_engine_id);
		}

		if (!snmp_set_security_protocols(&session, options)) {
			snmp_host_init_release(&session, Apsz, Xpsz);
			return NULL;
		}

		SPINE_LOG_MEDIUM(("Device[%i] SNMPv3 Using AuthProto: %s, PrivProto: %s", options->host_id, options->snmp_auth_protocol, options->snmp_priv_protocol));
	}

	/* open SNMP Session */
	thread_mutex_lock(LOCK_SNMP);
	sessp = snmp_sess_open(&session);
	thread_mutex_unlock(LOCK_SNMP);

	if (!sessp) {
		SPINE_LOG_DEVICE(options->host_id, POLLER_VERBOSITY_MEDIUM, ("ERROR: Device[%i] Problem initializing SNMP session '%s'", options->host_id, options->hostname));
	}

	snmp_host_init_release(&session, Apsz, Xpsz);
	return sessp;
}

/*! \fn void snmp_host_cleanup(void *snmp_session)
 *  \brief closes an established snmp session
 *
 *	This function performs cleanup of the snmp sessions once polling is completed
 *  for a host.
 *
 */
void snmp_host_cleanup(void *snmp_session) {
	if (snmp_session != NULL) {
		thread_mutex_lock(LOCK_SNMP);
		snmp_sess_close(snmp_session);
		thread_mutex_unlock(LOCK_SNMP);
	}
}
