/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2008 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

#ifdef USE_NET_SNMP
 #undef PACKAGE_NAME
 #undef PACKAGE_VERSION
 #undef PACKAGE_BUGREPORT
 #undef PACKAGE_STRING
 #undef PACKAGE_TARNAME
 #include <net-snmp/net-snmp-config.h>
 #include <net-snmp/utilities.h>
 #include <net-snmp/net-snmp-includes.h>
 #include <net-snmp/config_api.h>
 #include <net-snmp/mib_api.h>
#else
 #include <ucd-snmp/ucd-snmp-config.h>
 #include <ucd-snmp/ucd-snmp-includes.h>
 #include <ucd-snmp/system.h>
 #include <mib.h>
#endif

/* resolve problems in debian */
#ifndef NETSNMP_DS_LIB_DONT_PERSIST_STATE
 #define NETSNMP_DS_LIB_DONT_PERSIST_STATE 32
#endif

#define OIDSIZE(p) (sizeof(p)/sizeof(oid))

/*! \fn void snmp_spine_init()
 *  \brief wrapper function for init_snmp
 *
 *	Initializes snmp for the given application ID
 *
 */
void snmp_spine_init(void) {
#ifdef USE_NET_SNMP
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

	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);

	#ifdef PACKAGE_VERSION
		/* check that the headers we compiled with match the library we linked with -
		   apparently not defined in UCD-SNMP...
		*/
		SPINE_LOG_DEBUG(("DEBUG: SNMP Header Version is %s\n", PACKAGE_VERSION));
		SPINE_LOG_DEBUG(("DEBUG: SNMP Library Version is %s\n", netsnmp_get_version()));

		if(STRMATCH(PACKAGE_VERSION,netsnmp_get_version())) {
			init_snmp("spine");
		}else{
			/* report the error and quit spine */
			die("ERROR: SNMP Library Version Mismatch (%s vs %s)",PACKAGE_VERSION,netsnmp_get_version());
		}
	#else
		SPINE_LOG_DEBUG(("DEBUG: Issues with SNMP Header Version information, assuming old version of Net-SNMP.\n"));
		init_snmp("spine");
	#endif
#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS, 1);

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

/*! \fn void *snmp_host_init(int host_id, char *hostname, int snmp_version,
 * char *snmp_community, char *snmp_username, char *snmp_password,
 * char *snmp_auth_protocol, char *snmp_priv_passphrase, char *snmp_priv_protocol,
 * char *snmp_context, int snmp_port, int snmp_timeout)
 *  \brief initializes an snmp_session object for a Spine host
 *
 *	This function will initialize NET-SNMP or UCD-SNMP for the Spine host
 *  in question.
 *
 */
void *snmp_host_init(int host_id, char *hostname, int snmp_version, char *snmp_community,
					char *snmp_username, char *snmp_password, char *snmp_auth_protocol,
					char *snmp_priv_passphrase, char *snmp_priv_protocol,
					char *snmp_context, int snmp_port, int snmp_timeout) {

	void   *sessp = NULL;
	struct snmp_session session;
	char   hostnameport[BUFSIZE];

	/* initialize SNMP */
	snmp_sess_init(&session);

	#ifdef USE_NET_SNMP
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
	#else
		ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
		ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
		ds_set_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS, 1);
	#endif

	session.securityEngineID = 0;
	session.securityEngineIDLen = 0;

	session.securityName = 0;
	session.securityNameLen = 0;

	session.contextEngineID = 0;
	session.contextEngineIDLen = 0;

	session.contextName = 0;
	session.contextNameLen = 0;

	/* verify snmp version is accurate */
	if (snmp_version == 2) {
		session.version       = SNMP_VERSION_2c;
		session.securityModel = SNMP_SEC_MODEL_SNMPv2c;
	}else if (snmp_version == 1) {
		session.version       = SNMP_VERSION_1;
		session.securityModel = SNMP_SEC_MODEL_SNMPv1;
	}else if (snmp_version == 3) {
		session.version       = SNMP_VERSION_3;
		session.securityModel = USM_SEC_MODEL_NUMBER;
	}else {
		SPINE_LOG(("Host[%i] ERROR: SNMP Version Error for Host '%s'\n", host_id, hostname));
		return 0;
	}

	snprintf(hostnameport, BUFSIZE, "%s:%i", hostname, snmp_port);
	session.peername    = hostnameport;
	session.retries     = 3;
	session.remote_port = snmp_port;
	session.timeout     = (snmp_timeout * 1000); /* net-snmp likes microseconds */

	if ((snmp_version == 2) || (snmp_version == 1)) {
		session.community     = (unsigned char*) snmp_community;
		session.community_len = strlen(snmp_community);
	}else {
		/* set the SNMPv3 user name */
		session.securityName         = snmp_username;
		session.securityNameLen      = strlen(session.securityName);

		session.contextName          = snmp_context;
		session.contextNameLen       = strlen(session.contextName);

		session.securityAuthKeyLen   = USM_AUTH_KU_LEN;

		/* set the engineBoots and engineTime to null so that they are discovered */
		session.engineBoots          = 0;
		session.engineTime           = 0;

		/* set the authentication protocol */
		if (strcmp(snmp_auth_protocol, "MD5") == 0) {
			/* set the authentication method to MD5 */
			session.securityAuthProto    = snmp_duplicate_objid(usmHMACMD5AuthProtocol, OIDSIZE(usmHMACMD5AuthProtocol));
			session.securityAuthProtoLen = OIDSIZE(usmHMACMD5AuthProtocol);
		}else{
			/* set the authentication method to SHA1 */
			session.securityAuthProto    = snmp_duplicate_objid(usmHMACSHA1AuthProtocol, OIDSIZE(usmHMACSHA1AuthProtocol));
			session.securityAuthProtoLen = OIDSIZE(usmHMACSHA1AuthProtocol);
		}

		/* set the authentication key to the hashed version. The password must me at least 8 char */
		if (generate_Ku(session.securityAuthProto,
			session.securityAuthProtoLen,
			(u_char *) snmp_password,
			strlen(snmp_password),
			session.securityAuthKey,
			&(session.securityAuthKeyLen)) != SNMPERR_SUCCESS) {
			SPINE_LOG(("SNMP: Error generating SNMPv3 Ku from authentication pass phrase."));
		}

		/* set the privacy protocol to none */
		if (strcmp(snmp_priv_protocol, "[None]") == 0) {
			session.securityPrivProto    = snmp_duplicate_objid(usmNoPrivProtocol, OIDSIZE(usmNoPrivProtocol));
			session.securityPrivProtoLen = OIDSIZE(usmNoPrivProtocol);
			session.securityPrivKeyLen   = USM_PRIV_KU_LEN;

			/* set the security level to authenticate, but not encrypted */
			session.securityLevel        = SNMP_SEC_LEVEL_AUTHNOPRIV;
		}else{
			if (strcmp(snmp_priv_protocol, "DES") == 0) {
				session.securityPrivProto    = snmp_duplicate_objid(usmDESPrivProtocol, OIDSIZE(usmDESPrivProtocol));
				session.securityPrivProtoLen = OIDSIZE(usmDESPrivProtocol);
				session.securityPrivKeyLen   = USM_PRIV_KU_LEN;

				/* set the security level to authenticate, and encrypted */
				session.securityLevel        = SNMP_SEC_LEVEL_AUTHPRIV;
			}else{
				session.securityPrivProto    = snmp_duplicate_objid(usmAES128PrivProtocol, OIDSIZE(usmAES128PrivProtocol));
				session.securityPrivProtoLen = OIDSIZE(usmAES128PrivProtocol);
				session.securityPrivKeyLen   = USM_PRIV_KU_LEN;

				/* set the security level to authenticate, and encrypted */
				session.securityLevel        = SNMP_SEC_LEVEL_AUTHPRIV;
			}

			/* set the privacy key to the hashed version. */
			if (generate_Ku(session.securityAuthProto,
				session.securityAuthProtoLen,
				(u_char *) snmp_priv_passphrase,
				strlen(snmp_priv_passphrase),
				session.securityPrivKey,
				&(session.securityPrivKeyLen)) != SNMPERR_SUCCESS) {
				SPINE_LOG(("SNMP: Error generating SNMPv3 Ku from privacy pass phrase."));
			}
		}
	}

	/* open SNMP Session */
	thread_mutex_lock(LOCK_SNMP);
	sessp = snmp_sess_open(&session);
	thread_mutex_unlock(LOCK_SNMP);

	if (!sessp) {
		SPINE_LOG_MEDIUM(("ERROR: Problem initializing SNMP session '%s'\n", hostname));
	}

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
		snmp_sess_close(snmp_session);
	}
}

/*! \fn char *snmp_get(host_t *current_host, char *snmp_oid)
 *  \brief performs a single snmp_get for a specific snmp OID
 *
 *	This function will poll a specific snmp OID for a host.  The host snmp
 *  session must already be established.
 *
 *  \return returns the character representaton of the snmp OID, or "U" if
 *  unsuccessful.
 *
 */
char *snmp_get(host_t *current_host, char *snmp_oid) {
	struct snmp_pdu *pdu       = NULL;
	struct snmp_pdu *response  = NULL;
	struct variable_list *vars = NULL;
	size_t anOID_len           = MAX_OID_LEN;
	oid    anOID[MAX_OID_LEN];
	int    status;
	char   *result_string;

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: snmp.c snmp_get!");
	}
	result_string[0] = '\0';

	status = STAT_DESCRIP_ERROR;

	if (current_host->snmp_session != NULL) {
		anOID_len = MAX_OID_LEN;
		pdu = snmp_pdu_create(SNMP_MSG_GET);

		if (!snmp_parse_oid(snmp_oid, anOID, &anOID_len)) {
			SPINE_LOG(("ERROR: Problems parsing SNMP OID\n"));
			SET_UNDEFINED(result_string);
			return result_string;
		}else{
			snmp_add_null_var(pdu, anOID, anOID_len);
		}

		/* poll host */
		status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);

		/* liftoff, successful poll, process it!! */
		if (status == STAT_SUCCESS) {
			if (response == NULL) {
				SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get\n"));

				SET_UNDEFINED(result_string);
				status = STAT_ERROR;
			}else{
				if (response->errstat == SNMP_ERR_NOERROR) {
					vars = response->variables;

					#ifdef USE_NET_SNMP
					snprint_value(result_string, RESULTS_BUFFER, anOID, anOID_len, vars);
					#else
					sprint_value(result_string, anOID, anOID_len, vars);
					#endif
				}
			}
		}

		if (response) {
			snmp_free_pdu(response);
			response = NULL;
		}
	}else{
		status = STAT_DESCRIP_ERROR;
	}

	if (status != STAT_SUCCESS) {
		current_host->ignore_host = TRUE;

		SET_UNDEFINED(result_string);
	}

	return result_string;
}

/*! \fn char *snmp_getnext(host_t *current_host, char *snmp_oid)
 *  \brief performs a single snmp_getnext for a specific snmp OID
 *
 *	This function will poll a specific snmp OID for a host.  The host snmp
 *  session must already be established.
 *
 *  \return returns the character representaton of the snmp OID, or "U" if
 *  unsuccessful.
 *
 */
char *snmp_getnext(host_t *current_host, char *snmp_oid) {
	struct snmp_pdu *pdu       = NULL;
	struct snmp_pdu *response  = NULL;
	struct variable_list *vars = NULL;
	size_t anOID_len           = MAX_OID_LEN;
	oid    anOID[MAX_OID_LEN];
	int    status;
	char   *result_string;

	if (!(result_string = (char *) malloc(RESULTS_BUFFER))) {
		die("ERROR: Fatal malloc error: snmp.c snmp_get!");
	}
	result_string[0] = '\0';

	status           = STAT_DESCRIP_ERROR;

	if (current_host->snmp_session != NULL) {
		anOID_len = MAX_OID_LEN;
		pdu       = snmp_pdu_create(SNMP_MSG_GETNEXT);

		if (!snmp_parse_oid(snmp_oid, anOID, &anOID_len)) {
			SPINE_LOG(("ERROR: Problems parsing SNMP OID\n"));
			SET_UNDEFINED(result_string);
			return result_string;
		}else{
			snmp_add_null_var(pdu, anOID, anOID_len);
		}

		/* poll host */
		status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);

		/* liftoff, successful poll, process it!! */
		if (status == STAT_SUCCESS) {
			if (response == NULL) {
				SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get\n"));

				SET_UNDEFINED(result_string);
				status = STAT_ERROR;
			}else{
				if (response->errstat == SNMP_ERR_NOERROR) {
					vars = response->variables;

					if (vars != NULL) {
						#ifdef USE_NET_SNMP
						snprint_value(result_string, RESULTS_BUFFER, anOID, anOID_len, vars);
						#else
						sprint_value(result_string, anOID, anOID_len, vars);
						#endif
					}else{
						SET_UNDEFINED(result_string);
						status = STAT_ERROR;
					}
				}
			}
		}

		if (response) {
			snmp_free_pdu(response);
			response = NULL;
		}
	}else{
		status = STAT_DESCRIP_ERROR;
	}

	if (status != STAT_SUCCESS) {
		current_host->ignore_host = TRUE;

		SET_UNDEFINED(result_string);
	}

	return result_string;
}

/*! \fn void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, struct variable_list *variable)
 *
 *  \brief replacement for the buggy net-snmp.org snprint_value function
 *
 *	This function format an output buffer with the correct string representation
 *  of an snmp OID result fetched with snmp_get_multi.  The buffer pointed to by
 *  the function is modified.
 *
 */
void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, struct variable_list *variable) {
	u_char *buf    = NULL;
	size_t out_len = 0;

	if ((buf = (u_char *) calloc(buf_len, 1)) != 0) {
		if (sprint_realloc_value(&buf, &buf_len, &out_len, 1,
				objid, objidlen, variable)) {
			snprintf(obuf, buf_len, "%s", buf);
		}else{
			snprintf(obuf, buf_len, "%s [TRUNCATED]", buf);
		}
	}else{
		SET_UNDEFINED(obuf);
	}

	free(buf);
}

/*! \fn char *snmp_get_multi(host_t *current_host, snmp_oids_t *snmp_oids, int num_oids)
 *  \brief performs multiple OID snmp_get's in a single network call
 *
 *	This function will a group of snmp OID's for a host.  The host snmp
 *  session must already be established.  The function will modify elements of
 *  the snmp_oids array with the results from the snmp api call.
 *
 */
void snmp_get_multi(host_t *current_host, snmp_oids_t *snmp_oids, int num_oids) {
	struct snmp_pdu *pdu       = NULL;
	struct snmp_pdu *response  = NULL;
	struct variable_list *vars = NULL;
	int status;
	int i;
	int array_count;
	int index_count;

	struct nameStruct {
	    oid             name[MAX_OID_LEN];
	    size_t          name_len;
	} *name, *namep;

	/* load up oids */
	namep = name = (struct nameStruct *) calloc(num_oids, sizeof(*name));
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	for (i = 0; i < num_oids; i++) {
		namep->name_len = MAX_OID_LEN;

		if (!snmp_parse_oid(snmp_oids[i].oid, namep->name, &namep->name_len)) {
 			SPINE_LOG(("Host[%i] ERROR: Problems parsing Multi SNMP OID! (oid: %s)\n", current_host->id, snmp_oids[i].oid));

 			/* Mark this OID as "bad" */
			SET_UNDEFINED(snmp_oids[i].result);
		}else{
			snmp_add_null_var(pdu, namep->name, namep->name_len);
		}

		namep++;
	}

	status = STAT_DESCRIP_ERROR;

	/* execute the multi-get request */
	retry:
	status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);

	/* liftoff, successful poll, process it!! */
	if (status == STAT_SUCCESS) {
		if (response == NULL) {
			SPINE_LOG(("ERROR: An internal Net-Snmp error condition detected in Cacti snmp_get_multi\n"));
			status = STAT_ERROR;
		}else{
			if (response->errstat == SNMP_ERR_NOERROR) {
				vars = response->variables;

				for(i = 0; i < num_oids && vars; i++) {
					if (!IS_UNDEFINED(snmp_oids[i].result)) {
						#ifdef USE_NET_SNMP
						snmp_snprint_value(snmp_oids[i].result, RESULTS_BUFFER, vars->name, vars->name_length, vars);
						#else
						sprint_value(snmp_oids[i].result, vars->name, vars->name_length, vars);
						#endif

						vars = vars->next_variable;
					}
				}
			}else{
				if (response->errindex != 0) {
					index_count = 1;
					array_count = 0;

					/* Find our index against errindex */
					while (array_count < num_oids) {
						if (IS_UNDEFINED(snmp_oids[array_count].result) ) {
							array_count++;
						}else{
							/* if we have found our error, exit */
							if (index_count == response->errindex) {
								SET_UNDEFINED(snmp_oids[array_count].result);

								break;
							}
							array_count++;
							index_count++;
						}

					}

					/* remote the invalid OID from the PDU */
					pdu = snmp_fix_pdu(response, SNMP_MSG_GET);

					/* free the previous response */
					snmp_free_pdu(response);

					response = NULL;
					if (pdu != NULL) {
						/* retry the request */
						goto retry;
					}else{
					    /* all OID's errored out so exit cleanly */
						status = STAT_SUCCESS;
					}
				}else{
					status = STAT_DESCRIP_ERROR;
				}
			}
		}
	}

	if (status != STAT_SUCCESS) {
		current_host->ignore_host = 1;
		for (i = 0; i < num_oids; i++) {
			SET_UNDEFINED(snmp_oids[i].result);
		}
	}

	if (response != NULL) {
		snmp_free_pdu(response);
	}
}
