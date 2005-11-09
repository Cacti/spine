/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 | cactid: a backend data gatherer for cacti                               |
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
#include "cactid.h"
#include "locks.h"
#include "util.h"
#include "snmp.h"

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

void snmp_cactid_init() {
	init_snmp("cactid");
}

void snmp_cactid_close() {
	snmp_shutdown("cactid");
}

void *snmp_host_init(int host_id, char *hostname, int snmp_version, char *snmp_community, 
					char *snmp_username, char *snmp_password, int snmp_port, int snmp_timeout) {
	char logmessage[LOGSIZE];
	void *sessp = NULL;
	struct snmp_session session;

	char hostnameport[BUFSIZE];

	/* initialize SNMP */
 	thread_mutex_lock(LOCK_SNMP);
	#ifdef USE_NET_SNMP
	#ifdef NETSNMP_DS_LIB_DONT_PERSIST_STATE
	/* Prevent update of the snmpapp.conf file */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
	#endif
	#ifdef NETSNMP_DS_LIB_DONT_PRIT_UNITS
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PRINT_UNITS, 1);
	#endif
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_NUMERIC_ENUM, 0);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);
	#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS, 1);
	#endif
  	snmp_sess_init(&session);
	thread_mutex_unlock(LOCK_SNMP);

	/* verify snmp version is accurate */
	if (snmp_version == 2) {
		session.version = SNMP_VERSION_2c;
	}else if (snmp_version == 1) {
		session.version = SNMP_VERSION_1;
	}else if (snmp_version == 3) {
		session.version = SNMP_VERSION_3;
	}else {
		snprintf(logmessage, LOGSIZE-1, "Host[%i] ERROR: SNMP Version Error for Host '%s'\n", host_id, hostname);
		cacti_log(logmessage);
		return;
	}		

	/* net-snmp likes the hostname in 'host:port' format */
	snprintf(hostnameport, BUFSIZE-1, "%s:%i", hostname, snmp_port);

	session.peername = hostnameport;
	session.retries = 3;
	session.remote_port = snmp_port;
	session.timeout = (snmp_timeout * 1000); /* net-snmp likes microseconds */

	if ((snmp_version == 2) || (snmp_version == 1)) {
		session.community = strdup(snmp_community);
		session.community_len = strlen(snmp_community);
	}else {
	    /* set the SNMPv3 user name */
	    session.securityName = strdup(snmp_username);
	    session.securityNameLen = strlen(session.securityName);

		session.securityAuthKeyLen = USM_AUTH_KU_LEN;

	    /* set the authentication method to MD5 */
	    session.securityAuthProto = snmp_duplicate_objid(usmHMACMD5AuthProtocol, OIDSIZE(usmHMACMD5AuthProtocol));
	    session.securityAuthProtoLen = OIDSIZE(usmHMACMD5AuthProtocol);

		/* set the privacy protocol to none */
		session.securityPrivProto = usmNoPrivProtocol;
		session.securityPrivProtoLen = OIDSIZE(usmNoPrivProtocol);
		session.securityPrivKeyLen = USM_PRIV_KU_LEN;

	    /* set the security level to authenticate, but not encrypted */
		session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;

	    /* set the authentication key to the hashed version. The password must me at least 8 char */
	    if (generate_Ku(session.securityAuthProto, 
						session.securityAuthProtoLen,
						(u_char *) snmp_password,
						strlen(snmp_password),
	                    session.securityAuthKey,
	                    &(session.securityAuthKeyLen)) != SNMPERR_SUCCESS) {
	        cacti_log("SNMP: Error generating SNMPv3 Ku from authentication pass phrase.");
		}
	}

	/* open SNMP Session */
 	thread_mutex_lock(LOCK_SNMP);
	sessp = snmp_sess_open(&session);
	thread_mutex_unlock(LOCK_SNMP);

	if (!sessp) {
		snprintf(logmessage, LOGSIZE-1, "ERROR: Problem initializing SNMP session '%s'\n", hostname);
		cacti_log(logmessage);
	}
	
	return sessp;
}

void snmp_host_cleanup(void *snmp_session) {
	if (snmp_session != NULL) {	
		snmp_sess_close(snmp_session);
	}
}

char *snmp_get(host_t *current_host, char *snmp_oid) {
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	struct variable_list *vars = NULL;
	char logmessage[LOGSIZE];
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	int status;
	char *result_string;
	
	if (!(result_string = (char *) malloc(BUFSIZE))) {
		cacti_log("ERROR: Fatal malloc error: snmp.c snmp_get!\n");
		exit_cactid();
	}
	memset(result_string, 0, BUFSIZE);

	status = STAT_DESCRIP_ERROR;

	if (current_host->snmp_session != NULL) {
		anOID_len = MAX_OID_LEN;
		pdu = snmp_pdu_create(SNMP_MSG_GET);

		if (!snmp_parse_oid(snmp_oid, anOID, &anOID_len)) {
			cacti_log("ERROR: Problems parsing SNMP OID\n");
			snprintf(result_string, BUFSIZE-1, "U");
			return result_string;
		}else{
			snmp_add_null_var(pdu, anOID, anOID_len);
		}

		/* poll host */
		status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);

		/* liftoff, successful poll, process it!! */
		if (status == STAT_SUCCESS) {
			if (response == NULL) {
				cacti_log("ERROR: Some internal error caused snmp to return null response in snmp_get\n");
				snprintf(result_string, BUFSIZE-1, "U");
				return result_string;
			}else{
				if (response->errstat == SNMP_ERR_NOERROR) {
					vars = response->variables;

					#ifdef USE_NET_SNMP
					snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
					#else
					sprint_value(result_string, anOID, anOID_len, vars);
					#endif
				}
			}
		}

		snmp_free_pdu(response);
	}else {
		status = STAT_DESCRIP_ERROR;
	}

	if ((status == STAT_TIMEOUT) || (status != STAT_SUCCESS)) {
		current_host->ignore_host = 1;
		snprintf(result_string, BUFSIZE-1, "U");
	}else if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
		snprintf(result_string, BUFSIZE-1, "U");
	}

	return result_string;
}

void snmp_snprint_value(char *obuf, size_t buf_len, const oid * objid, size_t objidlen, struct variable_list * variable) {
	u_char *buf = NULL;
	size_t out_len = 0;

	if (buf = (u_char *) calloc(buf_len, 1)) {
		if (sprint_realloc_value(&buf, &buf_len, &out_len, 1,
				objid, objidlen, variable)) {
			snprintf(obuf, buf_len, "%s", buf);
		}else{
			snprintf(obuf, buf_len, "%s [TRUNCATED]", buf);
		}
	}else{
		snprintf(obuf, buf_len, "U");
	}

	free(buf);
}

void *snmp_get_multi(host_t *current_host, snmp_oids_t *snmp_oids, int num_oids) {
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	struct variable_list *vars = NULL;
	char logmessage[LOGSIZE];
	int status;
	int i;
	size_t out_len = 0;
	int max_repetitions = 1;
	int non_repeaters = 0;
	int names;
	size_t buffer_size = 255;

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
			cacti_log("ERROR: Problems parsing Multi SNMP OID!\n");

			/* something is wrong with one of the OID's, so return errors for everyone */
			for (i = 0; i < num_oids; i++) {
				snprintf(snmp_oids[i].result, sizeof(snmp_oids[i].result)-1, "U");
			}
			return;
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
			status = STAT_DESCRIP_ERROR;
			cacti_log("ERROR: Some internal error caused snmp to return null response in snmp_get_multi.\n");
		}else{
			if (response->errstat == SNMP_ERR_NOERROR) {
				i = 0;
				for (vars = response->variables; vars; vars = vars->next_variable) {
					#ifdef USE_NET_SNMP
					snmp_snprint_value(snmp_oids[i].result, 255, vars->name, vars->name_length, vars);
					#else
					sprint_value(snmp_oids[i].result, vars->name, vars->name_length, vars);
					#endif
					i++;
				}
			}else {
				if (response->errindex != 0) {
					/* removed errored OID and then retry */
					snprintf(snmp_oids[response->errindex].result, sizeof(snmp_oids[response->errindex].result)-1, "U");
					int count;
					for (count = 1, vars = response->variables;
						vars && count != response->errindex;
						vars = vars->next_variable, count++) {
							/*EMPTY*/;
					}

					pdu = snmp_fix_pdu(response, SNMP_MSG_GET);
					snmp_free_pdu(response);
					response = NULL;
					if (pdu != NULL) {
						usleep(50);
						goto retry;
					}else{
						status = STAT_DESCRIP_ERROR;
					}
				}else {
					status = STAT_DESCRIP_ERROR;
				}
			}
		}
	}

	if (status != STAT_SUCCESS) {
		current_host->ignore_host = 1;
		for (i = 0; i < num_oids; i++) {
			snprintf(snmp_oids[i].result, sizeof(snmp_oids[i].result)-1, "U");
		}
	}

	if (response != NULL) {
		snmp_free_pdu(response);
	}
}
