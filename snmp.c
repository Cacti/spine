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
 #include <net-snmp-config.h>
 #include <net-snmp-includes.h>
 #include <config_api.h>
 #include <mib_api.h>
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

/* do not load mibs, Cactid does not use them */
#define DISABLE_MIB_LOADING 1

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
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
	netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, NETSNMP_OID_OUTPUT_NUMERIC);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
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
		session.community = snmp_community;
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

void snmp_host_cleanup(host_t *current_host) {
	snmp_sess_close(current_host->snmp_session);
}

char *snmp_get(host_t *current_host, char *snmp_oid) {
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	struct variable_list *vars = NULL;
	char logmessage[LOGSIZE];
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	int status;
	char *result_string = (char *) malloc(BUFSIZE);

	if (current_host->snmp_session != NULL) {
		anOID_len = MAX_OID_LEN;
		pdu = snmp_pdu_create(SNMP_MSG_GET);
		read_objid(snmp_oid, anOID, &anOID_len);
		snmp_add_null_var(pdu, anOID, anOID_len);

		if (current_host->snmp_session != NULL) {
			status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);
		}else {
			status = STAT_DESCRIP_ERROR;
		}

		/* liftoff, successful poll, process it!! */
		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
			vars = response->variables;

			#ifdef USE_NET_SNMP
			snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
			#else
			sprint_value(result_string, anOID, anOID_len, vars);
			#endif
		}
	}else {
		status = STAT_DESCRIP_ERROR;
	}

	if ((status == STAT_TIMEOUT) || (status != STAT_SUCCESS)) {
		current_host->ignore_host = 1;
		snprintf(result_string, sizeof(result_string)-1, "SNMP ERROR");
	}else if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
		snprintf(result_string, BUFSIZE-1, "U");
	}

	if (current_host->snmp_session != NULL) {
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}

	return result_string;
}

void *snmp_get_bulk(host_t *current_host, snmp_oids_t *snmp_oids, int num_oids) {
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	struct variable_list *vars = NULL;
	char logmessage[LOGSIZE];
	int status;
	int i;
	int max_repetitions = 1;
	int non_repeaters = 0;
	int names;

	struct nameStruct {
	    oid             name[MAX_OID_LEN];
	    size_t          name_len;
	} *name, *namep;

	/* load up oids */
    namep = name = (struct nameStruct *) calloc(num_oids, sizeof(*name));
    for (i = 0; i < num_oids; i++) {
        namep->name_len = MAX_OID_LEN;
		snmp_parse_oid(snmp_oids[i].oid, namep->name, &namep->name_len);
        namep++;
    }

	if (current_host->snmp_session != NULL) {
		pdu = snmp_pdu_create(SNMP_MSG_GET);
	    for (i = 0; i < num_oids; i++) {
			snmp_add_null_var(pdu, name[i].name, name[i].name_len);
		}

		/* execute the bulk get request */
		retry:
		if (current_host->snmp_session != NULL) {
			status = snmp_sess_synch_response(current_host->snmp_session, pdu, &response);
		}else {
			status = STAT_DESCRIP_ERROR;
		}

		/* liftoff, successful poll, process it!! */
		if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
			i = 0;
            for (vars = response->variables; vars; vars = vars->next_variable) {
				#ifdef USE_NET_SNMP
				snprint_value(snmp_oids[i].result, sizeof(snmp_oids[i].result)-1, vars->name, vars->name_length, vars);
				#else
				sprint_value(snmp_oids[i].result, vars->name, vars->name_length, vars);
				#endif
				i++;
			}
		}else if (response->errindex != 0) {
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
				goto retry;
			}
		}
	}else {
		status = STAT_DESCRIP_ERROR;
	}

	if ((status == STAT_TIMEOUT) || (status != STAT_SUCCESS)) {
		current_host->ignore_host = 1;
		for (i = 0; i < num_oids; i++) {
			snprintf(snmp_oids[i].result, sizeof(snmp_oids[i].result)-1, "SNMP ERROR");
		}
	}

	if (current_host->snmp_session != NULL) {
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}
}
