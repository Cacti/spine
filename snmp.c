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

extern char **environ;

#ifdef USE_NET_SNMP
 #include <net-snmp-config.h>
 #include <net-snmp-includes.h>
#else
 #include <ucd-snmp/ucd-snmp-config.h>
 #include <ucd-snmp/ucd-snmp-includes.h>
 #include <ucd-snmp/system.h>
 #include <mib.h>
#endif

void snmp_init() {
	#ifdef USE_NET_SNMP
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NUMERIC_TIMETICKS, 1);
	#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS, 1);
	#endif
}

void snmp_host_init(host_t *current_host) {
	char logmessage[LOGSIZE];
	void *sessp = NULL;
	struct snmp_session session;

	char hostname[BUFSIZE];

	/* assume snmp session is invalid */
	current_host->snmp_session = NULL;

	/* initialize SNMP */
 	thread_mutex_lock(LOCK_SNMP);
	snmp_init();
  	snmp_sess_init(&session);
	thread_mutex_unlock(LOCK_SNMP);

	/* verify snmp version is accurate */
	if (current_host->snmp_version == 2) {
		session.version = SNMP_VERSION_2c;
	}else if (current_host->snmp_version == 1) {
		session.version = SNMP_VERSION_1;
	}else {
		snprintf(logmessage, LOGSIZE-1, "Host[%i] ERROR: SNMP Version Error for Host '%s'\n", current_host->id, current_host->hostname);
		cacti_log(logmessage);
		return;
	}		

	/* net-snmp likes the hostname in 'host:port' format */
	snprintf(hostname, BUFSIZE-1, "%s:%i", current_host->hostname, current_host->snmp_port);

	session.peername = hostname;
	session.retries = 3;
	session.remote_port = current_host->snmp_port;
	session.timeout = (current_host->snmp_timeout * 1000); /* net-snmp likes microseconds */
	session.community = current_host->snmp_community;
	session.community_len = strlen(current_host->snmp_community);

 	thread_mutex_lock(LOCK_SNMP);

	/* windows socket call */
	SOCK_STARTUP;

	/* open SNMP Session */
	sessp = snmp_sess_open(&session);

	thread_mutex_unlock(LOCK_SNMP);

	if (!sessp) {
		snprintf(logmessage, LOGSIZE-1, "ERROR: Problem initializing SNMP session '%s'\n", current_host->hostname);
		cacti_log(logmessage);
		current_host->snmp_session = NULL;
	}else{
		current_host->snmp_session = sessp;
	}
}

void snmp_host_cleanup(host_t *current_host) {
	snmp_sess_close(current_host->snmp_session);
	SOCK_CLEANUP;
}

char *snmp_get(host_t *current_host, char *snmp_oid) {
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	struct variable_list *vars = NULL;
	char logmessage[LOGSIZE];
	char storedoid[BUFSIZE];
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	int status;
	char *result_string = (char *) malloc(BUFSIZE);

	if (current_host->snmp_session != NULL) {
		/* only SNMP v1 and v2c are supported right now */
		if ((current_host->snmp_version != 1) && (current_host->snmp_version != 2)) {
			snprintf(logmessage, LOGSIZE-1, "Host[%i] ERROR: Only SNMP v1 and v2c are supported in Cactid [host: %s]\n", current_host->id, current_host->hostname);
			cacti_log(logmessage);
			snprintf(result_string, BUFSIZE-1, "%s", "U");

			return result_string;
		}

		anOID_len = MAX_OID_LEN;
		pdu = snmp_pdu_create(SNMP_MSG_GET);
		read_objid(snmp_oid, anOID, &anOID_len);
		strncpy(storedoid, snmp_oid, sizeof(storedoid));
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
		strncpy(result_string, "SNMP ERROR", BUFSIZE);
	}else if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
		snprintf(result_string, BUFSIZE-1, "%s", "U");
	}

	if (current_host->snmp_session != NULL) {
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}

	return result_string;
}
