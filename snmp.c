#include "common.h"
#include "cactid.h"
#include "locks.h"
#include "snmp.h"

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
	struct snmp_session session;
	
	init_snmp("cactid");
	
	SOCK_STARTUP;
	
	snmp_sess_init(&session);
	
	#ifdef USE_NET_SNMP
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
	#else
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT, 1);
	ds_set_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE, 1);
	#endif
}

void snmp_free() {
	SOCK_CLEANUP;
}

char *snmp_get(char *snmp_host, char *snmp_comm, int ver, char *snmp_oid, int snmp_port, int host_id) {
	void *sessp = NULL;
	struct snmp_session session;
	struct snmp_pdu *pdu = NULL;
	struct snmp_pdu *response = NULL;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len = MAX_OID_LEN;
	struct variable_list *vars = NULL;
	
	int status;
	
	char query[BUFSIZE];
	char storedoid[BUFSIZE];
	
	char *result_string = (char *) malloc(BUFSIZE);
	
	snmp_sess_init(&session);
	
	if (set.snmp_ver == 2) {
		session.version = SNMP_VERSION_2c;
	}else{
		session.version = SNMP_VERSION_1;
	}
	
	session.peername = snmp_host;
	session.remote_port = snmp_port;
	session.community = snmp_comm;
	session.community_len = strlen(snmp_comm);
	
	mutex_lock(LOCK_SNMP);
	sessp = snmp_sess_open(&session);
	mutex_unlock(LOCK_SNMP);
	
	anOID_len = MAX_OID_LEN;
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	read_objid(snmp_oid, anOID, &anOID_len);
	
	strncpy(storedoid, snmp_oid, sizeof(storedoid));
	
	snmp_add_null_var(pdu, anOID, anOID_len);
	
	if (sessp != NULL) {
		status = snmp_sess_synch_response(sessp, pdu, &response);
	}else{
		status = STAT_DESCRIP_ERROR;
	}
	
	/* No or Bad SNMP Response */
	if (status == STAT_DESCRIP_ERROR) {
		printf("*** SNMP No response: (%s@%s).\n", session.peername, storedoid);
	}else if (status != STAT_SUCCESS) {
		printf("*** SNMP Error: (%s@%s) Unsuccessuful (%d).\n", session.peername, storedoid, status);
	}else if (status == STAT_SUCCESS && response->errstat != SNMP_ERR_NOERROR) {
		printf("*** SNMP Error: (%s@%s) %s\n", session.peername, storedoid, snmp_errstring(response->errstat));
	}
	
	/* Liftoff, successful poll, process it */
	if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
		vars = response->variables;
		
		#ifdef USE_NET_SNMP
		snprint_value(result_string, BUFSIZE, anOID, anOID_len, vars);
		#else
		sprint_value(result_string, anOID, anOID_len, vars);
		#endif
	}
	
	if (status == STAT_TIMEOUT) {
		sprintf(result_string, "%s", "E");
	}else if (!(status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR)) {
		sprintf(result_string, "%s", "U");
	}
	
	if (sessp != NULL) {
		snmp_sess_close(sessp);
		
		if (response != NULL) {
			snmp_free_pdu(response);
		}
	}
	
	return result_string;
}
