#include "common.h"
#include "spine.h"
#include "snmp_session_factory.h"

void *spine_snmp_session_create(int host_id, char *hostname, int snmp_version, char *snmp_community,
	char *snmp_username, char *snmp_password, char *snmp_auth_protocol,
	char *snmp_priv_passphrase, char *snmp_priv_protocol,
	char *snmp_context, char *snmp_engine_id, int snmp_port, int snmp_timeout) {
	return snmp_host_init(host_id, hostname, snmp_version, snmp_community,
		snmp_username, snmp_password, snmp_auth_protocol,
		snmp_priv_passphrase, snmp_priv_protocol,
		snmp_context, snmp_engine_id, snmp_port, snmp_timeout);
}

void spine_snmp_session_destroy(void *sessp) {
	snmp_host_cleanup(sessp);
}
