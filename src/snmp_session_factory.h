#ifndef SPINE_SNMP_SESSION_FACTORY_H
#define SPINE_SNMP_SESSION_FACTORY_H

#include "common.h"
#include "spine.h"

void *spine_snmp_session_create(int host_id, char *hostname, int snmp_version, char *snmp_community,
	char *snmp_username, char *snmp_password, char *snmp_auth_protocol,
	char *snmp_priv_passphrase, char *snmp_priv_protocol,
	char *snmp_context, char *snmp_engine_id, int snmp_port, int snmp_timeout);
void spine_snmp_session_destroy(void *sessp);

#endif
