#include "common.h"
#include "spine.h"
#include "snmp_client.h"

char *spine_snmp_client_get(spine_spine_host_t *host, const char *oid) {
	return snmp_get(host, oid);
}

char *spine_snmp_client_get_base(spine_spine_host_t *host, const char *oid, int numeric) {
	return snmp_get_base(host, oid, numeric ? true : false);
}
