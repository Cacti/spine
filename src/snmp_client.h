#ifndef SPINE_SNMP_CLIENT_H
#define SPINE_SNMP_CLIENT_H

#include "common.h"
#include "spine.h"

char *spine_snmp_client_get(spine_spine_host_t *host, const char *oid);
char *spine_snmp_client_get_base(spine_spine_host_t *host, const char *oid, int numeric);

#endif
