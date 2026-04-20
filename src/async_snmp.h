#ifndef SPINE_ASYNC_SNMP_H
#define SPINE_ASYNC_SNMP_H

#include <uv.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

typedef void (*async_snmp_cb)(void *sessp, struct snmp_pdu *pdu, void *data);

/**
 * Perform an asynchronous SNMP GET request.
 * Results are returned via the callback with the provided opaque data pointer.
 */
int spine_async_snmp_get(uv_loop_t *runtime_loop, void *sessp, const char *oid_str, async_snmp_cb cb, void *data);

#endif
