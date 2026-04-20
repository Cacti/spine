#ifndef SPINE_ASYNC_DNS_H
#define SPINE_ASYNC_DNS_H

#include <uv.h>

typedef struct spine_async_dns_runtime spine_async_dns_runtime_t;
typedef void (*async_dns_cb)(struct addrinfo *res, int status, void *data);

int spine_async_dns_runtime_create(uv_loop_t *dns_loop, spine_async_dns_runtime_t **out_runtime);
void spine_async_dns_runtime_destroy(spine_async_dns_runtime_t *runtime);
int spine_async_dns_lookup_runtime(spine_async_dns_runtime_t *runtime, const char *hostname, async_dns_cb cb, void *data);

/* Returns the count of uv_getaddrinfo requests submitted and not yet
 * completed. uv_getaddrinfo is a request, not a handle, so uv_walk
 * does not observe it; the shutdown path uses this to bounded-wait
 * for outstanding lookups before uv_loop_close. */
int spine_async_dns_inflight(spine_async_dns_runtime_t *runtime);

#endif
