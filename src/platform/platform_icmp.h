/*
 * Platform ICMP abstraction.
 *
 * A tiny façade over the OS-specific ICMP echo primitives so the ping
 * logic in src/ping.c need not be littered with _WIN32 conditionals.
 * The POSIX side forwards back into ping.c's raw-socket path (kept as
 * the system of record) while the Windows side uses the IP Helper API
 * loaded dynamically so spine still launches when iphlpapi.dll is
 * absent (stripped WINE, nano server, etc).
 */
#ifndef SPINE_PLATFORM_ICMP_H
#define SPINE_PLATFORM_ICMP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SPINE_ICMP_OK = 0,
    SPINE_ICMP_TIMEOUT,
    SPINE_ICMP_UNREACHABLE,
    SPINE_ICMP_ERROR
} spine_icmp_status_t;

typedef struct {
    spine_icmp_status_t status;
    uint32_t rtt_us;          /* round-trip time, microseconds */
    int system_errno;         /* errno or GetLastError() */
} spine_icmp_result_t;

/* Send an ICMP echo to a numeric IPv4 dotted-quad address.
 * Returns 0 on call success (inspect result->status for outcome),
 * non-zero if the request could not be issued at all. */
int spine_icmp_echo_v4(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result);

/* Send an ICMPv6 echo to a numeric IPv6 address (may include a
 * %zone-id suffix for link-local destinations on platforms that
 * accept it). */
int spine_icmp_echo_v6(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* SPINE_PLATFORM_ICMP_H */
