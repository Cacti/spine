/*
 * POSIX thin wrapper around the raw-socket ICMP path in src/ping.c.
 *
 * The existing spine ping implementation is the authoritative
 * producer of RTTs on POSIX (it integrates with spine's capability
 * handling and socket wrappers), so this translation unit is
 * intentionally minimal: it just exposes a numeric-address oneshot
 * primitive backed by the same underlying machinery. Callers that
 * need the host_t-driven poller path should continue to call
 * ping_icmp() / ping_icmp_ipv6() directly.
 */
#include "platform_icmp.h"

#ifdef _WIN32
/* Mirror image of the Windows fallback in the sister TU: stubs so a
 * miswired build still links, with an error status surfaced. */
int spine_icmp_echo_v4(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    (void)ip; (void)timeout_ms; (void)payload; (void)payload_len;
    if (result) {
        result->status = SPINE_ICMP_ERROR;
        result->rtt_us = 0;
        result->system_errno = 0;
    }
    return -1;
}
int spine_icmp_echo_v6(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    (void)ip; (void)timeout_ms; (void)payload; (void)payload_len;
    if (result) {
        result->status = SPINE_ICMP_ERROR;
        result->rtt_us = 0;
        result->system_errno = 0;
    }
    return -1;
}
#else

#include <arpa/inet.h>
#include <errno.h>
/* On the BSDs <netinet/ip.h> uses u_char/u_short without pulling them in, so
   <sys/types.h> has to come first or the header fails to compile. */
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Forward declarations of helpers exposed from ping.c so we can keep
 * the POSIX raw-socket logic authoritative there. */
int ping_icmp_v4_posix_numeric(const char *ip, uint32_t timeout_ms,
                               const void *payload, size_t payload_len,
                               spine_icmp_result_t *result);
int ping_icmp_v6_posix_numeric(const char *ip, uint32_t timeout_ms,
                               const void *payload, size_t payload_len,
                               spine_icmp_result_t *result);

int spine_icmp_echo_v4(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    if (result == NULL) {
        return -1;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;
    return ping_icmp_v4_posix_numeric(ip, timeout_ms, payload, payload_len, result);
}

int spine_icmp_echo_v6(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    if (result == NULL) {
        return -1;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;
    return ping_icmp_v6_posix_numeric(ip, timeout_ms, payload, payload_len, result);
}

#endif /* !_WIN32 */
