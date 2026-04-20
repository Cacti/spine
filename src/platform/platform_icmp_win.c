/*
 * Windows ICMP via IP Helper API, loaded dynamically.
 *
 * Rationale: the IP Helper library (iphlpapi.dll) is present in every
 * supported Windows SKU, but dynamically loading it lets spine run in
 * minimal container images that stripped the DLL and produce a clean
 * runtime error instead of failing to start. Symbol lookup happens
 * once and is cached for the process lifetime.
 */
#include "platform_icmp.h"
#include "ping_wire.h"

/* Local free-and-NULL helper. spine.h exposes SPINE_FREE() but pulls
 * in the full runtime; this TU has no business including that, so we
 * inline the same contract here. */
#define SPINE_ICMP_FREE(p) do { if ((p) != NULL) { free((void *)(p)); (p) = NULL; } } while (0)

#ifndef _WIN32
/* On POSIX this translation unit is not built; a stub keeps the
 * object file link-friendly if the build system miswires targets. */
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdlib.h>
#include <string.h>

typedef HANDLE (WINAPI *pfn_IcmpCreateFile)(VOID);
typedef BOOL   (WINAPI *pfn_IcmpCloseHandle)(HANDLE);
typedef DWORD  (WINAPI *pfn_IcmpSendEcho2Ex)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                             IPAddr, IPAddr, LPVOID, WORD,
                                             PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);
typedef HANDLE (WINAPI *pfn_Icmp6CreateFile)(VOID);
typedef DWORD  (WINAPI *pfn_Icmp6SendEcho2)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                            struct sockaddr_in6 *, struct sockaddr_in6 *,
                                            LPVOID, WORD,
                                            PIP_OPTION_INFORMATION, LPVOID, DWORD, DWORD);

static HMODULE g_iphlpapi = NULL;
static pfn_IcmpCreateFile   p_IcmpCreateFile   = NULL;
static pfn_IcmpCloseHandle  p_IcmpCloseHandle  = NULL;
static pfn_IcmpSendEcho2Ex  p_IcmpSendEcho2Ex  = NULL;
static pfn_Icmp6CreateFile  p_Icmp6CreateFile  = NULL;
static pfn_Icmp6SendEcho2   p_Icmp6SendEcho2   = NULL;
static INIT_ONCE g_iphlpapi_once = INIT_ONCE_STATIC_INIT;
static LONG g_load_ok = 0;   /* 0 = not initialized, 1 = ok, -1 = failed */

static BOOL CALLBACK spine_icmp_load_once(PINIT_ONCE init_once, PVOID param, PVOID *context) {
    (void)init_once;
    (void)param;
    (void)context;

    g_iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (g_iphlpapi == NULL) {
        g_load_ok = -1;
        return TRUE;
    }

    p_IcmpCreateFile  = (pfn_IcmpCreateFile)  GetProcAddress(g_iphlpapi, "IcmpCreateFile");
    p_IcmpCloseHandle = (pfn_IcmpCloseHandle) GetProcAddress(g_iphlpapi, "IcmpCloseHandle");
    p_IcmpSendEcho2Ex = (pfn_IcmpSendEcho2Ex) GetProcAddress(g_iphlpapi, "IcmpSendEcho2Ex");
    p_Icmp6CreateFile = (pfn_Icmp6CreateFile) GetProcAddress(g_iphlpapi, "Icmp6CreateFile");
    p_Icmp6SendEcho2  = (pfn_Icmp6SendEcho2)  GetProcAddress(g_iphlpapi, "Icmp6SendEcho2");

    if (p_IcmpCreateFile && p_IcmpCloseHandle && p_IcmpSendEcho2Ex
        && p_Icmp6CreateFile && p_Icmp6SendEcho2) {
        g_load_ok = 1;
    } else {
        g_load_ok = -1;
    }

    return TRUE;
}

static void load_iphlpapi(void) {
    (void)InitOnceExecuteOnce(&g_iphlpapi_once, spine_icmp_load_once, NULL, NULL);
}

/* Default payload used when the caller passes NULL. Mirrors the POSIX
 * behaviour so callers can rely on the facade owning payload
 * composition. Wire format comes from the single source of truth in
 * ping_wire.h. */
static void win_default_payload(spine_ping_payload_t *p) {
    p->magic = SPINE_PING_MAGIC;
    p->pid_mask = (uint32_t) GetCurrentProcessId();
    /* GetTickCount wraps at 49.7 days. The payload only needs a
     * per-send low-order marker, but the wider counter sidesteps a
     * long-uptime host getting a tiny value right after wrap. */
    p->timestamp_us = (uint32_t)(GetTickCount64() & 0xFFFFFFFFu);
}

static spine_icmp_status_t map_status(DWORD st) {
    switch (st) {
        case IP_SUCCESS:
            return SPINE_ICMP_OK;
        case IP_REQ_TIMED_OUT:
            return SPINE_ICMP_TIMEOUT;
        case IP_DEST_HOST_UNREACHABLE:
        case IP_DEST_NET_UNREACHABLE:
            return SPINE_ICMP_UNREACHABLE;
        default:
            return SPINE_ICMP_ERROR;
    }
}

int spine_icmp_echo_v4(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    struct in_addr dst;
    IPAddr dst_addr;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD reply_size;
    void *reply_buf = NULL;
    DWORD replies;
    spine_ping_payload_t default_payload;
    const void *send_payload;
    size_t send_len;

    int rc = -1;

    if (result == NULL) {
        return rc;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;

    if (ip == NULL || payload_len > 0xFF00U) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return rc;
    }

    /* Own payload composition when the caller did not provide one.
     * Forwarding NULL with payload_len>0 into IP Helper access-violates
     * inside iphlpapi.dll, so reject that case explicitly. */
    if (payload == NULL && payload_len > 0) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return rc;
    }
    if (payload == NULL) {
        win_default_payload(&default_payload);
        send_payload = &default_payload;
        send_len = sizeof(default_payload);
    } else {
        send_payload = payload;
        send_len = payload_len;
    }

    load_iphlpapi();
    if (g_load_ok != 1) {
        result->system_errno = (int) GetLastError();
        return rc;
    }

    if (InetPtonA(AF_INET, ip, &dst) != 1) {
        result->system_errno = WSAGetLastError();
        goto cleanup;
    }
    dst_addr = dst.S_un.S_addr;

    h = p_IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        result->system_errno = (int) GetLastError();
        return -1;
    }

    /* Windows requires at least sizeof(ICMP_ECHO_REPLY) + payload + 8
     * to accommodate the returned options/padding. */
    reply_size = (DWORD)(sizeof(ICMP_ECHO_REPLY) + send_len + 8);
    reply_buf = calloc(1, reply_size);
    if (reply_buf == NULL) {
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    replies = p_IcmpSendEcho2Ex(h, NULL, NULL, NULL,
                                0 /* srcaddr: any */, dst_addr,
                                (LPVOID) send_payload, (WORD) send_len,
                                NULL, reply_buf, reply_size, timeout_ms);

    if (replies > 0) {
        PICMP_ECHO_REPLY r = (PICMP_ECHO_REPLY) reply_buf;
        result->status = map_status(r->Status);
        result->rtt_us = (uint32_t) r->RoundTripTime * 1000U;
    } else {
        DWORD err = GetLastError();
        result->status = map_status(err);
        result->system_errno = (int) err;
    }

    rc = 0;

cleanup:
    SPINE_ICMP_FREE(reply_buf);
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        p_IcmpCloseHandle(h);
    }
    return rc;
}

int spine_icmp_echo_v6(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD reply_size;
    void *reply_buf = NULL;
    DWORD replies;
    spine_ping_payload_t default_payload;
    const void *send_payload;
    size_t send_len;

    int rc = -1;

    if (result == NULL) {
        return rc;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;

    if (ip == NULL || payload_len > 0xFF00U) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return rc;
    }

    if (payload == NULL && payload_len > 0) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return rc;
    }
    if (payload == NULL) {
        win_default_payload(&default_payload);
        send_payload = &default_payload;
        send_len = sizeof(default_payload);
    } else {
        send_payload = payload;
        send_len = payload_len;
    }

    load_iphlpapi();
    if (g_load_ok != 1) {
        result->system_errno = (int) GetLastError();
        return rc;
    }

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.sin6_family = AF_INET6;
    dst.sin6_family = AF_INET6;

    if (InetPtonA(AF_INET6, ip, &dst.sin6_addr) != 1) {
        result->system_errno = WSAGetLastError();
        return rc;
    }

    h = p_Icmp6CreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        result->system_errno = (int) GetLastError();
        goto cleanup;
    }

    reply_size = (DWORD)(sizeof(ICMPV6_ECHO_REPLY) + send_len + 8);
    reply_buf = calloc(1, reply_size);
    if (reply_buf == NULL) {
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        goto cleanup;
    }

    replies = p_Icmp6SendEcho2(h, NULL, NULL, NULL,
                               &src, &dst,
                               (LPVOID) send_payload, (WORD) send_len,
                               NULL, reply_buf, reply_size, timeout_ms);

    if (replies > 0) {
        PICMPV6_ECHO_REPLY r = (PICMPV6_ECHO_REPLY) reply_buf;
        result->status = map_status(r->Status);
        result->rtt_us = (uint32_t) r->RoundTripTime * 1000U;
    } else {
        DWORD err = GetLastError();
        result->status = map_status(err);
        result->system_errno = (int) err;
    }

    rc = 0;

cleanup:
    SPINE_ICMP_FREE(reply_buf);
    if (h != NULL && h != INVALID_HANDLE_VALUE) {
        p_IcmpCloseHandle(h);
    }
    return rc;
}

#endif /* _WIN32 */
