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
static volatile LONG g_init_once = 0;
static volatile LONG g_load_ok = 0;   /* 0 = pending, 1 = ok, -1 = failed */

/* One-time loader. The first thread to enter runs the load; losers
 * spin until the winner publishes g_load_ok. Critical: all
 * function-pointer stores must be globally visible BEFORE g_load_ok
 * is published, and a loser thread that observes the published flag
 * must then see the initialized pointers, not stale NULLs. On ARM64
 * a plain `volatile` read is NOT an acquire, so we drive the spin
 * through InterlockedCompareExchange (a full barrier on every ISA
 * Windows supports) and close with MemoryBarrier() before the caller
 * dereferences the function pointers. */
static void load_iphlpapi(void) {
    if (InterlockedCompareExchange(&g_init_once, 1, 0) != 0) {
        /* Acquire-read g_load_ok via an interlocked no-op. A plain
         * load on ARM64 / weakly ordered hardware can satisfy the
         * `!= 0` check while the function pointer stores published
         * before g_load_ok are still invisible to this core. */
        while (InterlockedCompareExchange(&g_load_ok, 0, 0) == 0) {
            Sleep(0);  /* another thread is loading */
        }
        MemoryBarrier();
        return;
    }

    g_iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (g_iphlpapi == NULL) {
        MemoryBarrier();
        InterlockedExchange(&g_load_ok, -1);
        return;
    }

    p_IcmpCreateFile  = (pfn_IcmpCreateFile)  GetProcAddress(g_iphlpapi, "IcmpCreateFile");
    p_IcmpCloseHandle = (pfn_IcmpCloseHandle) GetProcAddress(g_iphlpapi, "IcmpCloseHandle");
    p_IcmpSendEcho2Ex = (pfn_IcmpSendEcho2Ex) GetProcAddress(g_iphlpapi, "IcmpSendEcho2Ex");
    p_Icmp6CreateFile = (pfn_Icmp6CreateFile) GetProcAddress(g_iphlpapi, "Icmp6CreateFile");
    p_Icmp6SendEcho2  = (pfn_Icmp6SendEcho2)  GetProcAddress(g_iphlpapi, "Icmp6SendEcho2");

    /* Publish all pointer stores ahead of g_load_ok so a concurrent
     * reader cannot observe a ready flag while pointers are still NULL. */
    MemoryBarrier();

    if (p_IcmpCreateFile && p_IcmpCloseHandle && p_IcmpSendEcho2Ex
        && p_Icmp6CreateFile && p_Icmp6SendEcho2) {
        InterlockedExchange(&g_load_ok, 1);
    } else {
        InterlockedExchange(&g_load_ok, -1);
    }
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
    HANDLE h;
    DWORD reply_size;
    void *reply_buf;
    DWORD replies;
    spine_ping_payload_t default_payload;
    const void *send_payload;
    size_t send_len;

    if (result == NULL) {
        return -1;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;

    if (ip == NULL || payload_len > 0xFF00U) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return -1;
    }

    /* Own payload composition when the caller did not provide one.
     * Forwarding NULL with payload_len>0 into IP Helper access-violates
     * inside iphlpapi.dll, so reject that case explicitly. */
    if (payload == NULL && payload_len > 0) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return -1;
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
        return -1;
    }

    if (InetPtonA(AF_INET, ip, &dst) != 1) {
        result->system_errno = WSAGetLastError();
        return -1;
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
        p_IcmpCloseHandle(h);
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        return -1;
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

    SPINE_ICMP_FREE(reply_buf);
    p_IcmpCloseHandle(h);
    return 0;
}

int spine_icmp_echo_v6(const char *ip, uint32_t timeout_ms,
                       const void *payload, size_t payload_len,
                       spine_icmp_result_t *result) {
    struct sockaddr_in6 src;
    struct sockaddr_in6 dst;
    HANDLE h;
    DWORD reply_size;
    void *reply_buf;
    DWORD replies;
    spine_ping_payload_t default_payload;
    const void *send_payload;
    size_t send_len;

    if (result == NULL) {
        return -1;
    }
    result->status = SPINE_ICMP_ERROR;
    result->rtt_us = 0;
    result->system_errno = 0;

    if (ip == NULL || payload_len > 0xFF00U) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return -1;
    }

    if (payload == NULL && payload_len > 0) {
        result->system_errno = ERROR_INVALID_PARAMETER;
        return -1;
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
        return -1;
    }

    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.sin6_family = AF_INET6;
    dst.sin6_family = AF_INET6;

    if (InetPtonA(AF_INET6, ip, &dst.sin6_addr) != 1) {
        result->system_errno = WSAGetLastError();
        return -1;
    }

    h = p_Icmp6CreateFile();
    if (h == INVALID_HANDLE_VALUE) {
        result->system_errno = (int) GetLastError();
        return -1;
    }

    reply_size = (DWORD)(sizeof(ICMPV6_ECHO_REPLY) + send_len + 8);
    reply_buf = calloc(1, reply_size);
    if (reply_buf == NULL) {
        p_IcmpCloseHandle(h);
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        return -1;
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

    SPINE_ICMP_FREE(reply_buf);
    p_IcmpCloseHandle(h);
    return 0;
}

#endif /* _WIN32 */
