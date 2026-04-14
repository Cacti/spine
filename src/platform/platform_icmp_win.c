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
static int g_load_ok = 0;

static void load_iphlpapi(void) {
    /* Windows has no stdatomic guarantees pre-VS2019 for MSVC, and
     * this is called from many threads. InterlockedCompareExchange
     * gives us a single-winner load with a full barrier. */
    if (InterlockedCompareExchange(&g_init_once, 1, 0) != 0) {
        while (g_load_ok == 0 && g_iphlpapi == NULL) {
            Sleep(0);  /* another thread is loading */
        }
        return;
    }

    g_iphlpapi = LoadLibraryW(L"iphlpapi.dll");
    if (g_iphlpapi == NULL) {
        g_load_ok = -1;
        return;
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
    reply_size = (DWORD)(sizeof(ICMP_ECHO_REPLY) + payload_len + 8);
    reply_buf = calloc(1, reply_size);
    if (reply_buf == NULL) {
        p_IcmpCloseHandle(h);
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        return -1;
    }

    replies = p_IcmpSendEcho2Ex(h, NULL, NULL, NULL,
                                0 /* srcaddr: any */, dst_addr,
                                (LPVOID) payload, (WORD) payload_len,
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

    free(reply_buf);
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

    reply_size = (DWORD)(sizeof(ICMPV6_ECHO_REPLY) + payload_len + 8);
    reply_buf = calloc(1, reply_size);
    if (reply_buf == NULL) {
        p_IcmpCloseHandle(h);
        result->system_errno = ERROR_NOT_ENOUGH_MEMORY;
        return -1;
    }

    replies = p_Icmp6SendEcho2(h, NULL, NULL, NULL,
                               &src, &dst,
                               (LPVOID) payload, (WORD) payload_len,
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

    free(reply_buf);
    p_IcmpCloseHandle(h);
    return 0;
}

#endif /* _WIN32 */
