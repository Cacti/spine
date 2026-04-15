/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | icmp_win_loader: smoke test the multi-threaded iphlpapi one-shot
 | loader in platform_icmp_win.c. N threads all call spine_icmp_echo_v4()
 | simultaneously; the first thread through InterlockedCompareExchange
 | runs the DLL load, and every loser spins until the flag is published.
 | This test fails if the loser path reads a stale NULL function pointer
 | before the acquire fence (the bug the H1 fix addresses).
 |
 | On weakly-ordered hardware this is not a deterministic test. A clean
 | run does not prove the code is correct; a crash or NULL deref does
 | prove the code is broken. That asymmetry is good enough for CI.
 +-------------------------------------------------------------------------+
*/

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#include "platform/platform_icmp.h"

#define WORKER_COUNT 8
#define ITERATIONS    4

static DWORD WINAPI worker(LPVOID arg) {
    (void)arg;
    for (int i = 0; i < ITERATIONS; i++) {
        spine_icmp_result_t r;
        memset(&r, 0, sizeof(r));
        /* 127.0.0.1 keeps the actual ping off the wire; we only care
         * that the loader races cleanly and the call returns without
         * touching a NULL function pointer. */
        (void)spine_icmp_echo_v4("127.0.0.1", 250, NULL, 0, &r);
    }
    return 0;
}

int main(void) {
    HANDLE threads[WORKER_COUNT];
    for (int i = 0; i < WORKER_COUNT; i++) {
        threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        if (threads[i] == NULL) {
            fprintf(stderr, "CreateThread failed: %lu\n", (unsigned long)GetLastError());
            return EXIT_FAILURE;
        }
    }
    DWORD wait_rc = WaitForMultipleObjects(WORKER_COUNT, threads, TRUE, 10000);
    for (int i = 0; i < WORKER_COUNT; i++) {
        CloseHandle(threads[i]);
    }
    if (wait_rc == WAIT_TIMEOUT) {
        fprintf(stderr, "icmp_win_loader: worker threads did not finish in 10s\n");
        return EXIT_FAILURE;
    }
    printf("icmp_win_loader passed\n");
    return EXIT_SUCCESS;
}

#else

int main(void) {
    /* Non-Windows builds keep the target link-friendly but skip. */
    return 0;
}

#endif
