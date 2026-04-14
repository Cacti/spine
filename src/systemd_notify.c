/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 +-------------------------------------------------------------------------+
*/

#include "systemd_notify.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#endif

void spine_sd_ready(void) {
#ifdef HAVE_LIBSYSTEMD
    /* Two-field notify: READY plus a non-empty STATUS so `systemctl status`
     * shows something useful immediately after start-up. */
    sd_notify(0,
              "READY=1\n"
              "STATUS=Polling started\n");
#endif
}

void spine_sd_stopping(const char *reason) {
#ifdef HAVE_LIBSYSTEMD
    sd_notifyf(0,
               "STOPPING=1\n"
               "STATUS=%s\n",
               reason ? reason : "Shutting down");
#else
    (void)reason;
#endif
}

void spine_sd_watchdog(void) {
#ifdef HAVE_LIBSYSTEMD
    /* sd_notify() short-circuits when NOTIFY_SOCKET is unset, so this is
     * cheap even when spine runs outside systemd. */
    sd_notify(0, "WATCHDOG=1");
#endif
}

void spine_sd_status(const char *fmt, ...) {
#ifdef HAVE_LIBSYSTEMD
    if (fmt == NULL) {
        return;  /* NULL status is a no-op; vsnprintf(NULL) is UB. */
    }
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    sd_notifyf(0, "STATUS=%s", buf);
#else
    (void)fmt;
#endif
}

void spine_sd_reloading(void) {
#ifdef HAVE_LIBSYSTEMD
    /* systemd wants MONOTONIC_USEC so it can compute reload duration.
     * If clock_gettime fails (vDSO issues, sandbox), send RELOADING=1 without
     * the timestamp; systemd handles that gracefully (uses time of receipt).
     * Silently defaulting to 0 would be interpreted as a pre-boot timestamp. */
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        uint64_t monotonic_us = (uint64_t)ts.tv_sec * 1000000ULL
                              + (uint64_t)ts.tv_nsec / 1000ULL;
        sd_notifyf(0,
                   "RELOADING=1\n"
                   "MONOTONIC_USEC=%" PRIu64 "\n",
                   monotonic_us);
    } else {
        /* Intentional fprintf: this TU stays decoupled from spine.h so it can
         * run from signal handlers and before set.log_level is initialized.
         * Under Type=notify systemd captures stderr into the journal, so this
         * still reaches operators without the SPINE_LOG plumbing. */
        int saved_errno = errno;
        sd_notify(0, "RELOADING=1\n");
        fprintf(stderr,
                "WARNING: clock_gettime(CLOCK_MONOTONIC) failed: %s; "
                "sd_notify reload sent without timestamp\n",
                strerror(saved_errno));
    }
#endif
}

int spine_sd_under_systemd(void) {
#ifdef HAVE_LIBSYSTEMD
    if (getenv("INVOCATION_ID") != NULL) {
        return 1;
    }
    return sd_booted() > 0;
#else
    /* INVOCATION_ID is set by systemd regardless of libsystemd linkage, so we
     * can still recognise the environment for log-prefix decisions. */
    return getenv("INVOCATION_ID") != NULL;
#endif
}
