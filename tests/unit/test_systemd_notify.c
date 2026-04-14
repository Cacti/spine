/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Idempotency and null-safety tests for the systemd_notify wrapper.       |
 |                                                                         |
 | The wrapper entry points must:                                          |
 |   - be safe to call when libsystemd is absent (no-op stubs),            |
 |   - be safe to call multiple times (idempotent / side-effect safe),     |
 |   - tolerate NULL status strings without crashing.                      |
 |                                                                         |
 | When libsystemd is linked, sd_notify() short-circuits whenever          |
 | NOTIFY_SOCKET is unset, so these calls remain no-ops under the unit     |
 | test harness. The point of this test is that the wrappers themselves    |
 | do not crash on repeated invocation or NULL input.                      |
 +-------------------------------------------------------------------------+
*/

#include "systemd_notify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

int main(void) {
    /* Ensure NOTIFY_SOCKET is unset so any real sd_notify calls no-op. */
    unsetenv("NOTIFY_SOCKET");

    /* READY: call twice; second call should refresh STATUS without crashing. */
    spine_sd_ready();
    spine_sd_ready();

    /* STATUS: literal, formatted, and NULL (wrapper treats NULL fmt as no-op).
     * The NULL call deliberately bypasses the format(printf) attribute; silence
     * -Wformat-security around it since this is a contract-robustness test. */
    spine_sd_status("polling 1234 hosts");
    spine_sd_status("%s", "polling 0 hosts");
#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wformat-security"
# if defined(__clang__)
#  pragma GCC diagnostic ignored "-Wformat-nonliteral"
# endif
#endif
    const char *null_fmt = NULL;
    spine_sd_status(null_fmt);
#if defined(__GNUC__) || defined(__clang__)
# pragma GCC diagnostic pop
#endif

    /* WATCHDOG: cheap, safe to call repeatedly whether or not WATCHDOG_USEC set. */
    spine_sd_watchdog();
    spine_sd_watchdog();

    /* RELOADING: exercises the clock_gettime path when libsystemd present. */
    spine_sd_reloading();
    spine_sd_reloading();

    /* STOPPING: double call mirrors SIGTERM handler + main() exit path. */
    spine_sd_stopping("graceful");
    spine_sd_stopping("graceful");
    spine_sd_stopping(NULL);

    /* under_systemd is a pure query; must never crash and must return 0/1. */
    int under = spine_sd_under_systemd();
    ASSERT(under == 0 || under == 1);

    printf("systemd_notify idempotency tests: %s\n",
           failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}
