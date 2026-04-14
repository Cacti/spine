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
 | spine: systemd sd_notify(3) integration                                 |
 +-------------------------------------------------------------------------+
 | When HAVE_LIBSYSTEMD is defined at build time, these helpers forward to |
 | sd_notify(3). Otherwise they compile to no-ops so callers need no       |
 | platform guards and non-Linux/Windows builds stay free of systemd deps. |
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_SYSTEMD_NOTIFY_H
#define SPINE_SYSTEMD_NOTIFY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Send READY=1 once core subsystems (DB, SNMP, PHP server, thread pool) are
 * live. Safe to call multiple times; subsequent calls just refresh STATUS. */
void spine_sd_ready(void);

/* Send STOPPING=1 with an optional human-readable reason. Called from the
 * shutdown path and from fatal signal handlers. reason may be NULL. */
void spine_sd_stopping(const char *reason);

/* Send WATCHDOG=1. Only meaningful when WATCHDOG_USEC is set by systemd
 * (i.e., the unit file specifies WatchdogSec=). The helper no-ops otherwise,
 * so it is cheap to call unconditionally in the main poll loop. */
void spine_sd_watchdog(void);

/* Send STATUS= with a printf-formatted free-form string (<=512 bytes). */
void spine_sd_status(const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

/* Send RELOADING=1 with MONOTONIC_USEC so systemd knows the reload started.
 * Pair with spine_sd_ready() once the reload completes. */
void spine_sd_reloading(void);

/* Return non-zero when spine is running under systemd (INVOCATION_ID set or
 * sd_booted()). Zero otherwise. When zero, log formatting stays unchanged. */
int spine_sd_under_systemd(void);

#ifdef __cplusplus
}
#endif

#endif /* SPINE_SYSTEMD_NOTIFY_H */
