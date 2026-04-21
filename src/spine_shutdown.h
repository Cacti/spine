/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Shutdown-wide constants shared across translation units. Keeps the
 | per-phase drain budget in one place so spine.c, async_dns.c, and any
 | future async subsystem that needs a bounded teardown stay consistent.
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_SHUTDOWN_H
#define SPINE_SHUTDOWN_H

/* Per-phase drain budget. systemd's default TimeoutStopSec is 90s; with
 * four phases at SPINE_SHUTDOWN_DRAIN_SECS each plus DB/SNMP close time
 * we stay well inside that. Raise only if operators report stuck
 * shutdowns; do not exceed ~10s or systemd TimeoutStopSec tuning
 * becomes load-bearing. */
#define SPINE_SHUTDOWN_DRAIN_SECS 3

/* Nanoseconds per second. Paired with uv_hrtime() for bounded drain
 * loops; hoisted here so any future subsystem that needs a similar
 * sub-second wall-clock deadline picks up the same literal. */
#define SPINE_NS_PER_SEC 1000000000ULL

#endif /* SPINE_SHUTDOWN_H */
