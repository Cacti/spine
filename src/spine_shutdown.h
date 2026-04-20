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

#endif /* SPINE_SHUTDOWN_H */
