#ifndef SPINE_AUDIT_H
#define SPINE_AUDIT_H

#include <time.h>

/* Thin wrapper around libaudit's audit_log_user_message(). When the build
 * is not linked against libaudit (macOS, BSDs, Linux without audit-libs),
 * every call compiles to a no-op.
 *
 * The event string lands in /var/log/audit/audit.log as a
 * type=USER_CMD (custom result code) record so auditd-side rules can
 * key on "spine" to route spine events to a dedicated audit pipe.
 *
 * A per-event-type token bucket caps sustained volume at
 * SPINE_AUDIT_RATE_MAX events per SPINE_AUDIT_RATE_WINDOW_SECS. When the
 * window trips, a single NOTE line lands in the spine log and further
 * events in that bucket are dropped until the window rolls. */
void spine_audit_event(const char *op, const char *detail, int result);

/* Test seam: swap the time source with a mock clock. Passing NULL restores
 * the default (time(2)). Not part of the production surface; tests only. */
typedef time_t (*spine_audit_clock_fn)(void);
void spine_audit_set_clock(spine_audit_clock_fn fn);

/* Test seam: reset internal rate-limit counters so each test case starts
 * from zero. */
void spine_audit_reset_for_test(void);

#endif
