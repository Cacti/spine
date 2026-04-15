#ifndef SPINE_AUDIT_H
#define SPINE_AUDIT_H

/* Thin wrapper around libaudit's audit_log_user_message(). When the build
 * is not linked against libaudit (macOS, BSDs, Linux without audit-libs),
 * every call compiles to a no-op.
 *
 * The event string lands in /var/log/audit/audit.log as a
 * type=USER_CMD (custom result code) record so auditd-side rules can
 * key on "spine" to route spine events to a dedicated audit pipe. */
void spine_audit_event(const char *op, const char *detail, int result);

#endif
