#include "spine_audit.h"

#include <stdio.h>
#include <string.h>

#ifdef HAVE_LIBAUDIT
#include <libaudit.h>
#include <unistd.h>
#endif

/* Cached audit fd. audit_open() binds a netlink socket; we keep it open for
 * the spine lifetime rather than paying the socket setup on every event.
 * -1 means "not yet attempted"; -2 means "attempted and failed, stop
 * retrying" so a non-audit-enabled kernel doesn't burn syscalls forever. */
#ifdef HAVE_LIBAUDIT
static int g_audit_fd = -1;
#endif

void spine_audit_event(const char *op, const char *detail, int result) {
#ifdef HAVE_LIBAUDIT
	if (g_audit_fd == -2) return;
	if (g_audit_fd == -1) {
		g_audit_fd = audit_open();
		if (g_audit_fd < 0) {
			g_audit_fd = -2;
			return;
		}
	}

	char msg[512];
	snprintf(msg, sizeof(msg), "op=spine-%s %s", op ? op : "event",
	         detail ? detail : "");

	/* AUDIT_USER_CMD is the kernel's generic "user-space command" event
	 * class. Auditd filter rules can key on our op= prefix rather than
	 * on the record type itself. */
	(void)audit_log_user_message(g_audit_fd, AUDIT_USER_CMD, msg,
	                             NULL, NULL, NULL, result);
#else
	(void)op;
	(void)detail;
	(void)result;
#endif
}
