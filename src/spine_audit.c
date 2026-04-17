#include "spine_audit.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef HAVE_LIBAUDIT
#include <fcntl.h>
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

/* Per-event-type token bucket. An op-string maps to a small enum so we can
 * index a fixed array rather than do per-event hashing. A runaway producer
 * (e.g. a trip-storm from the circuit breaker during a DB outage) would
 * otherwise flood the audit log and rotate legitimate events off disk. */
enum audit_bucket {
	AUDIT_BUCKET_CB_TRIP = 0,
	AUDIT_BUCKET_RELOAD,
	AUDIT_BUCKET_SIGTERM,
	AUDIT_BUCKET_OTHER,
	AUDIT_BUCKET__COUNT
};

#define SPINE_AUDIT_RATE_MAX          10
#define SPINE_AUDIT_RATE_WINDOW_SECS  60

struct rate_bucket {
	time_t window_start;
	int    count;
	int    notified;
};

static struct rate_bucket g_buckets[AUDIT_BUCKET__COUNT];

static time_t default_clock(void) { return time(NULL); }
static spine_audit_clock_fn g_clock = default_clock;

void spine_audit_set_clock(spine_audit_clock_fn fn) {
	g_clock = fn ? fn : default_clock;
}

void spine_audit_reset_for_test(void) {
	memset(g_buckets, 0, sizeof(g_buckets));
}

static enum audit_bucket classify(const char *op) {
	if (!op) return AUDIT_BUCKET_OTHER;
	if (strcmp(op, "cb-trip") == 0) return AUDIT_BUCKET_CB_TRIP;
	if (strcmp(op, "reload")  == 0) return AUDIT_BUCKET_RELOAD;
	if (strcmp(op, "sigterm") == 0) return AUDIT_BUCKET_SIGTERM;
	return AUDIT_BUCKET_OTHER;
}

/* Returns 1 if the event is permitted, 0 if the rate limit is tripped.
 * A tripped bucket logs one NOTE line and stays silent until the window
 * rolls; otherwise the NOTE itself becomes the flood. */
static int rate_allow(enum audit_bucket b, const char *op) {
	time_t now = g_clock();
	struct rate_bucket *rb = &g_buckets[b];

	if (rb->window_start == 0 || now - rb->window_start >= SPINE_AUDIT_RATE_WINDOW_SECS) {
		rb->window_start = now;
		rb->count = 0;
		rb->notified = 0;
	}

	if (rb->count < SPINE_AUDIT_RATE_MAX) {
		rb->count++;
		return 1;
	}

	if (!rb->notified) {
		fprintf(stderr, "NOTE: audit rate limit reached for op=%s\n",
		        op ? op : "(null)");
		rb->notified = 1;
	}
	return 0;
}

void spine_audit_event(const char *op, const char *detail, int result) {
	if (!rate_allow(classify(op), op)) return;

#ifdef HAVE_LIBAUDIT
	if (g_audit_fd == -2) return;
	if (g_audit_fd == -1) {
		g_audit_fd = audit_open();
		if (g_audit_fd < 0) {
			g_audit_fd = -2;
			return;
		}
		/* The audit netlink fd outlives any nft_popen'd poll script.
		 * Flip FD_CLOEXEC so child processes do not inherit a privileged
		 * audit socket capable of emitting kernel messages. */
		int fl = fcntl(g_audit_fd, F_GETFD);
		if (fl >= 0) {
			(void) fcntl(g_audit_fd, F_SETFD, fl | FD_CLOEXEC);
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
	(void)detail;
	(void)result;
#endif
}
