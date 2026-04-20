/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"
#include "circuit_breaker.h"
#include "spine_audit.h"

#include <pthread.h>
#include <stdio.h>

/* Per-host breaker entry. skip_cycles > 0 means the host is in cool-down:
 * every spine_cb_should_skip() returns 1 and decrements skip_cycles until it
 * reaches zero and the host re-enters service. next_cooldown carries the
 * exponential-backoff state so repeated trips extend the block-out window
 * (2, 4, 8, ... capped at SPINE_CB_COOLDOWN_MAX).
 *
 * last_activity is the wall-clock time of the most recent record/should_skip
 * interaction. Entries idle longer than SPINE_CB_IDLE_SECS are reaped by the
 * opportunistic reap pass below. This preserves backoff history across a
 * recovery window (a flapping host cannot escape its penalty by being
 * briefly healthy) while still bounding memory for host-id churn. */
typedef struct spine_cb_entry_s {
	int    host_id;
	int    consecutive_failures;
	int    skip_cycles;
	int    next_cooldown;
	time_t last_activity;
	UT_hash_handle hh;
} spine_cb_entry_t;

#define SPINE_CB_COOLDOWN_INITIAL 2
#define SPINE_CB_COOLDOWN_MAX     60
/* Reap entries that haven't been touched for an hour. Long enough that a
 * repeatedly-failing host with a 60-cycle cooldown stays in the table
 * across its penalty window; short enough to bound a discovery-churn
 * population. */
#define SPINE_CB_IDLE_SECS        3600
/* Reap cadence: do the sweep at most once per minute; the sweep is O(N)
 * under the table lock, so rate-limit it. */
#define SPINE_CB_REAP_INTERVAL    60

static spine_cb_entry_t *spine_cb_table = NULL;
static pthread_mutex_t   spine_cb_lock  = PTHREAD_MUTEX_INITIALIZER;
static int               spine_cb_initialized = 0;
static time_t            spine_cb_last_reap   = 0;

/* Caller holds spine_cb_lock. Drop entries whose last_activity is older
 * than SPINE_CB_IDLE_SECS; rate-limit to one pass per
 * SPINE_CB_REAP_INTERVAL seconds. */
static void spine_cb_reap_locked(time_t now) {
	if (now - spine_cb_last_reap < SPINE_CB_REAP_INTERVAL) return;
	spine_cb_last_reap = now;

	spine_cb_entry_t *entry, *tmp;
	HASH_ITER(hh, spine_cb_table, entry, tmp) {
		/* Keep any entry still serving cooldown cycles - the skip state
		 * is the entire reason the breaker exists. */
		if (entry->skip_cycles > 0) continue;
		if (now - entry->last_activity > SPINE_CB_IDLE_SECS) {
			HASH_DEL(spine_cb_table, entry);
			free(entry);
		}
	}
}

void spine_cb_init(void) {
	pthread_mutex_lock(&spine_cb_lock);
	spine_cb_initialized = 1;
	pthread_mutex_unlock(&spine_cb_lock);
}

void spine_cb_shutdown(void) {
	spine_cb_entry_t *entry, *tmp;

	pthread_mutex_lock(&spine_cb_lock);
	HASH_ITER(hh, spine_cb_table, entry, tmp) {
		HASH_DEL(spine_cb_table, entry);
		free(entry);
	}
	spine_cb_initialized = 0;
	pthread_mutex_unlock(&spine_cb_lock);
}

/* Lookup-or-create. Caller holds spine_cb_lock. Returns NULL on ENOMEM; the
 * breaker fails open in that case so we never block polling on an OOM. */
static spine_cb_entry_t *spine_cb_get(int host_id) {
	spine_cb_entry_t *entry = NULL;
	HASH_FIND_INT(spine_cb_table, &host_id, entry);
	if (entry) return entry;

	entry = (spine_cb_entry_t *)calloc(1, sizeof(*entry));
	if (!entry) return NULL;
	entry->host_id       = host_id;
	entry->next_cooldown = SPINE_CB_COOLDOWN_INITIAL;
	entry->last_activity = time(NULL);
	HASH_ADD_INT(spine_cb_table, host_id, entry);
	return entry;
}

int spine_cb_should_skip(int host_id) {
	int threshold = set.circuit_breaker_threshold;
	if (threshold <= 0) return 0;

	pthread_mutex_lock(&spine_cb_lock);
	if (!spine_cb_initialized) {
		pthread_mutex_unlock(&spine_cb_lock);
		return 0;
	}

	/* Lookup only - do not create an entry for an id we have never seen
	 * fail. A churning host-id population (auto-discovery) would otherwise
	 * grow spine_cb_table without bound across the process lifetime. */
	spine_cb_entry_t *entry = NULL;
	HASH_FIND_INT(spine_cb_table, &host_id, entry);

	int skip = 0;
	if (entry && entry->skip_cycles > 0) {
		entry->skip_cycles--;
		skip = 1;
	}
	pthread_mutex_unlock(&spine_cb_lock);
	return skip;
}

void spine_cb_record(int host_id, int errors) {
	int threshold = set.circuit_breaker_threshold;
	if (threshold <= 0) return;

	pthread_mutex_lock(&spine_cb_lock);
	if (!spine_cb_initialized) {
		pthread_mutex_unlock(&spine_cb_lock);
		return;
	}

	/* Only allocate on first failure. Healthy hosts have no representation
	 * in the table, which caps memory at the size of the concurrently
	 * failing population rather than the cumulative seen-host population.
	 * See spine_cb_should_skip() for the matching lookup-only path. */
	spine_cb_entry_t *entry = NULL;
	HASH_FIND_INT(spine_cb_table, &host_id, entry);
	if (!entry) {
		if (errors <= 0) {
			pthread_mutex_unlock(&spine_cb_lock);
			return;
		}
		entry = spine_cb_get(host_id);
		if (!entry) {
			pthread_mutex_unlock(&spine_cb_lock);
			return;
		}
	}

	if (errors > 0) {
		entry->consecutive_failures++;
		entry->last_activity = time(NULL);
		if (entry->consecutive_failures >= threshold) {
			entry->skip_cycles   = entry->next_cooldown;
			entry->next_cooldown = entry->next_cooldown * 2;
			if (entry->next_cooldown > SPINE_CB_COOLDOWN_MAX) {
				entry->next_cooldown = SPINE_CB_COOLDOWN_MAX;
			}
			int skip_cycles_copy = entry->skip_cycles;
			entry->consecutive_failures = 0;
			pthread_mutex_unlock(&spine_cb_lock);
			SPINE_LOG(("NOTE: circuit breaker tripped for device %d; skipping %d cycles",
				host_id, skip_cycles_copy));
			{
				char detail[96];
				snprintf(detail, sizeof(detail),
				         "device=%d skip=%d", host_id, skip_cycles_copy);
				spine_audit_event("cb-trip", detail, 1);
			}
			return;
		}
	} else {
		entry->consecutive_failures = 0;
		entry->last_activity        = time(NULL);
		/* Decay the backoff gently on recovery rather than resetting
		 * to INITIAL. A flapping host that trips -> recovers -> trips
		 * should not escape its penalty history by being briefly
		 * healthy. Halve next_cooldown per healthy record, floored at
		 * INITIAL; a truly stable host walks back to the initial
		 * penalty after a handful of successful cycles while a
		 * flapping one keeps most of its accumulated backoff. */
		if (entry->next_cooldown > SPINE_CB_COOLDOWN_INITIAL) {
			entry->next_cooldown /= 2;
			if (entry->next_cooldown < SPINE_CB_COOLDOWN_INITIAL) {
				entry->next_cooldown = SPINE_CB_COOLDOWN_INITIAL;
			}
		}
	}

	/* Opportunistic age-based reap, rate-limited. Bounded memory under
	 * discovery churn without losing backoff state for active hosts. */
	spine_cb_reap_locked(time(NULL));

	pthread_mutex_unlock(&spine_cb_lock);
}
