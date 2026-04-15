/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"
#include "circuit_breaker.h"

#include <pthread.h>

/* Per-host breaker entry. skip_cycles > 0 means the host is in cool-down:
 * every spine_cb_should_skip() returns 1 and decrements skip_cycles until it
 * reaches zero and the host re-enters service. next_cooldown carries the
 * exponential-backoff state so repeated trips extend the block-out window
 * (2, 4, 8, ... capped at SPINE_CB_COOLDOWN_MAX). */
typedef struct spine_cb_entry_s {
	int host_id;
	int consecutive_failures;
	int skip_cycles;
	int next_cooldown;
	UT_hash_handle hh;
} spine_cb_entry_t;

#define SPINE_CB_COOLDOWN_INITIAL 2
#define SPINE_CB_COOLDOWN_MAX     60

static spine_cb_entry_t *spine_cb_table = NULL;
static pthread_mutex_t   spine_cb_lock  = PTHREAD_MUTEX_INITIALIZER;
static int               spine_cb_initialized = 0;

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

	spine_cb_entry_t *entry = spine_cb_get(host_id);
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

	spine_cb_entry_t *entry = spine_cb_get(host_id);
	if (!entry) {
		pthread_mutex_unlock(&spine_cb_lock);
		return;
	}

	if (errors > 0) {
		entry->consecutive_failures++;
		if (entry->consecutive_failures >= threshold) {
			entry->skip_cycles   = entry->next_cooldown;
			entry->next_cooldown = entry->next_cooldown * 2;
			if (entry->next_cooldown > SPINE_CB_COOLDOWN_MAX) {
				entry->next_cooldown = SPINE_CB_COOLDOWN_MAX;
			}
			entry->consecutive_failures = 0;
			pthread_mutex_unlock(&spine_cb_lock);
			SPINE_LOG(("NOTE: circuit breaker tripped for device %d; skipping %d cycles",
				host_id, entry->skip_cycles));
			return;
		}
	} else {
		entry->consecutive_failures = 0;
		entry->next_cooldown        = SPINE_CB_COOLDOWN_INITIAL;
	}
	pthread_mutex_unlock(&spine_cb_lock);
}
