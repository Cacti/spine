/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Per-host circuit breaker. Opt-in feature gated on a non-zero threshold
 | in spine.conf (CircuitBreakerThreshold). Tracks consecutive poll
 | failures per host_id and, once the threshold trips, skips the host for
 | an exponentially-growing number of cycles (capped at 60) so that a
 | dead device does not drag every poll cycle into timeout territory.
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_CIRCUIT_BREAKER_H
#define SPINE_CIRCUIT_BREAKER_H

/* Allocate breaker state. Idempotent; safe to call from main() before any
 * worker thread exists. */
void spine_cb_init(void);

/* Free breaker state. Called once at process shutdown. */
void spine_cb_shutdown(void);

/* Returns 1 when the host is currently in cool-down and the caller should
 * skip polling it this cycle, 0 otherwise. When returning 1 the internal
 * counter is decremented so the host re-enters service after the remaining
 * cycles elapse. */
int spine_cb_should_skip(int host_id);

/* Record the outcome of a poll cycle. errors > 0 increments the consecutive
 * failure counter; errors == 0 resets it. When the threshold is crossed,
 * the host enters cool-down with exponential backoff. */
void spine_cb_record(int host_id, int errors);

/* Test seam: install a mock clock so age-based reap is deterministic.
 * Pass NULL to restore time(2). Production code never calls this. */
#include <time.h>
void spine_cb_set_clock_for_test(time_t (*fn)(void));

#endif /* SPINE_CIRCUIT_BREAKER_H */
