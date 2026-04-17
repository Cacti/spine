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

/* Accept raw from config, return a threshold in [1, 1_000_000]. Out-of-range
 * input is rejected with a warning and replaced by the default (5). When
 * warned_out is non-NULL it is set to 1 iff the value was replaced. */
#define SPINE_CB_THRESHOLD_DEFAULT 5
#define SPINE_CB_THRESHOLD_MIN     1
#define SPINE_CB_THRESHOLD_MAX     1000000
int spine_cb_clamp_threshold(int raw, int *warned_out);

#endif /* SPINE_CIRCUIT_BREAKER_H */
