/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Circuit-breaker age-reap tests. Uses the mock-clock seam
 | spine_cb_set_clock_for_test() so deadline math is deterministic.
 | Covers the self-review finding that eviction-on-recovery reset backoff
 | history for flapping hosts; replaced with decay + age-based reap.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"
#include "circuit_breaker.h"

#include <stdio.h>
#include <time.h>

#include "test_platform_helpers.h"

/* Mock clock driven by the test. Each test case advances g_mock_now
 * explicitly; no wall-clock dependency. */
static time_t g_mock_now;
static time_t mock_clock(void) { return g_mock_now; }

/* Hook into set.circuit_breaker_threshold. The breaker early-returns
 * when threshold <= 0, so we have to set it to exercise the real path. */
extern config_t set;

static void setup(int threshold) {
	set.circuit_breaker_threshold = threshold;
	spine_cb_set_clock_for_test(mock_clock);
	g_mock_now = 1000;
	spine_cb_init();
}

static void teardown(void) {
	spine_cb_shutdown();
	spine_cb_set_clock_for_test(NULL);
}

static void test_healthy_host_not_tracked(void) {
	setup(3);

	/* A host that never fails must not occupy a hash entry. */
	spine_cb_record(42, 0);

	unsigned long entries = 0;
	spine_cb_get_stats(&entries, NULL, NULL);
	ASSERT_INT_EQ((int)entries, 0);

	teardown();
}

static void test_trip_records_an_entry(void) {
	setup(3);

	for (int i = 0; i < 3; i++) spine_cb_record(7, 1);
	/* Now tripped: entry exists with skip_cycles > 0. */

	unsigned long entries = 0, trips = 0;
	spine_cb_get_stats(&entries, NULL, &trips);
	ASSERT_INT_EQ((int)entries, 1);
	ASSERT_INT_EQ((int)trips, 1);

	teardown();
}

static void test_reap_drops_idle_recovered_entry(void) {
	setup(2);

	/* Trip the host. */
	spine_cb_record(99, 1);
	spine_cb_record(99, 1);

	/* Drain the cooldown: skip_cycles decrements each should_skip. */
	while (spine_cb_should_skip(99)) { /* spin until cool */ }

	/* Record a recovery so consecutive_failures=0 and last_activity is
	 * stamped at the current mock time. */
	spine_cb_record(99, 0);

	/* Jump past the idle threshold (1 hour). The reap fires on the next
	 * should_skip (or record), rate-limited by REAP_INTERVAL (60s).
	 * Advance past both thresholds. */
	g_mock_now += 3600 + 120;
	(void)spine_cb_should_skip(99);   /* triggers reap */

	unsigned long entries = 0, reaped = 0;
	spine_cb_get_stats(&entries, &reaped, NULL);
	ASSERT_INT_EQ((int)entries, 0);
	ASSERT_INT_EQ((int)reaped,  1);

	teardown();
}

static void test_reap_keeps_active_entry(void) {
	setup(2);

	/* Trip the host with backoff still running. */
	spine_cb_record(55, 1);
	spine_cb_record(55, 1);
	/* Don't drain cooldown; skip_cycles > 0. */

	/* Advance time past idle threshold. Entry is still in cooldown so
	 * the reap must NOT drop it. */
	g_mock_now += 3600 + 120;
	(void)spine_cb_should_skip(55);

	unsigned long entries = 0;
	spine_cb_get_stats(&entries, NULL, NULL);
	ASSERT_INT_EQ((int)entries, 1);

	teardown();
}

int main(void) {
	test_healthy_host_not_tracked();
	test_trip_records_an_entry();
	test_reap_drops_idle_recovered_entry();
	test_reap_keeps_active_entry();
	return finish_tests("spine_cb_reap");
}
