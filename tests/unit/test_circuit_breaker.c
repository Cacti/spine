/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Circuit breaker state machine + thread-safety smoke tests.              |
 |                                                                         |
 | The production code pulls in common.h (which drags mysql + net-snmp).  |
 | Rather than link the whole poller for a pure-algorithm test, we        |
 | provide a minimal `set` config and a stub spine_log. The breaker has   |
 | no other hidden dependencies.                                          |
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"
#include "circuit_breaker.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

/* Minimal `set` and logging stubs. The real symbols live in spine.c /
 * util.c, both of which we do not link here. */
config_t set;

int spine_log(const char *format, ...) {
	(void) format;
	return 0;
}

void die(const char *format, ...) {
	(void) format;
	exit(1);
}

static void reset_breaker(int threshold) {
	spine_cb_shutdown();
	memset(&set, 0, sizeof(set));
	set.circuit_breaker_threshold = threshold;
	spine_cb_init();
}

/* Breaker disabled when threshold <= 0: every call must be a no-op and
 * should_skip must always return 0. */
static void test_disabled_when_threshold_zero(void) {
	reset_breaker(0);
	for (int i = 0; i < 10; i++) {
		spine_cb_record(1, 1);
	}
	ASSERT_INT_EQ(spine_cb_should_skip(1), 0);
	spine_cb_shutdown();
}

/* N-1 failures keep the breaker closed; the Nth trips it and the host
 * enters cool-down for at least one cycle. */
static void test_trips_on_threshold(void) {
	reset_breaker(3);

	spine_cb_record(42, 1);
	ASSERT_INT_EQ(spine_cb_should_skip(42), 0);
	spine_cb_record(42, 1);
	ASSERT_INT_EQ(spine_cb_should_skip(42), 0);
	spine_cb_record(42, 1); /* trip */
	ASSERT_INT_EQ(spine_cb_should_skip(42), 1);

	spine_cb_shutdown();
}

/* A successful poll must reset the failure counter before the trip. */
static void test_success_resets_failures(void) {
	reset_breaker(3);

	spine_cb_record(7, 1);
	spine_cb_record(7, 1);
	spine_cb_record(7, 0);  /* reset */
	spine_cb_record(7, 1);
	spine_cb_record(7, 1);
	ASSERT_INT_EQ(spine_cb_should_skip(7), 0);

	spine_cb_shutdown();
}

/* Every subsequent trip should double the cooldown window, capped at
 * SPINE_CB_COOLDOWN_MAX (60 cycles). First trip -> 2, second -> 4, etc.
 * We walk the cooldown down to 0 between trips with should_skip calls so
 * the breaker can re-trip. */
static void test_exponential_backoff_capped(void) {
	reset_breaker(1);

	int expected_windows[] = {2, 4, 8, 16, 32, 60, 60};
	const int n = (int)(sizeof(expected_windows) / sizeof(expected_windows[0]));

	for (int i = 0; i < n; i++) {
		spine_cb_record(99, 1);
		int window = 0;
		while (spine_cb_should_skip(99)) {
			window++;
			if (window > 200) {
				ASSERT_TRUE_MSG(0, "cooldown did not drain");
				return;
			}
		}
		ASSERT_INT_EQ(window, expected_windows[i]);
	}

	spine_cb_shutdown();
}

/* Unknown host ID with an enabled breaker must pass through: should_skip
 * returns 0 because no entry has tripped for it. */
static void test_unknown_host_passes(void) {
	reset_breaker(5);
	ASSERT_INT_EQ(spine_cb_should_skip(12345), 0);
	ASSERT_INT_EQ(spine_cb_should_skip(-1), 0);
	spine_cb_shutdown();
}

/* Thread-safety: four workers each pound on host_id=1 with a mix of
 * successes and failures. We only assert that the call graph does not
 * crash or corrupt state, and that the final should_skip is well-formed
 * (0 or 1). A race on the consecutive_failures counter is harmless. */
static void *cb_worker(void *arg) {
	int tid = (int)(long)arg;
	for (int i = 0; i < 500; i++) {
		int errors = ((tid + i) % 3 == 0) ? 0 : 1;
		spine_cb_record(1, errors);
		(void) spine_cb_should_skip(1);
	}
	return NULL;
}

static void test_thread_safety(void) {
	reset_breaker(10);

	pthread_t t[4];
	for (int i = 0; i < 4; i++) {
		ASSERT_INT_EQ(pthread_create(&t[i], NULL, cb_worker, (void *)(long)i), 0);
	}
	for (int i = 0; i < 4; i++) {
		pthread_join(t[i], NULL);
	}

	int r = spine_cb_should_skip(1);
	ASSERT_TRUE(r == 0 || r == 1);

	spine_cb_shutdown();
}

int main(void) {
	test_disabled_when_threshold_zero();
	test_trips_on_threshold();
	test_success_resets_failures();
	test_exponential_backoff_capped();
	test_unknown_host_passes();
	test_thread_safety();
	return finish_tests("circuit breaker tests");
}
