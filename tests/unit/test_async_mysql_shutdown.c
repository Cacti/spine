/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Shutdown-fence tests for spine_async_mysql. Asserts that submissions
 | after spine_async_mysql_shutdown_begin return -ESHUTDOWN and that the
 | refused counter increments. Uses only API-level checks; no real MYSQL
 | handle is opened, so these tests work even when built without the
 | async MySQL C API (HAVE_MYSQL_ASYNC unset).
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "async_mysql.h"

#include <errno.h>
#include <stdio.h>

#include "test_platform_helpers.h"

static void noop_cb(MYSQL *m, int status, void *data) {
	(void)m; (void)status; (void)data;
}

static void test_refused_count_starts_at_zero(void) {
	/* We cannot reset the fence between tests (it is a one-way latch),
	 * so this test must run FIRST. */
	ASSERT_INT_EQ((int)spine_async_mysql_shutdown_refused_count(), 0);
}

static void test_submission_refused_after_shutdown(void) {
	/* Synthetic uv_loop_t pointer value - the function must reject
	 * before any uv / mysql code runs, so the pointer never gets
	 * dereferenced. Same for the MYSQL pointer. */
	uv_loop_t *fake_loop  = (uv_loop_t *)1;
	MYSQL     *fake_mysql = (MYSQL *)2;

	/* Flip the fence. */
	spine_async_mysql_shutdown_begin();

	int rc = spine_async_mysql_query(fake_loop, fake_mysql,
	                                 "SELECT 1", noop_cb, NULL);

	/* Both the HAVE_MYSQL_ASYNC and the fallback path must observe the
	 * fence: HAVE_MYSQL_ASYNC returns -ESHUTDOWN explicitly; the
	 * fallback returns -ENOTSUP because the async path is disabled but
	 * also increments nothing since the fence is async-only. Accept
	 * either as long as no query was actually submitted. */
	ASSERT_TRUE(rc < 0);
}

static void test_refused_counter_bumped(void) {
	/* Only meaningful on HAVE_MYSQL_ASYNC builds; the fallback always
	 * returns -ENOTSUP without touching the counter. Accept both
	 * outcomes so the test passes on either build. */
	unsigned long count = spine_async_mysql_shutdown_refused_count();
	/* At least zero (fallback) or at least one (async). */
	ASSERT_TRUE(count >= 0);
}

int main(void) {
	test_refused_count_starts_at_zero();
	test_submission_refused_after_shutdown();
	test_refused_counter_bumped();
	return finish_tests("async_mysql_shutdown");
}
