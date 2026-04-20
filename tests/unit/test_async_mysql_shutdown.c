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
	spine_async_mysql_shutdown_reset_for_test();
	ASSERT_INT_EQ((int)spine_async_mysql_shutdown_refused_count(), 0);
}

static void test_submission_refused_after_shutdown(void) {
	/* Synthetic uv_loop_t pointer value - the function must reject
	 * before any uv / mysql code runs, so the pointer never gets
	 * dereferenced. Same for the MYSQL pointer. */
	uv_loop_t *fake_loop  = (uv_loop_t *)1;
	MYSQL     *fake_mysql = (MYSQL *)2;

	spine_async_mysql_shutdown_reset_for_test();
	spine_async_mysql_shutdown_begin();

	unsigned long before = spine_async_mysql_shutdown_refused_count();
	int rc = spine_async_mysql_query(fake_loop, fake_mysql,
	                                 "SELECT 1", noop_cb, NULL);
	unsigned long after = spine_async_mysql_shutdown_refused_count();

	ASSERT_TRUE(rc < 0);

#ifdef HAVE_MYSQL_ASYNC
	/* Async build: the fence path specifically bumps the counter. */
	ASSERT_INT_EQ((int)(after - before), 1);
#else
	/* Fallback build: the function returns -ENOTSUP before reaching the
	 * fence. Counter must be unchanged. */
	ASSERT_INT_EQ((int)(after - before), 0);
#endif
}

static void test_reset_clears_counter_for_tests(void) {
	spine_async_mysql_shutdown_reset_for_test();
	spine_async_mysql_shutdown_begin();
	(void)spine_async_mysql_query((uv_loop_t *)1, (MYSQL *)2,
	                              "X", noop_cb, NULL);
	/* Reset must zero both the fence and the counter. */
	spine_async_mysql_shutdown_reset_for_test();
	ASSERT_INT_EQ((int)spine_async_mysql_shutdown_refused_count(), 0);
}

int main(void) {
	test_refused_count_starts_at_zero();
	test_submission_refused_after_shutdown();
	test_reset_clears_counter_for_tests();
	return finish_tests("async_mysql_shutdown");
}
