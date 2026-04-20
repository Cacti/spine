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
	/* Real uv_loop so a future refactor that dereferences the loop
	 * before the fence check does not segfault - it would fail
	 * cleanly against a valid-but-empty loop. */
	uv_loop_t loop;
	ASSERT_INT_EQ(uv_loop_init(&loop), 0);

	MYSQL *fake_mysql = (MYSQL *)2;

	spine_async_mysql_shutdown_reset_for_test();
	spine_async_mysql_shutdown_begin();

	unsigned long before = spine_async_mysql_shutdown_refused_count();
	int rc = spine_async_mysql_query(&loop, fake_mysql,
	                                 "SELECT 1", noop_cb, NULL);
	unsigned long after = spine_async_mysql_shutdown_refused_count();

	ASSERT_TRUE(rc < 0);

#ifdef HAVE_MYSQL_ASYNC
	ASSERT_INT_EQ((int)(after - before), 1);
#else
	ASSERT_INT_EQ((int)(after - before), 0);
#endif

	uv_loop_close(&loop);
}

static void test_reset_clears_counter_for_tests(void) {
	uv_loop_t loop;
	ASSERT_INT_EQ(uv_loop_init(&loop), 0);

	spine_async_mysql_shutdown_reset_for_test();
	spine_async_mysql_shutdown_begin();
	(void)spine_async_mysql_query(&loop, (MYSQL *)2, "X", noop_cb, NULL);
	spine_async_mysql_shutdown_reset_for_test();
	ASSERT_INT_EQ((int)spine_async_mysql_shutdown_refused_count(), 0);

	uv_loop_close(&loop);
}

int main(void) {
	test_refused_count_starts_at_zero();
	test_submission_refused_after_shutdown();
	test_reset_clears_counter_for_tests();
	return finish_tests("async_mysql_shutdown");
}
