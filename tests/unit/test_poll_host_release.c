/* Teardown tests for poll_host().
 *
 * poll_host() leaves through three places and each spelled its teardown out
 * again. The copies drifted: one never called mysql_thread_end(), which leaks
 * the MySQL client library's thread-local state once per affected device per
 * cycle on a thread-per-device poller.
 *
 * Neither db_release_connection() nor mysql_thread_end() returns anything to
 * assert on, so this binary interposes on both with the linker's --wrap and
 * records what was called. That is what makes a "did it release everything"
 * test possible at all; without it these two functions are unreachable from
 * the suite and were the only extracted code sitting at zero coverage.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"

/* what the wrappers saw */
static int  released[8][2];
static int  release_count;
static int  thread_end_count;

void __real_db_release_connection(int type, int id);
void __wrap_db_release_connection(int type, int id) {
	if (release_count < 8) {
		released[release_count][0] = type;
		released[release_count][1] = id;
	}
	release_count++;
}

int __real_mysql_thread_end(void);
int __wrap_mysql_thread_end(void) {
	thread_end_count++;
	return 0;
}

static int reset(void **state) {
	(void) state;
	memset(released, 0, sizeof(released));
	release_count = 0;
	thread_end_count = 0;
	set.poller_id = 1;
	set.mode = 0;
	return 0;
}

static pool_t *make_pool(int id) {
	pool_t *p = calloc(1, sizeof(pool_t));

	assert_non_null(p);
	p->id = id;
	return p;
}

static void test_local_connection_is_released(void **state) {
	pool_t *local = make_pool(3);

	(void) state;

	poll_host_release_connections(local, NULL, 42, 1);

	assert_int_equal(release_count, 1);
	assert_int_equal(released[0][0], LOCAL);
	assert_int_equal(released[0][1], 3);

	free(local);
}

/* A remote connection is only released when this poller actually has one. */
static void test_remote_connection_is_released_only_for_a_remote_poller(void **state) {
	pool_t *local  = make_pool(3);
	pool_t *remote = make_pool(9);

	(void) state;

	set.poller_id = 1;
	set.mode = REMOTE_ONLINE;
	poll_host_release_connections(local, remote, 42, 1);
	assert_int_equal(release_count, 1);

	reset(state);
	set.poller_id = 2;
	set.mode = REMOTE_ONLINE;
	poll_host_release_connections(local, remote, 42, 1);
	assert_int_equal(release_count, 2);
	assert_int_equal(released[1][0], REMOTE);
	assert_int_equal(released[1][1], 9);

	free(local);
	free(remote);
}

/* A NULL connection is a warning, not a crash and not a release. */
static void test_null_connections_release_nothing(void **state) {
	(void) state;

	set.poller_id = 2;
	set.mode = REMOTE_ONLINE;
	poll_host_release_connections(NULL, NULL, 42, 1);

	assert_int_equal(release_count, 0);
}

/* The bug: this path must end the MySQL thread. */
static void test_release_ends_the_mysql_thread(void **state) {
	host_t    *host   = calloc(1, sizeof(host_t));
	reindex_t *rex    = calloc(1, sizeof(reindex_t));
	ping_t    *ping   = calloc(1, sizeof(ping_t));
	char      *errstr = calloc(1, DBL_BUFSIZE);
	int       *bsize  = calloc(1, sizeof(int));
	int       *berr   = calloc(1, sizeof(int));
	pool_t    *local  = make_pool(3);

	(void) state;

	poll_host_release(&host, &rex, &ping, &errstr, &bsize, &berr, local, NULL, 42, 1);

	assert_int_equal(thread_end_count, 1);
	free(local);
}

/* Every pointer is nulled, so a caller that does not return immediately
   cannot double free. */
static void test_release_nulls_every_pointer(void **state) {
	host_t    *host   = calloc(1, sizeof(host_t));
	reindex_t *rex    = calloc(1, sizeof(reindex_t));
	ping_t    *ping   = calloc(1, sizeof(ping_t));
	char      *errstr = calloc(1, DBL_BUFSIZE);
	int       *bsize  = calloc(1, sizeof(int));
	int       *berr   = calloc(1, sizeof(int));
	pool_t    *local  = make_pool(3);

	(void) state;

	poll_host_release(&host, &rex, &ping, &errstr, &bsize, &berr, local, NULL, 42, 1);

	assert_null(host);
	assert_null(rex);
	assert_null(ping);
	assert_null(errstr);
	assert_null(bsize);
	assert_null(berr);

	free(local);
}

/* Releasing an already released set must be harmless: SPINE_FREE tolerates
   NULL, so a second call frees nothing and still ends the thread once more. */
static void test_release_is_safe_on_already_null_pointers(void **state) {
	host_t    *host   = NULL;
	reindex_t *rex    = NULL;
	ping_t    *ping   = NULL;
	char      *errstr = NULL;
	int       *bsize  = NULL;
	int       *berr   = NULL;

	(void) state;

	poll_host_release(&host, &rex, &ping, &errstr, &bsize, &berr, NULL, NULL, 42, 1);

	assert_int_equal(thread_end_count, 1);
	assert_int_equal(release_count, 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_local_connection_is_released, reset),
		cmocka_unit_test_setup(test_remote_connection_is_released_only_for_a_remote_poller, reset),
		cmocka_unit_test_setup(test_null_connections_release_nothing, reset),
		cmocka_unit_test_setup(test_release_ends_the_mysql_thread, reset),
		cmocka_unit_test_setup(test_release_nulls_every_pointer, reset),
		cmocka_unit_test_setup(test_release_is_safe_on_already_null_pointers, reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
