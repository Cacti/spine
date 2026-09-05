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
#include "nft_popen.h"

#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

/* what the wrappers saw */
static int  released[8][2];
static int  release_count;
static int  thread_end_count;
static pool_t fake_pool;
static unsigned char fake_result_storage;
static MYSQL_RES *fake_result = (MYSQL_RES *)&fake_result_storage;
static my_ulonglong fake_num_rows;
static int query_count;
static int result_free_count;
static char *fake_rows[2][21];
static int fake_row_count;
static int fake_row_index;
static int snmp_init_count;
static int snmp_cleanup_count;
static int snmp_multi_count;
static int snmp_multi_sizes[2];
static int insert_count;
static char inserted_query[MAX_MYSQL_BUF_SIZE + RESULTS_BUFFER];
static unsigned char fake_snmp_session;
static int fake_debug_devices[2];
extern int *debug_devices;
static poller_thread_t fake_detail;
static poller_thread_t *fake_details[1];
extern poller_thread_t **details;

pool_t *__wrap_db_get_connection(int type) {
	(void) type;
	return &fake_pool;
}

MYSQL_RES *__wrap_db_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	(void) query;
	query_count++;
	return fake_result;
}

my_ulonglong __wrap_mysql_num_rows(MYSQL_RES *result) {
	assert_ptr_equal(result, fake_result);
	return fake_num_rows;
}

void __wrap_db_free_result(MYSQL_RES *result) {
	assert_ptr_equal(result, fake_result);
	result_free_count++;
}

MYSQL_ROW __wrap_mysql_fetch_row(MYSQL_RES *result) {
	assert_ptr_equal(result, fake_result);
	if (fake_row_index >= fake_row_count) return NULL;
	return fake_rows[fake_row_index++];
}

int __wrap_db_insert(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	assert_int_equal(type, LOCAL);
	insert_count++;
	snprintf(inserted_query, sizeof(inserted_query), "%s", query);
	return 0;
}

void __wrap_db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	(void) mysql;
	if (output == NULL || max_size <= 0) return;
	snprintf(output, (size_t)max_size, "%s", input == NULL ? "" : input);
}

void *__wrap_snmp_host_init(int host_id, char *hostname, int snmp_version,
	char *snmp_community, char *snmp_username, char *snmp_password,
	char *snmp_auth_protocol, char *snmp_priv_passphrase,
	char *snmp_priv_protocol, char *snmp_context, char *snmp_engine_id,
	int snmp_port, int snmp_timeout) {
	(void) host_id;
	(void) hostname;
	(void) snmp_version;
	(void) snmp_community;
	(void) snmp_username;
	(void) snmp_password;
	(void) snmp_auth_protocol;
	(void) snmp_priv_passphrase;
	(void) snmp_priv_protocol;
	(void) snmp_context;
	(void) snmp_engine_id;
	(void) snmp_port;
	(void) snmp_timeout;
	snmp_init_count++;
	return &fake_snmp_session;
}

void __wrap_snmp_host_cleanup(void *session) {
	assert_ptr_equal(session, &fake_snmp_session);
	snmp_cleanup_count++;
}

void __wrap_snmp_get_multi(host_t *host, target_t *items,
	snmp_oids_t *oids, int num_oids) {
	int i;
	(void) host;
	(void) items;
	assert_true(snmp_multi_count < 2);
	snmp_multi_sizes[snmp_multi_count] = num_oids;
	for (i = 0; i < num_oids; i++) {
		snprintf(oids[i].result, sizeof(oids[i].result), "%s",
			snmp_multi_count == 0 ? "in:4242 out:7" : "in:99 out:8");
	}
	snmp_multi_count++;
}

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

/* spine_reap_child_bounded() is meant to poll before it ever sleeps. Counting
   the sleeps states that directly; timing the call only states it on an idle
   machine, and the CI runners are not idle. */
static int usleep_count;
static int fail_cloexec_call;
static int cloexec_calls;
static int fail_next_waitpid_with_eintr;
static int waitpid_calls;
static int captured_pipe[2] = { -1, -1 };

int __real_usleep(useconds_t usec);
int __wrap_usleep(useconds_t usec) {
	usleep_count++;
	return __real_usleep(usec);
}

int __real_pipe(int pdes[2]);
int __wrap_pipe(int pdes[2]) {
	int rc = __real_pipe(pdes);
	if (rc == 0) {
		captured_pipe[0] = pdes[0];
		captured_pipe[1] = pdes[1];
	}
	return rc;
}

int __real_fcntl(int fd, int command, ...);
int __wrap_fcntl(int fd, int command, ...) {
	va_list args;
	int argument;

	if (command == F_SETFD) {
		cloexec_calls++;
		if (fail_cloexec_call == cloexec_calls) {
			errno = EIO;
			return -1;
		}
	}
	if (command == F_GETFD) return __real_fcntl(fd, command);

	va_start(args, command);
	argument = va_arg(args, int);
	va_end(args);
	return __real_fcntl(fd, command, argument);
}

pid_t __real_waitpid(pid_t pid, int *status, int options);
pid_t __wrap_waitpid(pid_t pid, int *status, int options) {
	waitpid_calls++;
	if (fail_next_waitpid_with_eintr) {
		fail_next_waitpid_with_eintr = FALSE;
		errno = EINTR;
		return -1;
	}
	return __real_waitpid(pid, status, options);
}

static int reset(void **state) {
	(void) state;
	memset(released, 0, sizeof(released));
	release_count = 0;
	thread_end_count = 0;
	usleep_count = 0;
	fail_cloexec_call = 0;
	cloexec_calls = 0;
	fail_next_waitpid_with_eintr = FALSE;
	waitpid_calls = 0;
	captured_pipe[0] = captured_pipe[1] = -1;
	memset(&fake_pool, 0, sizeof(fake_pool));
	fake_pool.id = 3;
	fake_num_rows = 0;
	query_count = 0;
	result_free_count = 0;
	memset(fake_rows, 0, sizeof(fake_rows));
	fake_row_count = 0;
	fake_row_index = 0;
	snmp_init_count = 0;
	snmp_cleanup_count = 0;
	snmp_multi_count = 0;
	memset(snmp_multi_sizes, 0, sizeof(snmp_multi_sizes));
	insert_count = 0;
	inserted_query[0] = '\0';
	memset(fake_debug_devices, 0, sizeof(fake_debug_devices));
	debug_devices = fake_debug_devices;
	memset(&fake_detail, 0, sizeof(fake_detail));
	fake_detail.host_threads = 2;
	fake_details[0] = &fake_detail;
	details = fake_details;
	set.ping_only = FALSE;
	set.has_output_regex = FALSE;
	set.spine_log_level = 0;
	set.poller_interval = 0;
	set.active_profiles = 1;
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


/* Both helpers take pointers the caller owns. Every other extracted function
   refuses a NULL rather than dereferencing it; these did not. */
static void test_reap_rejects_a_null_status(void **state) {
	(void) state;
	assert_int_equal(spine_reap_child_bounded(getpid(), NULL, 2), -1);
}

static void test_pipe_cloexec_failure_closes_and_clears_both_ends(void **state) {
	int pdes[2] = { 17, 18 };

	(void) state;
	fail_cloexec_call = 1;
	assert_false(spine_open_pipe_cloexec(pdes));
	assert_int_equal(pdes[0], -1);
	assert_int_equal(pdes[1], -1);
	assert_true(captured_pipe[0] >= 0);
	assert_true(captured_pipe[1] >= 0);
	errno = 0;
	assert_int_equal(__real_fcntl(captured_pipe[0], F_GETFD), -1);
	assert_int_equal(errno, EBADF);
	errno = 0;
	assert_int_equal(__real_fcntl(captured_pipe[1], F_GETFD), -1);
	assert_int_equal(errno, EBADF);
}

static void test_second_pipe_cloexec_failure_closes_and_clears_both_ends(void **state) {
	int pdes[2] = { 17, 18 };

	(void) state;
	fail_cloexec_call = 2;
	assert_false(spine_open_pipe_cloexec(pdes));
	assert_int_equal(cloexec_calls, 2);
	assert_int_equal(pdes[0], -1);
	assert_int_equal(pdes[1], -1);
	assert_true(captured_pipe[0] >= 0);
	assert_true(captured_pipe[1] >= 0);
	errno = 0;
	assert_int_equal(__real_fcntl(captured_pipe[0], F_GETFD), -1);
	assert_int_equal(errno, EBADF);
	errno = 0;
	assert_int_equal(__real_fcntl(captured_pipe[1], F_GETFD), -1);
	assert_int_equal(errno, EBADF);
}

static void test_reap_retries_waitpid_after_eintr(void **state) {
	siginfo_t info;
	int pstat = 1;
	pid_t pid;

	(void) state;
	pid = fork();
	assert_true(pid >= 0);
	if (pid == 0) _exit(0);

	memset(&info, 0, sizeof(info));
	assert_int_equal(waitid(P_PID, pid, &info, WEXITED | WNOWAIT), 0);
	fail_next_waitpid_with_eintr = TRUE;
	assert_int_equal(spine_reap_child_bounded(pid, &pstat, 2), 0);
	assert_true(waitpid_calls >= 2);
	assert_true(WIFEXITED(pstat));
}

static void test_release_rejects_null_arguments(void **state) {
	host_t    *host   = NULL;
	reindex_t *rex    = NULL;
	ping_t    *ping   = NULL;
	char      *errstr = NULL;
	int       *bsize  = NULL;
	int       *berr   = NULL;

	(void) state;

	poll_host_release(NULL, &rex, &ping, &errstr, &bsize, &berr, NULL, NULL, 42, 1);
	poll_host_release(&host, NULL, &ping, &errstr, &bsize, &berr, NULL, NULL, 42, 1);
	poll_host_release(&host, &rex, &ping, &errstr, NULL, &berr, NULL, NULL, 42, 1);

	/* nothing was released, so the thread was not ended either */
	assert_int_equal(thread_end_count, 0);
	assert_int_equal(release_count, 0);
}

static void test_poll_host_releases_everything_when_host_row_count_is_not_one(void **state) {
	char host_time[] = "1700000000";
	int host_errors = 77;
	(void) state;

	/* The first host query returns zero rows. poll_host() must free that result
	 * and take its consolidated cleanup path without touching later queries. */
	fake_num_rows = 0;
	poll_host(0, 42, 1, 1, 0, host_time, &host_errors, 0.0);

	assert_int_equal(query_count, 1);
	assert_int_equal(result_free_count, 1);
	assert_int_equal(release_count, 1);
	assert_int_equal(released[0][0], LOCAL);
	assert_int_equal(released[0][1], fake_pool.id);
	assert_int_equal(thread_end_count, 1);
}

static void test_poll_host_ping_only_uses_the_same_cleanup_path(void **state) {
	char host_time[] = "1700000000";
	int host_errors = 77;

	(void) state;
	set.ping_only = TRUE;
	poll_host(0, 0, 1, 1, 0, host_time, &host_errors, 0.0);

	assert_int_equal(query_count, 0);
	assert_int_equal(result_free_count, 0);
	assert_int_equal(release_count, 1);
	assert_int_equal(released[0][0], LOCAL);
	assert_int_equal(released[0][1], fake_pool.id);
	assert_int_equal(thread_end_count, 1);
}

static void test_poll_host_flushes_snmp_batch_on_identity_change(void **state) {
	char host_time[] = "1700000000";
	int host_errors = 77;

	(void) state;
	/* host_id zero skips the host/reindex queries but still exercises the real
	 * poller-item loop. A port and community change on item two must flush item
	 * one through the shared normalizer before the replacement session opens. */
	fake_rows[0][0] = "0";
	fake_rows[0][1] = "router1";
	fake_rows[0][2] = "public-a";
	fake_rows[0][3] = "2";
	fake_rows[0][6] = "first";
	fake_rows[0][8] = ".1.3.6.1.2.1.1.1.0";
	fake_rows[0][11] = "101";
	fake_rows[0][13] = "161";
	fake_rows[0][20] = "[0-9]+";
	fake_rows[1][0] = "0";
	fake_rows[1][1] = "router1";
	fake_rows[1][2] = "public-b";
	fake_rows[1][3] = "2";
	fake_rows[1][6] = "second";
	fake_rows[1][8] = ".1.3.6.1.2.1.1.2.0";
	fake_rows[1][11] = "102";
	fake_rows[1][13] = "1161";
	fake_rows[1][20] = "[0-9]+";
	fake_row_count = 2;
	fake_num_rows = 2;
	set.has_output_regex = TRUE;

	poll_host(0, 0, 1, 1, 0, host_time, &host_errors, 0.0);

	assert_int_equal(query_count, 1);
	assert_int_equal(result_free_count, 1);
	assert_int_equal(fake_row_index, 2);
	assert_int_equal(snmp_init_count, 2);
	assert_int_equal(snmp_cleanup_count, 2);
	assert_int_equal(snmp_multi_count, 2);
	assert_int_equal(snmp_multi_sizes[0], 1);
	assert_int_equal(snmp_multi_sizes[1], 1);
	assert_int_equal(insert_count, 1);
	assert_non_null(strstr(inserted_query, "'4242'"));
	assert_non_null(strstr(inserted_query, "'99'"));
	assert_int_equal(host_errors, 0);
	assert_int_equal(release_count, 1);
	assert_int_equal(thread_end_count, 1);
}



/* A script that exits a moment after closing stdout used to cost the full
   50ms, because the loop slept before its first WNOHANG. nft_pclose() holds an
   available_scripts token throughout, so that was poller capacity, not just one
   thread.

   waitid(WNOWAIT) blocks until the child has exited but leaves it reapable, so
   by the time the call is made the very first WNOHANG must succeed. A correct
   implementation sleeps zero times; the old one slept once before looking. The
   assertion is on that count rather than on elapsed time, so a loaded runner or
   a sanitizer build cannot turn it red. */
static void test_reap_polls_before_it_sleeps(void **state) {
	siginfo_t info;
	int pstat = 1;
	pid_t pid;

	(void) state;

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		_exit(0);
	}

	memset(&info, 0, sizeof(info));
	assert_int_equal(waitid(P_PID, pid, &info, WEXITED | WNOWAIT), 0);

	assert_int_equal(spine_reap_child_bounded(pid, &pstat, 100), 0);
	assert_int_equal(usleep_count, 0);
	assert_true(WIFEXITED(pstat));
	assert_int_equal(WEXITSTATUS(pstat), 0);
}

/* nft_pclose() gives up on a child that outlives SIGKILL, and before this
   branch there was nothing to hand it to: no SIGCHLD handler, no waitpid(-1).
   The dropped child stayed a zombie for the daemon's lifetime and accumulated
   once per affected script per cycle against RLIMIT_NPROC.

   The give-up path itself cannot be driven from a test, because SIGKILL cannot
   be blocked and a D-state child needs stalled hardware. What is testable is
   the thing that path depends on: that a parked pid really is reaped, and that
   the list is bounded. */
static pid_t spawn_sleeper(void) {
	pid_t pid = fork();

	assert_true(pid >= 0);

	if (pid == 0) {
		pause();
		_exit(0);
	}

	return pid;
}

static void test_a_parked_child_is_reaped_by_the_sweep(void **state) {
	siginfo_t info;
	pid_t     pid;

	(void) state;

	assert_int_equal(nft_abandoned_pending(), 0);

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		_exit(0);
	}

	/* block until it has exited but leave it reapable, so the sweep below is
	   testing the sweep and not racing the child's exit */
	memset(&info, 0, sizeof(info));
	assert_int_equal(waitid(P_PID, pid, &info, WEXITED | WNOWAIT), 0);

	nft_abandon_child(pid, "test");

	/* the sweep runs inside the accessor, so an exited child is gone by now */
	assert_int_equal(nft_abandoned_pending(), 0);

	/* and it really was reaped, not merely forgotten */
	assert_int_equal(waitpid(pid, NULL, WNOHANG), -1);
	assert_int_equal(errno, ECHILD);
}

static void test_a_live_child_stays_parked_until_it_exits(void **state) {
	pid_t pid;

	(void) state;

	assert_int_equal(nft_abandoned_pending(), 0);

	pid = spawn_sleeper();
	nft_abandon_child(pid, "test");

	/* still running, so the sweep must leave it on the list */
	assert_int_equal(nft_abandoned_pending(), 1);

	kill(pid, SIGKILL);

	/* it exits asynchronously; the sweep is WNOHANG, so allow it to land */
	while (nft_abandoned_pending() != 0) {
		usleep(1000);
	}
}

static void test_the_parked_list_is_bounded(void **state) {
	pid_t pids[NFT_ABANDONED_MAX + 4];
	int   i;

	(void) state;

	assert_int_equal(nft_abandoned_pending(), 0);

	for (i = 0; i < NFT_ABANDONED_MAX + 4; i++) {
		pids[i] = spawn_sleeper();
		nft_abandon_child(pids[i], "test");
	}

	/* past the cap a pid is logged and dropped rather than growing the list */
	assert_int_equal(nft_abandoned_pending(), NFT_ABANDONED_MAX);

	for (i = 0; i < NFT_ABANDONED_MAX + 4; i++) {
		kill(pids[i], SIGKILL);
	}

	while (nft_abandoned_pending() != 0) {
		usleep(1000);
	}

	/* the four the list refused are this process's children and nobody swept
	   them, which is exactly the leak the cap accepts; reap them here so the
	   test does not leave zombies behind */
	for (i = 0; i < NFT_ABANDONED_MAX + 4; i++) {
		(void) waitpid(pids[i], NULL, 0);
	}
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_local_connection_is_released, reset),
		cmocka_unit_test_setup(test_remote_connection_is_released_only_for_a_remote_poller, reset),
		cmocka_unit_test_setup(test_null_connections_release_nothing, reset),
		cmocka_unit_test_setup(test_release_ends_the_mysql_thread, reset),
		cmocka_unit_test_setup(test_release_nulls_every_pointer, reset),
		cmocka_unit_test_setup(test_release_is_safe_on_already_null_pointers, reset),
		cmocka_unit_test_setup(test_reap_rejects_a_null_status, reset),
		cmocka_unit_test_setup(test_pipe_cloexec_failure_closes_and_clears_both_ends, reset),
		cmocka_unit_test_setup(test_second_pipe_cloexec_failure_closes_and_clears_both_ends, reset),
		cmocka_unit_test_setup(test_reap_retries_waitpid_after_eintr, reset),
		cmocka_unit_test_setup(test_reap_polls_before_it_sleeps, reset),
		cmocka_unit_test_setup(test_release_rejects_null_arguments, reset),
		cmocka_unit_test_setup(test_poll_host_releases_everything_when_host_row_count_is_not_one, reset),
		cmocka_unit_test_setup(test_poll_host_ping_only_uses_the_same_cleanup_path, reset),
		cmocka_unit_test_setup(test_poll_host_flushes_snmp_batch_on_identity_change, reset),
		cmocka_unit_test_setup(test_a_parked_child_is_reaped_by_the_sweep, reset),
		cmocka_unit_test_setup(test_a_live_child_stays_parked_until_it_exits, reset),
		cmocka_unit_test_setup(test_the_parked_list_is_bounded, reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
