/* End-to-end nft_pclose escalation and abandoned-child ownership tests. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "spine.h"
#include "nft_popen.h"

static int reap_results[3];
static int reap_attempts[3];
static int reap_calls;
static int kill_calls;
static int kill_signals[2];
static pthread_mutex_t reap_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reap_cond = PTHREAD_COND_INITIALIZER;
static int block_reap;
static int reap_entered;
static int block_abandon;
static int abandon_entered;
static char last_log[BUFSIZE];
static int fail_next_file_actions_init;

void nft_fill_abandoned_for_test(pid_t pid);
int nft_pclose_grace_attempts_for_test(void);

int __real_posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions);
int __wrap_posix_spawn_file_actions_init(posix_spawn_file_actions_t *actions) {
	if (fail_next_file_actions_init) {
		fail_next_file_actions_init = FALSE;
		return EIO;
	}
	return __real_posix_spawn_file_actions_init(actions);
}

void nft_abandon_parked_test_hook(void) {
	if (!block_abandon) return;
	pthread_mutex_lock(&reap_mutex);
	abandon_entered = TRUE;
	pthread_cond_broadcast(&reap_cond);
	while (block_abandon) pthread_cond_wait(&reap_cond, &reap_mutex);
	pthread_mutex_unlock(&reap_mutex);
}

int spine_reap_child_bounded_test(pid_t pid, int *status, int attempts) {
	int result;
	(void) pid;
	if (block_reap) {
		pthread_mutex_lock(&reap_mutex);
		reap_entered = TRUE;
		pthread_cond_broadcast(&reap_cond);
		pthread_mutex_unlock(&reap_mutex);
		while (block_reap) usleep(1000);
	}
	assert_true(reap_calls < 3);
	reap_attempts[reap_calls] = attempts;
	result = reap_results[reap_calls++];
	if (result == 0 && status != NULL) *status = SIGKILL;
	if (result < 0) errno = EINVAL;
	return result;
}

int __real_kill(pid_t pid, int signal_number);

int __wrap_kill(pid_t pid, int signal_number) {
	if (kill_calls < 2) kill_signals[kill_calls] = signal_number;
	kill_calls++;
	return __real_kill(pid, signal_number);
}

int __wrap_spine_log(const char *format, ...) {
	va_list args;

	va_start(args, format);
	vsnprintf(last_log, sizeof(last_log), format, args);
	va_end(args);
	return 0;
}

static int reset(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	set.log_destination = LOGDEST_STDOUT;
	signal(SIGPIPE, SIG_IGN);
	reap_calls = 0;
	memset(reap_attempts, 0, sizeof(reap_attempts));
	kill_calls = 0;
	memset(kill_signals, 0, sizeof(kill_signals));
	block_reap = FALSE;
	reap_entered = FALSE;
	block_abandon = FALSE;
	abandon_entered = FALSE;
	last_log[0] = '\0';
	fail_next_file_actions_init = FALSE;
	return 0;
}

static int count_open_descriptors(void) {
	int count = 0;
	int fd;

	for (fd = 0; fd < FD_SETSIZE; fd++) {
		if (fcntl(fd, F_GETFD) >= 0) count++;
	}
	return count;
}

static void test_file_actions_init_failure_releases_everything(void **state) {
	int before;

	(void) state;
	before = count_open_descriptors();
	fail_next_file_actions_init = TRUE;
	errno = 0;
	assert_int_equal(nft_popen("printf unreachable", "r"), -1);
	assert_int_equal(errno, EIO);
	assert_int_equal(count_open_descriptors(), before);
	assert_non_null(strstr(last_log, "posix_spawn_file_actions_init failed"));
	assert_int_equal(nft_abandoned_pending(), 0);
}

static pid_t open_sleeping_child(int *fd) {
	pid_t pid;
	*fd = nft_popen("sleep 30", "r");
	assert_true(*fd >= 0);
	pid = nft_pchild(*fd);
	assert_true(pid > 1);
	return pid;
}

static void reap_directly(pid_t pid) {
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
}

static void wait_for_abandoned_sweep(void) {
	int attempt;
	for (attempt = 0; attempt < 100 && nft_abandoned_pending() != 0; attempt++) {
		usleep(1000);
	}
	assert_int_equal(nft_abandoned_pending(), 0);
}

static void test_pclose_escalates_to_sigkill_then_succeeds(void **state) {
	int fd;
	pid_t pid;
	(void) state;
	reap_results[0] = 1;
	reap_results[1] = 1;
	reap_results[2] = 0;
	pid = open_sleeping_child(&fd);
	assert_true(nft_pclose(fd) >= 0);
	assert_int_equal(reap_calls, 3);
	assert_int_equal(kill_calls, 2);
	assert_int_equal(kill_signals[0], SIGTERM);
	assert_int_equal(kill_signals[1], SIGKILL);
	reap_directly(pid);
}

static void test_pclose_allows_exit_after_sigterm_without_sigkill(void **state) {
	int fd;
	pid_t pid;
	(void) state;
	set.script_timeout = 7;
	reap_results[0] = 1;
	reap_results[1] = 0;
	pid = open_sleeping_child(&fd);
	assert_true(nft_pclose(fd) >= 0);
	assert_int_equal(reap_calls, 2);
	assert_true(reap_attempts[0] > reap_attempts[1]);
	assert_int_equal(kill_calls, 1);
	assert_int_equal(kill_signals[0], SIGTERM);
	reap_directly(pid);
}

static void test_pclose_reaps_within_the_grace_budget(void **state) {
	int fd;
	pid_t pid;
	(void) state;
	reap_results[0] = 0;
	pid = open_sleeping_child(&fd);
	assert_true(nft_pclose(fd) >= 0);
	assert_int_equal(reap_calls, 1);
	assert_int_equal(kill_calls, 0);
	assert_int_equal(__real_kill(pid, SIGKILL), 0);
	reap_directly(pid);
}

static void test_pclose_grace_is_capped_below_the_poller_interval(void **state) {
	int normal_attempts;
	int maximum_attempts;
	int short_interval_attempts;

	(void) state;
	set.poller_interval = 60;
	set.script_timeout = 25;
	normal_attempts = nft_pclose_grace_attempts_for_test();
	set.script_timeout = 300;
	maximum_attempts = nft_pclose_grace_attempts_for_test();
	set.poller_interval = 20;
	short_interval_attempts = nft_pclose_grace_attempts_for_test();

	assert_true(normal_attempts > 0);
	assert_int_equal(maximum_attempts, normal_attempts);
	assert_true(short_interval_attempts < normal_attempts);
	#ifndef SOLAR_THREAD
	assert_true(normal_attempts < 60 * 20);
	assert_true(short_interval_attempts < 20 * 20);
	#else
	assert_true(normal_attempts < 60);
	assert_true(short_interval_attempts < 20);
	#endif
}

static void test_pclose_reports_timeout_and_parks_the_pid(void **state) {
	int fd;
	(void) state;
	set.script_timeout = 2;
	reap_results[0] = 1;
	reap_results[1] = 1;
	reap_results[2] = 1;
	open_sleeping_child(&fd);
	errno = 0;
	assert_int_equal(nft_pclose(fd), -1);
	assert_int_equal(errno, ETIMEDOUT);
	assert_int_equal(kill_calls, 2);
	assert_int_equal(kill_signals[0], SIGTERM);
	assert_int_equal(kill_signals[1], SIGKILL);
	assert_int_equal(reap_calls, 3);
	assert_true(reap_attempts[0] > reap_attempts[1]);
	assert_int_equal(reap_attempts[1], reap_attempts[2]);
	wait_for_abandoned_sweep();
}

static void test_pclose_parks_a_pid_after_wait_error(void **state) {
	int fd;
	pid_t pid;
	(void) state;
	reap_results[0] = -1;
	pid = open_sleeping_child(&fd);
	assert_int_equal(nft_pclose(fd), -1);
	assert_int_equal(errno, EINVAL);
	assert_int_equal(kill_calls, 0);
	assert_int_equal(__real_kill(pid, SIGKILL), 0);
	wait_for_abandoned_sweep();
}

static void test_pclose_does_not_sigkill_after_wait_error_during_term_grace(void **state) {
	int fd;
	(void) state;
	reap_results[0] = 1;
	reap_results[1] = -1;
	open_sleeping_child(&fd);
	assert_int_equal(nft_pclose(fd), -1);
	assert_int_equal(errno, EINVAL);
	assert_int_equal(kill_calls, 1);
	assert_int_equal(kill_signals[0], SIGTERM);
	wait_for_abandoned_sweep();
}

static void test_pclose_parks_after_wait_error_during_kill_grace(void **state) {
	int fd;
	(void) state;
	reap_results[0] = 1;
	reap_results[1] = 1;
	reap_results[2] = -1;
	open_sleeping_child(&fd);
	assert_int_equal(nft_pclose(fd), -1);
	assert_int_equal(errno, EINVAL);
	assert_int_equal(kill_calls, 2);
	assert_int_equal(kill_signals[0], SIGTERM);
	wait_for_abandoned_sweep();
}

static void test_pclose_drops_a_new_pid_when_the_abandoned_cap_is_full(void **state) {
	int fd;
	int status;
	pid_t dropped_pid;
	pid_t keeper_pid;

	(void) state;
	keeper_pid = fork();
	assert_true(keeper_pid >= 0);
	if (keeper_pid == 0) {
		pause();
		_exit(0);
	}
	nft_fill_abandoned_for_test(keeper_pid);
	reap_results[0] = -1;
	dropped_pid = open_sleeping_child(&fd);
	assert_int_equal(nft_pclose(fd), -1);
	assert_int_equal(nft_abandoned_pending(), NFT_ABANDONED_MAX);
	assert_non_null(strstr(last_log, "abandoned list is full"));

	assert_int_equal(__real_kill(dropped_pid, SIGKILL), 0);
	reap_directly(dropped_pid);
	assert_int_equal(__real_kill(keeper_pid, SIGKILL), 0);
	while (waitpid(keeper_pid, &status, 0) < 0 && errno == EINTR) {}
	wait_for_abandoned_sweep();
}

struct close_thread_args {
	int fd;
};

static void *run_pclose(void *arg) {
	struct close_thread_args *args = arg;
	(void) nft_pclose(args->fd);
	return NULL;
}

static void *run_pclose_then_testcancel(void *arg) {
	struct close_thread_args *args = arg;
	(void) nft_pclose(args->fd);
	/* nft_pclose() must restore the caller's cancellation state only after its
	 * cleanup handler is disarmed. This is the caller's next safe point. */
	pthread_testcancel();
	return NULL;
}

static void test_cancellation_after_detach_reaps_the_child(void **state) {
	struct close_thread_args args;
	pthread_t thread;
	void *thread_result;
	pid_t pid;
	(void) state;

	reap_results[0] = 1;
	pid = open_sleeping_child(&args.fd);
	block_reap = TRUE;
	assert_int_equal(pthread_create(&thread, NULL, run_pclose, &args), 0);
	pthread_mutex_lock(&reap_mutex);
	while (!reap_entered) pthread_cond_wait(&reap_cond, &reap_mutex);
	pthread_mutex_unlock(&reap_mutex);

	assert_int_equal(pthread_cancel(thread), 0);
	assert_int_equal(pthread_join(thread, &thread_result), 0);
	assert_ptr_equal(thread_result, PTHREAD_CANCELED);
	block_reap = FALSE;

	errno = 0;
	assert_int_equal(nft_pchild(args.fd), -1);
	assert_int_equal(errno, EBADF);
	errno = 0;
	assert_int_equal(waitpid(pid, NULL, WNOHANG), -1);
	assert_int_equal(errno, ECHILD);
}

static void test_cancellation_after_parking_does_not_run_blocking_cleanup(void **state) {
	struct close_thread_args args;
	pthread_t thread;
	void *thread_result;
	(void) state;

	reap_results[0] = 1;
	reap_results[1] = 1;
	reap_results[2] = 1;
	open_sleeping_child(&args.fd);
	block_abandon = TRUE;
	assert_int_equal(pthread_create(&thread, NULL, run_pclose_then_testcancel, &args), 0);
	pthread_mutex_lock(&reap_mutex);
	while (!abandon_entered) pthread_cond_wait(&reap_cond, &reap_mutex);
	pthread_mutex_unlock(&reap_mutex);

	assert_int_equal(pthread_cancel(thread), 0);
	pthread_mutex_lock(&reap_mutex);
	block_abandon = FALSE;
	pthread_cond_broadcast(&reap_cond);
	pthread_mutex_unlock(&reap_mutex);
	assert_int_equal(pthread_join(thread, &thread_result), 0);
	assert_ptr_equal(thread_result, PTHREAD_CANCELED);
	errno = 0;
	assert_int_equal(nft_pchild(args.fd), -1);
	assert_int_equal(errno, EBADF);
	wait_for_abandoned_sweep();
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_file_actions_init_failure_releases_everything, reset),
		cmocka_unit_test_setup(test_pclose_escalates_to_sigkill_then_succeeds, reset),
		cmocka_unit_test_setup(test_pclose_allows_exit_after_sigterm_without_sigkill, reset),
		cmocka_unit_test_setup(test_pclose_reaps_within_the_grace_budget, reset),
		cmocka_unit_test_setup(test_pclose_grace_is_capped_below_the_poller_interval, reset),
		cmocka_unit_test_setup(test_pclose_reports_timeout_and_parks_the_pid, reset),
		cmocka_unit_test_setup(test_pclose_parks_a_pid_after_wait_error, reset),
		cmocka_unit_test_setup(test_pclose_does_not_sigkill_after_wait_error_during_term_grace, reset),
		cmocka_unit_test_setup(test_pclose_parks_after_wait_error_during_kill_grace, reset),
		cmocka_unit_test_setup(test_pclose_drops_a_new_pid_when_the_abandoned_cap_is_full, reset),
		cmocka_unit_test_setup(test_cancellation_after_detach_reaps_the_child, reset),
		cmocka_unit_test_setup(test_cancellation_after_parking_does_not_run_blocking_cleanup, reset),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
