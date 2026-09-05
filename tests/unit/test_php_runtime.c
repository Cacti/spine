/* Production-linked PHP Script Server runtime tests.
 *
 * These use a real child, real close-on-exec pipes and the shipped php.c.
 * They deliberately avoid a Cacti/PHP installation while covering the hot
 * init -> command -> response -> close lifecycle and deterministic failures.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <poll.h>

#include "common.h"
#include "spine.h"
#include "php.h"

static pthread_mutex_t spawn_barrier_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t spawn_barrier_cond = PTHREAD_COND_INITIALIZER;
static int block_shell_spawn;
static int block_php_spawn;
static int shell_spawn_reached;
static int release_shell_spawn;
static int fail_next_dup;
static int fail_duplicated_cloexec;
static __thread int duplicated_fd = -1;
static int fail_next_setsigdefault;
static int track_spawnattr_destroy;
static int spawnattr_destroyed;
static int php_spawn_calls;
static int fail_php_spawn_call;
static int fail_next_sigmask;
static int track_write;
static int write_calls;

int __real_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset);
int __wrap_pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset) {
	if (fail_next_sigmask && how == SIG_BLOCK) {
		fail_next_sigmask = FALSE;
		return EAGAIN;
	}
	return __real_pthread_sigmask(how, set, oldset);
}

ssize_t __real_write(int fd, const void *buffer, size_t length);
ssize_t __wrap_write(int fd, const void *buffer, size_t length) {
	if (track_write) write_calls++;
	return __real_write(fd, buffer, length);
}

int __real_dup(int fd);
int __wrap_dup(int fd) {
	int result;
	if (fail_next_dup) {
		fail_next_dup = FALSE;
		errno = EMFILE;
		return -1;
	}
	result = __real_dup(fd);
	duplicated_fd = result;
	return result;
}

int __real_fcntl(int fd, int command, ...);
int __wrap_fcntl(int fd, int command, ...) {
	va_list args;
	int argument;

	if (fail_duplicated_cloexec && fd == duplicated_fd && command == F_SETFD) {
		fail_duplicated_cloexec = FALSE;
		errno = EIO;
		return -1;
	}
	if (command == F_GETFD) return __real_fcntl(fd, command);
	va_start(args, command);
	argument = va_arg(args, int);
	va_end(args);
	return __real_fcntl(fd, command, argument);
}

int __real_posix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *actions,
	const posix_spawnattr_t *attributes,
	char *const argv[], char *const envp[]);

int __wrap_posix_spawn(pid_t *pid, const char *path,
	const posix_spawn_file_actions_t *actions,
	const posix_spawnattr_t *attributes,
	char *const argv[], char *const envp[]) {
	if (strcmp(path, PHP_TEST_SERVER_PATH) == 0) {
		php_spawn_calls++;
		if (php_spawn_calls == fail_php_spawn_call) return EIO;
	}
	if ((block_shell_spawn && strcmp(path, "/bin/sh") == 0) ||
	    (block_php_spawn && strcmp(path, PHP_TEST_SERVER_PATH) == 0)) {
		pthread_mutex_lock(&spawn_barrier_mutex);
		shell_spawn_reached = TRUE;
		pthread_cond_broadcast(&spawn_barrier_cond);
		while (!release_shell_spawn) {
			pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
		}
		pthread_mutex_unlock(&spawn_barrier_mutex);
	}

	return __real_posix_spawn(pid, path, actions, attributes, argv, envp);
}

int __real_posix_spawnattr_setsigdefault(posix_spawnattr_t *attr, const sigset_t *defaults);
int __wrap_posix_spawnattr_setsigdefault(posix_spawnattr_t *attr, const sigset_t *defaults) {
	if (fail_next_setsigdefault) {
		fail_next_setsigdefault = FALSE;
		return EIO;
	}
	return __real_posix_spawnattr_setsigdefault(attr, defaults);
}

int __real_posix_spawnattr_destroy(posix_spawnattr_t *attr);
int __wrap_posix_spawnattr_destroy(posix_spawnattr_t *attr) {
	if (track_spawnattr_destroy) spawnattr_destroyed = TRUE;
	return __real_posix_spawnattr_destroy(attr);
}

static int php_setup(void **state) {
	int i;

	(void) state;
	memset(&set, 0, sizeof(set));
	init_mutexes();
	signal(SIGPIPE, SIG_IGN);

	php_processes = calloc(MAX_PHP_SERVERS, sizeof(*php_processes));
	assert_non_null(php_processes);
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		php_processes[i].php_state = PHP_BUSY;
		php_processes[i].php_pid = -1;
		php_processes[i].php_read_fd = -1;
		php_processes[i].php_write_fd = -1;
	}

	set.php_servers = 2;
	set.script_timeout = 1;
	set.cacti_version = 1300;
	set.poller_id = 1;
	set.log_destination = LOGDEST_STDOUT;
	block_shell_spawn = FALSE;
	block_php_spawn = FALSE;
	shell_spawn_reached = FALSE;
	release_shell_spawn = FALSE;
	fail_next_dup = FALSE;
	fail_duplicated_cloexec = FALSE;
	duplicated_fd = -1;
	fail_next_setsigdefault = FALSE;
	track_spawnattr_destroy = FALSE;
	spawnattr_destroyed = FALSE;
	php_spawn_calls = 0;
	fail_php_spawn_call = 0;
	fail_next_sigmask = FALSE;
	track_write = FALSE;
	write_calls = 0;
	snprintf(set.path_php, sizeof(set.path_php), "%s", PHP_TEST_SERVER_PATH);
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "normal");
	return 0;
}

static int php_teardown(void **state) {
	int i;

	(void) state;
	if (php_processes != NULL) {
		for (i = 0; i < MAX_PHP_SERVERS; i++) {
			if (php_processes[i].php_pid > 1) {
				php_close(i);
			} else {
				if (php_processes[i].php_read_fd > STDERR_FILENO)
					close(php_processes[i].php_read_fd);
				if (php_processes[i].php_write_fd > STDERR_FILENO &&
				    php_processes[i].php_write_fd != php_processes[i].php_read_fd)
					close(php_processes[i].php_write_fd);
			}
		}
		free(php_processes);
		php_processes = NULL;
	}
	return 0;
}

static void test_round_robin_wraps_at_server_count(void **state) {
	(void) state;
	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_pid = 10;
	php_processes[0].php_read_fd = 10;
	php_processes[0].php_write_fd = 11;
	php_processes[1].php_state = PHP_READY;
	php_processes[1].php_pid = 12;
	php_processes[1].php_read_fd = 12;
	php_processes[1].php_write_fd = 13;
	set.php_current_server = set.php_servers;
	assert_int_equal(php_get_process(), 0);
	assert_int_equal(php_get_process(), 1);
	assert_int_equal(php_get_process(), 0);
	php_processes[0].php_pid = php_processes[0].php_read_fd = php_processes[0].php_write_fd = -1;
	php_processes[1].php_pid = php_processes[1].php_read_fd = php_processes[1].php_write_fd = -1;
}

static void test_round_robin_rejects_failed_slots(void **state) {
	(void) state;
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	assert_int_equal(php_get_process(), -1);
}

static void test_round_robin_returns_a_healthy_slot_when_all_are_contended(void **state) {
	int i;
	(void) state;

	for (i = 0; i < set.php_servers; i++) {
		php_processes[i].php_state = PHP_READY;
		php_processes[i].php_pid = 100 + i;
		php_processes[i].php_read_fd = 20 + (i * 2);
		php_processes[i].php_write_fd = 21 + (i * 2);
		thread_mutex_lock(LOCK_PHP_PROC_0 + i);
	}

	set.php_current_server = 0;
	assert_int_equal(php_get_process(), 0);

	for (i = 0; i < set.php_servers; i++) {
		thread_mutex_unlock(LOCK_PHP_PROC_0 + i);
		php_processes[i].php_pid = -1;
		php_processes[i].php_read_fd = -1;
		php_processes[i].php_write_fd = -1;
	}
}

static void *hold_php_slot(void *arg) {
	int slot = *(int *)arg;

	thread_mutex_lock(LOCK_PHP_PROC_0 + slot);
	pthread_mutex_lock(&spawn_barrier_mutex);
	shell_spawn_reached = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	while (!release_shell_spawn) {
		pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
	}
	pthread_mutex_unlock(&spawn_barrier_mutex);
	thread_mutex_unlock(LOCK_PHP_PROC_0 + slot);
	return NULL;
}

static void test_dead_slot_is_recovered_while_another_slot_is_contended(void **state) {
	pthread_t holder;
	int held_slot = 0;
	int selected;
	(void) state;

	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_pid = 100;
	php_processes[0].php_read_fd = 20;
	php_processes[0].php_write_fd = 21;
	set.php_current_server = 0;
	assert_int_equal(pthread_create(&holder, NULL, hold_php_slot, &held_slot), 0);
	pthread_mutex_lock(&spawn_barrier_mutex);
	while (!shell_spawn_reached) {
		pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
	}
	pthread_mutex_unlock(&spawn_barrier_mutex);

	selected = php_get_process();
	assert_int_equal(selected, 1);
	assert_int_equal(php_processes[1].php_state, PHP_READY);

	pthread_mutex_lock(&spawn_barrier_mutex);
	release_shell_spawn = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	pthread_mutex_unlock(&spawn_barrier_mutex);
	assert_int_equal(pthread_join(holder, NULL), 0);
	php_processes[0].php_pid = -1;
	php_processes[0].php_read_fd = -1;
	php_processes[0].php_write_fd = -1;
}

static void test_failed_recovery_falls_back_to_the_contended_slot(void **state) {
	pthread_t holder;
	int held_slot = 0;
	int selected;
	(void) state;

	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_pid = 100;
	php_processes[0].php_read_fd = 20;
	php_processes[0].php_write_fd = 21;
	set.php_current_server = 0;
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	assert_int_equal(pthread_create(&holder, NULL, hold_php_slot, &held_slot), 0);
	pthread_mutex_lock(&spawn_barrier_mutex);
	while (!shell_spawn_reached) {
		pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
	}
	pthread_mutex_unlock(&spawn_barrier_mutex);

	selected = php_get_process();
	assert_int_equal(selected, 0);

	pthread_mutex_lock(&spawn_barrier_mutex);
	release_shell_spawn = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	pthread_mutex_unlock(&spawn_barrier_mutex);
	assert_int_equal(pthread_join(holder, NULL), 0);
	php_processes[0].php_pid = -1;
	php_processes[0].php_read_fd = -1;
	php_processes[0].php_write_fd = -1;
}

static void noop_sigpipe_handler(int signal_number) {
	(void) signal_number;
}

static void test_broken_pipe_with_runtime_sigpipe_handler_does_not_block(void **state) {
	struct sigaction action;
	int pdes[2];
	pid_t child;
	int status;
	int attempts;
	(void) state;

	assert_int_equal(pipe(pdes), 0);
	close(pdes[0]);
	child = fork();
	assert_true(child >= 0);
	if (child == 0) {
		memset(&action, 0, sizeof(action));
		action.sa_handler = noop_sigpipe_handler;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGPIPE, &action, NULL) != 0) _exit(2);
		errno = 0;
		if (php_write_no_sigpipe_for_test(pdes[1], "x", 1) != -1 || errno != EPIPE)
			_exit(3);
		_exit(0);
	}
	close(pdes[1]);
	for (attempts = 0; attempts < 100; attempts++) {
		pid_t waited = waitpid(child, &status, WNOHANG);
		if (waited == child) break;
		assert_true(waited == 0 || (waited < 0 && errno == EINTR));
		usleep(10000);
	}
	if (attempts == 100) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		fail_msg("SIGPIPE-protected write blocked for more than one second");
	}
	assert_true(WIFEXITED(status));
	assert_int_equal(WEXITSTATUS(status), 0);
}

static void test_sigmask_failure_prevents_the_pipe_write(void **state) {
	(void) state;

	fail_next_sigmask = TRUE;
	track_write = TRUE;
	errno = 0;
	assert_int_equal(php_write_no_sigpipe_for_test(-1, "x", 1), -1);
	assert_int_equal(errno, EAGAIN);
	assert_int_equal(write_calls, 0);
	track_write = FALSE;
}

static void test_preexisting_pending_sigpipe_is_preserved(void **state) {
	struct sigaction saved_action;
	struct sigaction default_action;
	sigset_t blocked;
	sigset_t old_mask;
	sigset_t pending;
	int pdes[2];
	int received_signal = 0;
	int result;
	int saved_errno;
	int pending_before;
	int pending_after;

	(void) state;
	assert_int_equal(sigaction(SIGPIPE, NULL, &saved_action), 0);
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGPIPE);
	assert_int_equal(pthread_sigmask(SIG_BLOCK, &blocked, &old_mask), 0);
	memset(&default_action, 0, sizeof(default_action));
	default_action.sa_handler = SIG_DFL;
	sigemptyset(&default_action.sa_mask);
	assert_int_equal(sigaction(SIGPIPE, &default_action, NULL), 0);
	assert_int_equal(raise(SIGPIPE), 0);
	assert_int_equal(sigpending(&pending), 0);
	pending_before = sigismember(&pending, SIGPIPE);

	assert_int_equal(pipe(pdes), 0);
	close(pdes[0]);
	errno = 0;
	result = (int)php_write_no_sigpipe_for_test(pdes[1], "x", 1);
	saved_errno = errno;
	assert_int_equal(sigpending(&pending), 0);
	pending_after = sigismember(&pending, SIGPIPE);
	close(pdes[1]);
	assert_int_equal(sigwait(&blocked, &received_signal), 0);
	assert_int_equal(sigaction(SIGPIPE, &saved_action, NULL), 0);
	assert_int_equal(pthread_sigmask(SIG_SETMASK, &old_mask, NULL), 0);

	assert_true(pending_before);
	assert_int_equal(result, -1);
	assert_int_equal(saved_errno, EPIPE);
	assert_true(pending_after);
	assert_int_equal(received_signal, SIGPIPE);
}

static void test_spawnattr_sigpipe_failure_destroys_initialized_attr(void **state) {
	posix_spawnattr_t attr;
	(void) state;

	fail_next_setsigdefault = TRUE;
	track_spawnattr_destroy = TRUE;
	errno = 0;
	assert_int_equal(spine_spawnattr_sigpipe_default(&attr), -1);
	assert_int_equal(errno, EIO);
	assert_true(spawnattr_destroyed);
	track_spawnattr_destroy = FALSE;
}

static void test_full_script_server_lifecycle(void **state) {
	char *result;

	(void) state;
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
	assert_true(php_processes[0].php_pid > 1);
	assert_true(php_processes[0].php_read_fd >= 0);
	assert_true(php_processes[0].php_write_fd >= 0);

	result = php_cmd("poll 7", 0);
	assert_non_null(result);
	assert_string_equal(result, "42\n");
	free(result);

	php_close(0);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
}

static void test_php_child_restores_sigpipe_default(void **state) {
	(void) state;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "check-sigpipe");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
}

static void test_script_server_lifecycle_with_stdio_closed(void **state) {
	int saved_stdin;
	int saved_stdout;
	int init_result;
	char *result = NULL;

	(void) state;
	saved_stdin = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0);
	assert_true(saved_stdout >= 0);

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	init_result = php_init(0);
	if (init_result == TRUE) {
		result = php_cmd("poll 7", 0);
		php_close(0);
	}

	dup2(saved_stdin, STDIN_FILENO);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdin);
	close(saved_stdout);

	assert_int_equal(init_result, TRUE);
	assert_non_null(result);
	assert_string_equal(result, "42\n");
	free(result);
}

struct popen_thread_result {
	int fd;
};

static void *open_script_while_blocked(void *arg) {
	struct popen_thread_result *result = arg;
	result->fd = nft_popen("printf concurrent-visible", "r");
	return NULL;
}

static void test_php_spawn_does_not_inherit_an_nft_collision_descriptor(void **state) {
	struct popen_thread_result opened = { .fd = -1 };
	pthread_t thread;
	struct pollfd pfd;
	char output[128] = {0};
	ssize_t n;
	int total = 0;
	int reached_eof = FALSE;
	int saved_stdin;
	int saved_stdout;
	int init_result;

	(void) state;
	saved_stdin = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0);
	assert_true(saved_stdout >= 0);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	block_shell_spawn = TRUE;
	assert_int_equal(pthread_create(&thread, NULL, open_script_while_blocked, &opened), 0);
	pthread_mutex_lock(&spawn_barrier_mutex);
	while (!shell_spawn_reached) {
		pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
	}
	pthread_mutex_unlock(&spawn_barrier_mutex);

	/* The nft_popen collision duplicate exists but has not spawned yet. A PHP
	 * child started in this window must not inherit that pipe write end. */
	init_result = php_init(0);

	pthread_mutex_lock(&spawn_barrier_mutex);
	release_shell_spawn = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	pthread_mutex_unlock(&spawn_barrier_mutex);
	assert_int_equal(pthread_join(thread, NULL), 0);

	if (opened.fd >= 0) {
		pfd.fd = opened.fd;
		pfd.events = POLLIN;
		while (poll(&pfd, 1, 2000) > 0) {
			n = read(opened.fd, output + total, sizeof(output) - 1 - (size_t)total);
			if (n == 0) {
				reached_eof = TRUE;
				break;
			}
			if (n < 0) break;
			total += (int)n;
			if ((size_t)total >= sizeof(output) - 1) break;
		}
		output[total] = '\0';
	}

	if (init_result == TRUE) php_close(0);
	if (opened.fd >= 0) nft_pclose(opened.fd);
	dup2(saved_stdin, STDIN_FILENO);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdin);
	close(saved_stdout);

	assert_int_equal(init_result, TRUE);
	assert_true(opened.fd >= 0);
	assert_non_null(strstr(output, "concurrent-visible"));
	assert_true(reached_eof);
}

static void test_init_marks_an_unexpected_handshake_busy(void **state) {
	(void) state;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "bad-start");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_busy_handshake_is_recovered_on_the_next_poll(void **state) {
	char *result;
	int process;
	pid_t failed_pid;

	(void) state;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "bad-start");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
	failed_pid = php_processes[0].php_pid;
	assert_true(failed_pid > 1);
	assert_true(php_processes[0].php_read_fd >= 0);
	assert_true(php_processes[0].php_write_fd >= 0);

	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "normal");
	process = php_get_process();
	assert_int_equal(process, 0);
	assert_true(php_processes[0].php_pid > 1);
	assert_int_not_equal(php_processes[0].php_pid, failed_pid);
	errno = 0;
	assert_int_equal(waitpid(failed_pid, NULL, WNOHANG), -1);
	assert_int_equal(errno, ECHILD);
	result = php_cmd("poll 7", process);
	assert_non_null(result);
	assert_string_equal(result, "42\n");
	free(result);
}

struct php_thread_result {
	int process;
	char *command_result;
};

static int command_finished;

static void *get_php_process_thread(void *arg) {
	struct php_thread_result *result = arg;
	result->process = php_get_process();
	return NULL;
}

static void *run_php_command_thread(void *arg) {
	struct php_thread_result *result = arg;
	result->command_result = php_cmd("poll 7", 0);
	pthread_mutex_lock(&spawn_barrier_mutex);
	command_finished = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	pthread_mutex_unlock(&spawn_barrier_mutex);
	return NULL;
}

static void test_recovery_and_command_share_the_slot_lock(void **state) {
	struct php_thread_result recovery = { .process = -1, .command_result = NULL };
	struct php_thread_result command = { .process = -1, .command_result = NULL };
	pthread_t recovery_thread;
	pthread_t command_thread;
	(void) state;

	set.php_servers = 1;
	block_php_spawn = TRUE;
	command_finished = FALSE;
	assert_int_equal(pthread_create(&recovery_thread, NULL, get_php_process_thread, &recovery), 0);

	pthread_mutex_lock(&spawn_barrier_mutex);
	while (!shell_spawn_reached) {
		pthread_cond_wait(&spawn_barrier_cond, &spawn_barrier_mutex);
	}
	pthread_mutex_unlock(&spawn_barrier_mutex);

	/* A blocked handshake must not retain the process-global round-robin lock. */
	assert_int_equal(thread_mutex_trylock(LOCK_PHP), 0);
	thread_mutex_unlock(LOCK_PHP);

	assert_int_equal(pthread_create(&command_thread, NULL, run_php_command_thread, &command), 0);
	usleep(20000);
	pthread_mutex_lock(&spawn_barrier_mutex);
	assert_false(command_finished);
	release_shell_spawn = TRUE;
	pthread_cond_broadcast(&spawn_barrier_cond);
	pthread_mutex_unlock(&spawn_barrier_mutex);

	assert_int_equal(pthread_join(recovery_thread, NULL), 0);
	assert_int_equal(pthread_join(command_thread, NULL), 0);
	assert_int_equal(recovery.process, 0);
	assert_non_null(command.command_result);
	assert_string_equal(command.command_result, "42\n");
	free(command.command_result);
}

static void test_recovery_attempts_only_one_failed_slot_per_call(void **state) {
	double started;
	double elapsed;
	(void) state;

	set.php_servers = 3;
	set.script_timeout = 1;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "silent");
	started = get_time_as_double();
	assert_int_equal(php_get_process(), -1);
	elapsed = get_time_as_double() - started;

	assert_true(elapsed < 2.5);
}

static void test_child_exit_during_startup_fails_closed_without_restart(void **state) {
	(void) state;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "exit-before-start");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_php_init_later_failure_preserves_earlier_server(void **state) {
	pid_t first_pid;
	int first_read_fd;
	int first_write_fd;
	(void) state;

	set.php_servers = 2;
	fail_php_spawn_call = 2;
	assert_int_equal(php_init(PHP_INIT), FALSE);

	first_pid = php_processes[0].php_pid;
	first_read_fd = php_processes[0].php_read_fd;
	first_write_fd = php_processes[0].php_write_fd;
	assert_true(first_pid > 1);
	assert_true(first_read_fd >= 0);
	assert_true(first_write_fd >= 0);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
	assert_int_equal(php_processes[0].php_pid, first_pid);
	assert_int_equal(php_processes[0].php_read_fd, first_read_fd);
	assert_int_equal(php_processes[0].php_write_fd, first_write_fd);
	assert_int_equal(php_processes[1].php_pid, -1);
	assert_int_equal(php_processes[1].php_read_fd, -1);
	assert_int_equal(php_processes[1].php_write_fd, -1);
	assert_int_equal(php_processes[1].php_state, PHP_BUSY);
}

static void assert_stdio_collision_failure_is_clean(int fail_dup, int fail_cloexec) {
	int saved_stdin = dup(STDIN_FILENO);
	int result;
	assert_true(saved_stdin >= 0);
	close(STDIN_FILENO);
	fail_next_dup = fail_dup;
	fail_duplicated_cloexec = fail_cloexec;
	result = php_init(0);
	dup2(saved_stdin, STDIN_FILENO);
	close(saved_stdin);
	assert_int_equal(result, FALSE);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
}

static void test_stdio_collision_dup_failure_is_clean(void **state) {
	(void) state;
	assert_stdio_collision_failure_is_clean(TRUE, FALSE);
}

static void test_stdio_collision_cloexec_failure_is_clean(void **state) {
	(void) state;
	assert_stdio_collision_failure_is_clean(FALSE, TRUE);
}

static void test_init_timeout_does_not_recurse(void **state) {
	(void) state;
	set.script_timeout = 0;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "silent");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_spawn_failure_releases_every_resource(void **state) {
	(void) state;
	/* calloc-like zeroes reproduce the process-wide initialization that used to
	 * let a failed slot masquerade as stdin. php_init() must replace them. */
	memset(&php_processes[0], 0, sizeof(php_processes[0]));
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	assert_int_equal(php_init(0), FALSE);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
}

static void test_command_rejects_a_writable_poisoned_slot(void **state) {
	char *result;
	int fd;

	(void) state;
	fd = open("/dev/null", O_RDWR);
	assert_true(fd >= 0);
	memset(&php_processes[0], 0, sizeof(php_processes[0]));
	php_processes[0].php_write_fd = fd;

	result = php_cmd("poll 9", 0);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	close(fd);
	php_processes[0].php_read_fd = php_processes[0].php_write_fd = -1;
}

static void test_readpipe_rejects_fd_at_fd_setsize(void **state) {
	char command[] = "test";
	char *result;
	int oversized_fd;
	int pdes[2];

	(void) state;
	assert_int_equal(pipe(pdes), 0);
	oversized_fd = fcntl(pdes[0], F_DUPFD, FD_SETSIZE);
	assert_true(oversized_fd >= FD_SETSIZE);
	close(pdes[0]);
	close(pdes[1]);
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_read_fd = oversized_fd;
	result = php_readpipe(0, command);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_int_not_equal(php_processes[0].php_state, PHP_READY);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_get_process(), -1);
}

static void test_startup_read_rejects_fd_at_fd_setsize_without_restart(void **state) {
	char command[] = "INIT";
	char *result;
	int oversized_fd;
	int pdes[2];
	(void) state;

	assert_int_equal(pipe(pdes), 0);
	oversized_fd = fcntl(pdes[0], F_DUPFD, FD_SETSIZE);
	assert_true(oversized_fd >= FD_SETSIZE);
	close(pdes[0]);
	close(pdes[1]);
	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_read_fd = oversized_fd;
	php_processes[0].php_write_fd = -1;

	result = php_read_result_for_test(0, command, FALSE);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
	assert_int_equal(php_processes[0].php_read_fd, oversized_fd);
	assert_int_equal(php_spawn_calls, 0);
	close(oversized_fd);
	php_processes[0].php_read_fd = -1;
}

static void test_command_retires_fd_at_fd_setsize(void **state) {
	char *result;
	int oversized_fd;
	int pdes[2];

	(void) state;
	assert_int_equal(pipe(pdes), 0);
	oversized_fd = fcntl(pdes[0], F_DUPFD, FD_SETSIZE);
	assert_true(oversized_fd >= FD_SETSIZE);
	close(pdes[0]);

	php_processes[0].php_pid = fork();
	assert_true(php_processes[0].php_pid >= 0);
	if (php_processes[0].php_pid == 0) {
		pause();
		_exit(0);
	}
	set.php_servers = 1;
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_read_fd = oversized_fd;
	php_processes[0].php_write_fd = pdes[1];

	result = php_cmd("poll 9", 0);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	assert_int_not_equal(php_processes[0].php_state, PHP_READY);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
	assert_int_equal(php_get_process(), -1);
}

static void test_readpipe_rejects_an_oversized_response(void **state) {
	char payload[RESULTS_BUFFER];
	char command[] = "test";
	char *result;
	int pdes[2];

	(void) state;
	memset(payload, 'x', sizeof(payload));
	assert_int_equal(pipe(pdes), 0);
	assert_int_equal(write(pdes[1], payload, sizeof(payload)), (ssize_t)sizeof(payload));
	close(pdes[1]);
	php_processes[0].php_read_fd = pdes[0];

	result = php_readpipe(0, command);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	close(pdes[0]);
	php_processes[0].php_read_fd = -1;
}

static void test_command_gives_up_after_three_failed_writes(void **state) {
	struct sigaction saved_sigpipe;
	struct sigaction default_sigpipe;
	char *result;
	int pdes[2];

	(void) state;
	assert_int_equal(pipe(pdes), 0);
	close(pdes[0]);
	php_processes[0].php_state = PHP_READY;
	php_processes[0].php_pid = fork();
	assert_true(php_processes[0].php_pid >= 0);
	if (php_processes[0].php_pid == 0) {
		pause();
		_exit(0);
	}
	php_processes[0].php_read_fd = pdes[0];
	php_processes[0].php_write_fd = pdes[1];
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	assert_int_equal(sigaction(SIGPIPE, NULL, &saved_sigpipe), 0);
	memset(&default_sigpipe, 0, sizeof(default_sigpipe));
	default_sigpipe.sa_handler = SIG_DFL;
	assert_int_equal(sigaction(SIGPIPE, &default_sigpipe, NULL), 0);

	result = php_cmd("poll 9", 0);
	sigaction(SIGPIPE, &saved_sigpipe, NULL);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_round_robin_wraps_at_server_count, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_round_robin_rejects_failed_slots, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_round_robin_returns_a_healthy_slot_when_all_are_contended, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_dead_slot_is_recovered_while_another_slot_is_contended, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_failed_recovery_falls_back_to_the_contended_slot, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_broken_pipe_with_runtime_sigpipe_handler_does_not_block, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_sigmask_failure_prevents_the_pipe_write, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_preexisting_pending_sigpipe_is_preserved, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_spawnattr_sigpipe_failure_destroys_initialized_attr, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_full_script_server_lifecycle, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_php_child_restores_sigpipe_default, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_script_server_lifecycle_with_stdio_closed, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_php_spawn_does_not_inherit_an_nft_collision_descriptor, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_init_marks_an_unexpected_handshake_busy, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_busy_handshake_is_recovered_on_the_next_poll, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_recovery_and_command_share_the_slot_lock, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_recovery_attempts_only_one_failed_slot_per_call, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_child_exit_during_startup_fails_closed_without_restart, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_php_init_later_failure_preserves_earlier_server, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_stdio_collision_dup_failure_is_clean, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_stdio_collision_cloexec_failure_is_clean, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_init_timeout_does_not_recurse, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_spawn_failure_releases_every_resource, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_command_rejects_a_writable_poisoned_slot, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_readpipe_rejects_fd_at_fd_setsize, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_startup_read_rejects_fd_at_fd_setsize_without_restart, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_command_retires_fd_at_fd_setsize, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_readpipe_rejects_an_oversized_response, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_command_gives_up_after_three_failed_writes, php_setup, php_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
