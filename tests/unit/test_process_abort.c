/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "internal/common.h"
#include "app/spine.h"
#include "database/persistence.h"
#include "app/startup_internal.h"
#include <sys/wait.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define WORKERS 4
struct owned_processes {
	pid_t leader;
	pid_t descendant;
};
static int ready_fd;
static int control_fd;
static int abort_from_worker;

#ifdef SPINE_TEST_ABORT_FAULTS
static _Atomic int injected_fault;
static _Thread_local int write_interrupted;
static int fail_shutdown_reap;
static int reap_calls;
static pthread_mutex_t close_gate = PTHREAD_MUTEX_INITIALIZER;
static int close_waiting;
static int close_released;
static _Thread_local int closing_owner;
extern int __real_pipe(int descriptors[2]);
extern int __real_fcntl(int fd, int command, ...);
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*) (void *), void *);
extern ssize_t __real_read(int, void *, size_t);
#ifdef __GLIBC__
extern ssize_t __real___read_chk(int, void *, size_t, size_t);
#endif
extern ssize_t __real_write(int, const void *, size_t);
extern int __real_raise(int);
extern int __real_pthread_kill(pthread_t, int);
extern int __real_usleep(useconds_t);
extern int __real_spine_worker_set_reap(spine_worker_set_t *, size_t *);
extern void __gcov_dump(void) __attribute__((weak));
extern void __gcov_reset(void) __attribute__((weak));

int __wrap_pipe(int descriptors[2]) {
	if (injected_fault == 1) {
		errno = EMFILE;
		return -1;
	}
	return __real_pipe(descriptors);
}

int __wrap_fcntl(int fd, int command, ...) {
	va_list args;
	int value = 0;
	if ((injected_fault == 2 && command == F_GETFL) ||
		(injected_fault == 3 && command == F_SETFL)) {
		errno = EIO;
		return -1;
	}
	if (command != F_GETFL && command != F_GETFD) {
		va_start(args, command);
		value = va_arg(args, int);
		va_end(args);
	}
	return __real_fcntl(fd, command, value);
}

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*entry)(void *), void *arg) {
	if (injected_fault == 4) return EAGAIN;
	return __real_pthread_create(thread, attr, entry, arg);
}

ssize_t __wrap_read(int fd, void *buffer, size_t size) {
	if (injected_fault == 5) {
		errno = EIO;
		return -1;
	}
	return __real_read(fd, buffer, size);
}

#ifdef __GLIBC__
/* Fortified headers may route the same source read through __read_chk under
 * newer Clang. Preserve its buffer check when the fault is not armed. */
ssize_t __wrap___read_chk(int fd, void *buffer, size_t size, size_t capacity) {
	if (injected_fault == 5) {
		errno = EIO;
		return -1;
	}
	return __real___read_chk(fd, buffer, size, capacity);
}
#endif

ssize_t __wrap_write(int fd, const void *buffer, size_t size) {
	if (injected_fault == 6 && size == 1) {
		errno = EIO;
		return -1;
	}
	if (injected_fault == 7 && size == 1 && !write_interrupted) {
		write_interrupted = TRUE;
		errno = EINTR;
		return -1;
	}
	if (injected_fault == 8 && size == 1) {
		ssize_t sent = __real_write(fd, buffer, size);
		if (sent != 1) return sent;
		errno = EAGAIN;
		return -1;
	}
	return __real_write(fd, buffer, size);
}

int __wrap_raise(int signal_number) {
	/* Instrumentation only: preserve real signal behavior, flushing counters
	 * before the kernel ends a fixture without normal gcov exit handlers. */
	if (__gcov_dump != NULL) {
		__gcov_dump();
		if (__gcov_reset != NULL) __gcov_reset();
	}
	return __real_raise(signal_number);
}

int __wrap_pthread_kill(pthread_t thread, int signal_number) {
	if (__gcov_dump != NULL) {
		__gcov_dump();
		if (__gcov_reset != NULL) __gcov_reset();
	}
	if (injected_fault == 9) return EINVAL;
	return __real_pthread_kill(thread, signal_number);
}

int __wrap_usleep(useconds_t delay) {
	if (closing_owner) {
		int released = FALSE;
		while (!released) {
			pthread_mutex_lock(&close_gate);
			close_waiting = TRUE;
			released = close_released;
			pthread_mutex_unlock(&close_gate);
			if (!released) __real_usleep(1000);
		}
	}
	return __real_usleep(delay);
}

int __wrap_spine_worker_set_reap(spine_worker_set_t *workers, size_t *remaining) {
	if (fail_shutdown_reap && ++reap_calls == 2) return EIO;
	return __real_spine_worker_set_reap(workers, remaining);
}
#endif

static void *script_worker(void *argument) {
	struct owned_processes owned;
	int fd;
	char line[64];
	char byte;
	FILE *stream;
	long descendant;
	(void) argument;

	fd = nft_popen("trap '' TERM; sleep 300 & printf '%s\\n' \"$!\"; wait", "r");
	if (fd < 0) _exit(91);
	owned.leader = nft_pchild(fd);
	stream = fdopen(dup(fd), "r");
	if (stream == NULL || fgets(line, sizeof(line), stream) == NULL) _exit(92);
	descendant = strtol(line, NULL, 10);
	owned.descendant = (pid_t) descendant;
	fclose(stream);
	if (write(ready_fd, &owned, sizeof(owned)) != sizeof(owned)) _exit(93);
	if (abort_from_worker && argument != NULL) {
		if (read(control_fd, &byte, 1) != 1) _exit(94);
		die("Fixture fatal worker error");
	}
	/* Keep this worker owning its subprocess while another worker or the
	 * termination coordinator aborts the whole external-script registry. */
	/* This fixture ends the whole process deliberately. Keep its detached
	 * owners alive without starting unrelated close/reap work during exit. */
	for (;;) pause();
	return NULL;
}

static int process_alive(pid_t pid) {
#ifdef __linux__
	char path[64];
	char line[256];
	char *end;
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%ld/stat", (long) pid);
	file = fopen(path, "r");
	if (file != NULL) {
		if (fgets(line, sizeof(line), file) != NULL) {
			end = strrchr(line, ')');
			if (end != NULL && end[1] == ' ' && end[2] == 'Z') {
				fclose(file);
				return FALSE;
			}
		}
		fclose(file);
	}
#endif
	return kill(pid, 0) == 0 || errno != ESRCH;
}

static void check_abort(int signal_number, int worker_fatal) {
	int ready[2];
	int control[2];
	pid_t fixture;
	pid_t waited;
	int status = 0;
	int attempt;
	int i;
	int survivors = 0;
	struct owned_processes owned[WORKERS];

#ifdef __linux__
	/* Adopt and reap the fixture's descendants instead of relying on a
	 * container's PID 1 to reap orphan zombies. */
	assert_int_equal(prctl(PR_SET_CHILD_SUBREAPER, 1), 0);
#endif
	assert_int_equal(pipe(ready), 0);
	assert_int_equal(pipe(control), 0);
	fixture = fork();
	assert_true(fixture >= 0);
	if (fixture == 0) {
		pthread_t workers[WORKERS];
		pthread_attr_t attributes;
		char byte;
		close(ready[0]);
		close(control[1]);
		ready_fd = ready[1];
		control_fd = control[0];
		abort_from_worker = worker_fatal;
		init_mutexes();
		install_spine_signal_handler();
		if (pthread_attr_init(&attributes) != 0 ||
			pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED) != 0) _exit(109);
		for (i = 0; i < WORKERS; i++) {
			if (pthread_create(&workers[i], &attributes, script_worker, i == 0 ? &workers[0] : NULL) != 0) _exit(95);
		}
		(void) pthread_attr_destroy(&attributes);
		if (!worker_fatal) {
			if (read(control_fd, &byte, 1) != 1) _exit(96);
			if (signal_number == 0) die("Fixture fatal parent error");
			/* Deliver on a worker to prove handler handoff does not prevent
			 * that worker from releasing a registry lock. */
			if (pthread_kill(workers[0], signal_number) != 0) _exit(97);
		}
		for (;;) pause();
	}
	close(ready[1]);
	close(control[0]);
	for (i = 0; i < WORKERS; i++) {
		assert_int_equal(read(ready[0], &owned[i], sizeof(owned[i])), sizeof(owned[i]));
		assert_true(owned[i].leader > 1 && owned[i].descendant > 1);
	}
	assert_int_equal(write(control[1], "x", 1), 1);
	close(control[1]);
	close(ready[0]);
	waited = 0;
	for (attempt = 0; attempt < 500 && waited == 0; attempt++) {
		waited = waitpid(fixture, &status, WNOHANG);
		if (waited == 0) usleep(10000);
	}
	/* Always clean the fixture before asserting, including a broken policy. */
	if (waited != fixture) {
		(void) kill(fixture, SIGKILL);
		(void) waitpid(fixture, &status, 0);
	}
	for (i = 0; i < WORKERS; i++) {
		for (attempt = 0; attempt < 200 &&
			 (process_alive(owned[i].leader) || process_alive(owned[i].descendant));
			 attempt++) usleep(10000);
		survivors += process_alive(owned[i].leader) || process_alive(owned[i].descendant);
		(void) kill(-owned[i].leader, SIGKILL);
#ifdef __linux__
		(void) waitpid(owned[i].leader, NULL, 0);
		(void) waitpid(owned[i].descendant, NULL, 0);
#endif
	}
	assert_int_equal(waited, fixture);
	assert_int_equal(survivors, 0);
	if (signal_number == 0) {
		assert_true(WIFEXITED(status));
		assert_int_equal(WEXITSTATUS(status), EXIT_FAILURE);
	} else {
		assert_true(WIFSIGNALED(status));
		assert_int_equal(WTERMSIG(status), signal_number);
	}
}

static void test_fatal_parent(void **state) {
	(void) state;
	check_abort(0, FALSE);
}
static void test_fatal_worker(void **state) {
	(void) state;
	check_abort(0, TRUE);
}
static void test_interrupt(void **state) {
	(void) state;
	check_abort(SIGINT, FALSE);
}
static void test_terminate(void **state) {
	(void) state;
	check_abort(SIGTERM, FALSE);
}
static void test_quit(void **state) {
	(void) state;
	check_abort(SIGQUIT, FALSE);
}

static void test_abort_rejects_spawn_and_preserves_closing_owner(void **state) {
	pid_t fixture;
	int status;
	(void) state;
	fixture = fork();
	assert_true(fixture >= 0);
	if (fixture == 0) {
		int fd = nft_popen("printf x; sleep 300", "r");
		int result;
		int parked_status;
		pid_t parked;
		poller_queries_t queries = {0};
		target_t item = {0};
		poll_output_buffers_t output;
		char byte;
		if (fd < 0 || read(fd, &byte, 1) != 1) _exit(98);
		parked = fork();
		if (parked < 0) _exit(101);
		if (parked == 0) {
			for (;;) pause();
		}
		nft_abandon_child(parked, "abort fixture");
		nft_abort_children();
		nft_abort_children();
		output = write_poll_results(NULL, NULL, &queries, &item, 1, "1791676800");
		if (!output.failed || output.output != NULL || output.boost != NULL) _exit(110);
		if (waitpid(parked, &parked_status, 0) != parked ||
			!WIFSIGNALED(parked_status) || WTERMSIG(parked_status) != SIGKILL) _exit(102);
		errno = 0;
		result = nft_popen("exit 0", "r");
		if (result != -1 || errno != ECANCELED) _exit(99);
		(void) nft_pclose(fd);
		if (nft_pclose(fd) != -1 || errno != EBADF) _exit(100);
		_exit(0);
	}
	assert_int_equal(waitpid(fixture, &status, 0), fixture);
	assert_true(WIFEXITED(status));
	assert_int_equal(WEXITSTATUS(status), 0);
}

static void test_coordinator_install_uninstall(void **state) {
	(void) state;
	install_spine_signal_handler();
	install_spine_signal_handler();
	uninstall_spine_signal_handler();
	uninstall_spine_signal_handler();
	install_spine_signal_handler();
	uninstall_spine_signal_handler();
}

static void test_owned_reap_rejects_invalid_owner(void **state) {
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pid_t pid = 0;
	int status;
	(void) state;
	assert_int_equal(spine_reap_child_owned(NULL, &status, 1, &mutex), -1);
	assert_int_equal(spine_reap_child_owned(&pid, &status, 1, &mutex), -1);
	pid = getpid();
	assert_int_equal(spine_reap_child_owned(&pid, &status, 1, NULL), -1);
}

struct deadline_owner {
	int ready;
	int blocked;
	int script;
};

static void *deadline_worker(void *argument) {
	struct deadline_owner *owner = argument;
	int fd = owner->blocked;
	char byte;
	ssize_t received;
	if (owner->script) {
		fd = nft_popen("printf x; exec sleep 300", "r");
		if (fd < 0 || read(fd, &byte, 1) != 1) _exit(111);
	}
	if (write(owner->ready, "x", 1) != 1) _exit(112);
	received = read(fd, &byte, 1);
	if (received < 0) _exit(113);
	if (owner->script) (void) nft_pclose(fd);
	return NULL;
}

static void test_deadline_joins_stopped_workers_or_preserves_live_state(void **state) {
	int scenario;
	(void) state;
	for (scenario = 0; scenario < 3; scenario++) {
		pid_t fixture;
		int status;
		double start = spine_monotonic_time();
#ifndef SPINE_TEST_ABORT_FAULTS
		if (scenario == 2) continue;
#endif
		fixture = fork();
		assert_true(fixture >= 0);
		if (fixture == 0) {
			spine_worker_set_t workers = {0};
			pthread_attr_t attributes;
			struct deadline_owner owner;
			int ready[2];
			int blocked[2];
			char byte;
			alarm(5);
			if (pipe(ready) != 0 || pipe(blocked) != 0) _exit(114);
			owner = (struct deadline_owner){.ready = ready[1], .blocked = blocked[0], .script = scenario == 0};
			set.poller.threads = 1;
			set.poller.poller_interval = 1;
			if (pthread_attr_init(&attributes) != 0 ||
				spine_permits_init(&available_threads, 1) != 0 ||
				spine_worker_set_init(&workers, 1) != 0 ||
				spine_worker_set_start(&workers, &attributes, deadline_worker, &owner) != 0) _exit(115);
			(void) pthread_attr_destroy(&attributes);
			if (read(ready[0], &byte, 1) != 1) _exit(116);
#ifdef SPINE_TEST_ABORT_FAULTS
			fail_shutdown_reap = scenario == 2;
#endif
			(void) wait_for_workers(get_time_as_double() - 2, &workers);
			_exit(117);
		}
		assert_int_equal(waitpid(fixture, &status, 0), fixture);
		assert_true(WIFEXITED(status));
		assert_int_equal(WEXITSTATUS(status), EXIT_FAILURE);
		assert_true(spine_monotonic_time() - start < 3);
	}
}

#ifdef SPINE_TEST_ABORT_FAULTS
static void *gated_close(void *argument) {
	int *result = argument;
	closing_owner = TRUE;
	*result = nft_pclose(*result);
	return NULL;
}

static void test_abort_and_cancellation_during_close(void **state) {
	int cancel;
	(void) state;
	for (cancel = 0; cancel < 2; cancel++) {
		int status;
		pid_t fixture = fork();
		assert_true(fixture >= 0);
		if (fixture == 0) {
			pthread_t closer;
			void *joined;
			int result = nft_popen("printf x; exec sleep 300", "r");
			pid_t child = nft_pchild(result);
			char ready;
			int waiting = FALSE;
			alarm(5);
			if (result < 0 || read(result, &ready, 1) != 1) _exit(103);
			if (pthread_create(&closer, NULL, gated_close, &result) != 0) _exit(104);
			while (!waiting) {
				pthread_mutex_lock(&close_gate);
				waiting = close_waiting;
				pthread_mutex_unlock(&close_gate);
				__real_usleep(1000);
			}
			if (cancel) {
				if (pthread_cancel(closer) != 0) _exit(105);
			} else {
				nft_abort_children();
				pthread_mutex_lock(&close_gate);
				close_released = TRUE;
				pthread_mutex_unlock(&close_gate);
			}
			if (pthread_join(closer, &joined) != 0) _exit(106);
			if (cancel) {
				if (joined != PTHREAD_CANCELED || waitpid(child, &status, 0) != child ||
					!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL) _exit(107);
			} else if (!WIFSIGNALED(result) || WTERMSIG(result) != SIGKILL) _exit(108);
			(void) nft_abandoned_pending();
			_exit(0);
		}
		assert_int_equal(waitpid(fixture, &status, 0), fixture);
		assert_true(WIFEXITED(status));
		assert_int_equal(WEXITSTATUS(status), 0);
	}
}

static void test_coordinator_failures_are_fatal(void **state) {
	int fault;
	(void) state;
	for (fault = 1; fault <= 9; fault++) {
		int status;
		pid_t fixture = fork();
		assert_true(fixture >= 0);
		if (fixture == 0) {
			alarm(5);
			injected_fault = fault;
			install_spine_signal_handler();
			if (fault >= 6) {
				/* kill enters the handler without going through the wrapped
				 * raise that the coordinator uses for its final disposition. */
				(void) kill(getpid(), SIGTERM);
			}
			for (;;) pause();
		}
		assert_int_equal(waitpid(fixture, &status, 0), fixture);
		fprintf(stderr, "Termination fault case %i: raw status %i\n", fault, status);
		if (fault <= 5 || fault == 9) {
			assert_true(WIFEXITED(status));
			assert_int_equal(WEXITSTATUS(status), fault == 9 ? 128 + SIGTERM : EXIT_FAILURE);
		} else {
			assert_true(WIFSIGNALED(status));
			assert_int_equal(WTERMSIG(status), SIGTERM);
		}
	}
}
#endif

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_fatal_parent),
		cmocka_unit_test(test_fatal_worker),
		cmocka_unit_test(test_interrupt),
		cmocka_unit_test(test_terminate),
		cmocka_unit_test(test_quit),
		cmocka_unit_test(test_abort_rejects_spawn_and_preserves_closing_owner),
		cmocka_unit_test(test_coordinator_install_uninstall),
		cmocka_unit_test(test_owned_reap_rejects_invalid_owner),
		cmocka_unit_test(test_deadline_joins_stopped_workers_or_preserves_live_state),
#ifdef SPINE_TEST_ABORT_FAULTS
		cmocka_unit_test(test_abort_and_cancellation_during_close),
		cmocka_unit_test(test_coordinator_failures_are_fatal),
#endif
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
