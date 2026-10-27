/* SPDX-License-Identifier: GPL-2.0-or-later
 * Copyright (C) 2026 The Cacti Group
 * Exercise the production process implementation with real children. Only
 * waitpid/clock failures are injected at the system-call boundary. */
#include "common.h"
#include "spine.h"
#include <stdarg.h>
#include <fcntl.h>
#include <sys/wait.h>
#undef waitpid
#undef clock_gettime
extern pid_t waitpid(pid_t, int *, int);
extern int clock_gettime(clockid_t, struct timespec *);

config_t set;
static pthread_mutex_t ForkMutex = PTHREAD_MUTEX_INITIALIZER;
static int WaitFault;
static int ClockFault;
static int Assertions;
static int Cases;
static pthread_mutex_t AssertionMutex = PTHREAD_MUTEX_INITIALIZER;

#define CHECK(condition) do { \
	pthread_mutex_lock(&AssertionMutex); Assertions++; pthread_mutex_unlock(&AssertionMutex); \
	if (!(condition)) { fprintf(stderr, "%s:%i: %s (errno=%i)\n", __FILE__, __LINE__, #condition, errno); exit(1); } \
} while (0)

void thread_mutex_lock(int mutex) { (void)mutex; pthread_mutex_lock(&ForkMutex); }
void thread_mutex_unlock(int mutex) { (void)mutex; pthread_mutex_unlock(&ForkMutex); }
int spine_log(const char *format, ...) { (void)format; return 0; }

pid_t nft_test_waitpid(pid_t pid, int *status, int options) {
	CHECK(pid > 0); /* Never reap another subsystem's children. */
	CHECK(options == WNOHANG);
	if (WaitFault == 3) return 0;
	if (WaitFault) {
		errno = WaitFault == 1 ? EINTR : EINVAL;
		WaitFault = 0;
		return -1;
	}
	return waitpid(pid, status, options);
}

int nft_test_clock_gettime(clockid_t clock, struct timespec *time) {
	if (ClockFault) { errno = EINVAL; return -1; }
	return clock_gettime(clock, time);
}

static double now(void) {
	struct timespec time;
	CHECK(clock_gettime(CLOCK_MONOTONIC, &time) == 0);
	return time.tv_sec + time.tv_nsec / 1000000000.0;
}

static int descriptors(void) {
	int fd, count = 0;
	for (fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) != -1) count++;
	return count;
}

static int command(const char *text, pid_t *pid) {
	fd_set fds;
	struct timeval timeout = {2, 0};
	char output[32];
	int fd = nft_popen(text, "r");
	CHECK(fd >= 0);
	*pid = nft_pchild(fd);
	CHECK(*pid > 0);
	CHECK(fcntl(fd, F_GETFD) & FD_CLOEXEC);
	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	CHECK(select(fd + 1, &fds, NULL, NULL, &timeout) == 1);
	CHECK(read(fd, output, sizeof(output)) == 3);
	CHECK(memcmp(output, "42\n", 3) == 0);
	return fd;
}

static void reaped(pid_t pid) {
	int status;
	errno = 0;
	CHECK(waitpid(pid, &status, WNOHANG) == -1 && errno == ECHILD);
}

static void normal_and_delayed(void) {
	int i, fd, before = descriptors();
	pid_t pid;
	double started = now(), closing = 0;
	for (i = 0; i < 100; i++) {
		fd = command("printf '42\\n'; exec sleep 0.05", &pid);
		double close_started = now();
		CHECK(nft_pclose(fd) >= 0);
		closing += now() - close_started;
		CHECK(fcntl(fd, F_GETFD) == -1 && errno == EBADF);
	}
	CHECK(closing < 1.0); /* Old retry loop takes about 2.5s here. */
	CHECK(nft_popen_cleanup() == 0);
	CHECK(descriptors() == before);
	reaped(pid);
	printf("ok delayed cleanup: close_total=%.3fs elapsed=%.3fs\n", closing, now() - started);
	Cases++;
}

static void faults_and_ownership(void) {
	int fault, fd, status;
	pid_t pid, foreign = fork();
	CHECK(foreign >= 0);
	if (!foreign) _exit(42);
	for (fault = 1; fault <= 2; fault++) {
		fd = command("printf '42\\n'; exec sleep 5", &pid);
		WaitFault = fault;
		CHECK(nft_pclose(fd) == 0);
		CHECK(nft_popen_cleanup() == 0);
		reaped(pid);
	}
	fd = command("printf '42\\n'; exec sleep 5", &pid);
	ClockFault = 1;
	CHECK(nft_pclose(fd) == 0);
	CHECK(nft_popen_cleanup() == 0);
	ClockFault = 0;
	reaped(pid);
	CHECK(waitpid(foreign, &status, 0) == foreign);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 42);
	CHECK(nft_pclose(-1) == -1 && errno == EBADF);
	CHECK(nft_pchild(-1) == -1 && errno == EBADF);
	printf("ok interrupted/error reap, failed clock, foreign PID ownership, invalid fd\n");
	Cases++;
}

static void saturation(void) {
	pid_t pids[512];
	int i, fd, count = 0, before = descriptors();
	WaitFault = 3;
	while (count < 512) {
		fd = nft_popen("exec sleep 5", "r");
		if (fd < 0) { CHECK(errno == EAGAIN); break; }
		pids[count++] = nft_pchild(fd);
		CHECK(nft_pclose(fd) == 0);
	}
	CHECK(count > 0 && count < 512);
	CHECK(nft_popen_cleanup() == -1); /* Bounded even when reaping cannot progress. */
	WaitFault = 0;
	CHECK(nft_popen_cleanup() == 0);
	for (i = 0; i < count; i++) reaped(pids[i]);
	CHECK(descriptors() == before);
	printf("ok saturation: %i retained children, bounded failed drain and recovery\n", count);
	Cases++;
}

static pid_t CancelPid;
static void *cancelled(void *unused) {
	(void)unused;
	int fd = command("printf '42\\n'; exec sleep 5", &CancelPid);
	pthread_cancel(pthread_self());
	nft_pclose(fd);
	pthread_testcancel();
	return NULL;
}

static void cancellation(void) {
	pthread_t thread;
	void *result;
	int before = descriptors();
	CHECK(pthread_create(&thread, NULL, cancelled, NULL) == 0);
	CHECK(pthread_join(thread, &result) == 0);
	CHECK(result == PTHREAD_CANCELED);
	CHECK(nft_popen_cleanup() == 0);
	reaped(CancelPid);
	CHECK(descriptors() == before);
	printf("ok cancellation transfers pipe/PID ownership\n");
	Cases++;
}

static void *parallel_commands(void *unused) {
	int i, fd;
	pid_t pid;
	(void)unused;
	for (i = 0; i < 50; i++) {
		fd = command("printf '42\\n'", &pid);
		CHECK(nft_pclose(fd) >= 0);
	}
	return NULL;
}

static void concurrency(void) {
	pthread_t threads[16];
	int i, before = descriptors();
	for (i = 0; i < 16; i++) CHECK(pthread_create(&threads[i], NULL, parallel_commands, NULL) == 0);
	for (i = 0; i < 16; i++) CHECK(pthread_join(threads[i], NULL) == 0);
	CHECK(nft_popen_cleanup() == 0);
	CHECK(descriptors() == before);
	printf("ok 800 commands across 16 threads, no descriptor growth\n");
	Cases++;
}

static void already_reaped(void) {
	int status;
	pid_t pid;
	int fd = command("printf '42\\n'; exit 7", &pid);
	CHECK(waitpid(pid, &status, 0) == pid);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	CHECK(nft_pclose(fd) == 0);
	CHECK(nft_popen_cleanup() == 0);
	printf("ok ECHILD removes ownership without signalling a reused PID\n");
	Cases++;
}

static void available_status(void) {
	pid_t pid;
	siginfo_t info;
	int fd = command("printf '42\\n'; exit 7", &pid);
	CHECK(waitid(P_PID, pid, &info, WEXITED | WNOWAIT) == 0);
	int status = nft_pclose(fd);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);
	reaped(pid);
	printf("ok immediately available exit status is preserved\n");
	Cases++;
}

int main(void) {
	alarm(30);
	normal_and_delayed();
	faults_and_ownership();
	saturation();
	cancellation();
	concurrency();
	already_reaped();
	available_status();
	CHECK(nft_popen_cleanup() == 0);
	printf("PASS: %i cases, %i assertions\n", Cases, Assertions);
	return 0;
}
