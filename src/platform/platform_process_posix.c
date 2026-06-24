/* pipe2(2) is a Linux/BSD extension. On glibc it is only declared when
 * _GNU_SOURCE is visible before any libc header is included (features.h
 * latches the exposed symbol set on first inclusion). The project otherwise
 * builds with _POSIX_C_SOURCE=200809L which would hide it. Define the macro
 * before pulling in platform_process.h, which transitively includes
 * <sys/types.h>. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
/* On the BSDs pipe2() is gated behind __BSD_VISIBLE, which _POSIX_C_SOURCE
 * turns off. Force it on before any system header latches the symbol set. */
#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)) && !defined(__BSD_VISIBLE)
#define __BSD_VISIBLE 1
#endif

#include "platform_process.h"

#ifndef _WIN32

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "platform.h"

extern char **environ;

int spine_process_pipe(int pipe_fds[2]) {
	/* CLOEXEC on both ends keeps the pipe from leaking into unrelated
	 * concurrent spawns. posix_spawn_file_actions_adddup2 clears CLOEXEC
	 * on the duped fds, so the intended child still inherits stdin/stdout. */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	return pipe2(pipe_fds, O_CLOEXEC);
#else
	int rc = pipe(pipe_fds);
	if (rc == 0) {
		if (fcntl(pipe_fds[0], F_SETFD, FD_CLOEXEC) == -1 ||
			fcntl(pipe_fds[1], F_SETFD, FD_CLOEXEC) == -1) {
			int saved_errno = errno;
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			errno = saved_errno;
			return -1;
		}
	}
	return rc;
#endif
}

int spine_process_close_fd(int fd) {
	return close(fd);
}

int spine_process_wait(spine_pid_t pid, int *status) {
	pid_t wait_result;

	do {
		wait_result = waitpid(pid, status, 0);
	} while (wait_result == -1 && errno == EINTR);

	return wait_result == -1 ? -1 : 0;
}

int spine_process_terminate(spine_pid_t pid) {
	return kill(pid, SIGTERM);
}

int spine_process_spawn_retry(
	spine_pid_t *pid,
	const char *path,
	posix_spawn_file_actions_t *file_actions,
	posix_spawnattr_t *spawn_attr,
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
) {
	int spawn_err;
	int retry_count;
	char *const *spawn_envp;

	retry_count = 0;
	spawn_envp = envp == NULL ? environ : envp;

	do {
		pid_t spawned_pid;

		spawn_err = posix_spawn(&spawned_pid, path, file_actions, spawn_attr, argv, spawn_envp);
		if ((spawn_err == EAGAIN || spawn_err == ENOMEM) && retry_count < retry_limit) {
			retry_count++;
			spine_platform_sleep_us(retry_sleep_us);
			continue;
		}

		if (spawn_err == 0) {
			*pid = spawned_pid;
		}

		break;
	} while (1);

	return spawn_err;
}

#endif
