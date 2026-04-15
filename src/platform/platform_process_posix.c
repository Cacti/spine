/* pipe2(2) is a Linux/BSD extension. On glibc it is gated by _GNU_SOURCE;
 * CMake injects the macro through spine_posix_features for every Linux
 * target (both spine_platform and the test binaries) so this TU inherits
 * it without a per-file #define. */

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
	/* OpenBSD declares pipe2 only when __BSD_VISIBLE is set, which the
	 * project's strict _POSIX_C_SOURCE compilation hides. Fall through
	 * there to the portable pipe + fcntl(FD_CLOEXEC) path. */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
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
