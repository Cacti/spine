#include "platform_process.h"

#ifndef _WIN32

#include <errno.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include "platform.h"

extern char **environ;

int spine_process_pipe(int pipe_fds[2]) {
	return pipe(pipe_fds);
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

		spawn_err = posix_spawn(&spawned_pid, path, file_actions, NULL, argv, spawn_envp);
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
