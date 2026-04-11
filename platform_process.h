#ifndef SPINE_PLATFORM_PROCESS_H
#define SPINE_PLATFORM_PROCESS_H

#include <sys/types.h>

#ifndef _WIN32
#include <spawn.h>
#endif

int spine_process_pipe(int pipe_fds[2]);
int spine_process_close_fd(int fd);
int spine_process_wait(pid_t pid, int *status);
int spine_process_terminate(pid_t pid);
int spine_process_spawn_retry(
	pid_t *pid,
	const char *path,
#ifndef _WIN32
	posix_spawn_file_actions_t *file_actions,
#else
	void *file_actions,
#endif
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
);

#endif
