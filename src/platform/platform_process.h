#ifndef SPINE_PLATFORM_PROCESS_H
#define SPINE_PLATFORM_PROCESS_H

#include <sys/types.h>
#include <stdint.h>

#ifndef _WIN32
#include <spawn.h>
typedef pid_t spine_pid_t;
#else
typedef intptr_t spine_pid_t;
_Static_assert(sizeof(spine_pid_t) >= sizeof(void *), "spine_pid_t must hold Windows HANDLE values");
#endif

int spine_process_pipe(int pipe_fds[2]);
int spine_process_close_fd(int fd);
int spine_process_wait(spine_pid_t pid, int *status);
int spine_process_terminate(spine_pid_t pid);
int spine_process_spawn_retry(
	spine_pid_t *pid,
	const char *path,
#ifndef _WIN32
	posix_spawn_file_actions_t *file_actions,
	posix_spawnattr_t *spawn_attr,
#else
	void *file_actions,
	void *spawn_attr,
#endif
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
);

#endif
