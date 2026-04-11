#include "platform_process.h"

#ifdef _WIN32

#include <errno.h>

int spine_process_pipe(int pipe_fds[2]) {
	(void) pipe_fds;
	errno = ENOSYS;
	return -1;
}

int spine_process_close_fd(int fd) {
	(void) fd;
	errno = ENOSYS;
	return -1;
}

int spine_process_wait(pid_t pid, int *status) {
	(void) pid;
	(void) status;
	errno = ENOSYS;
	return -1;
}

int spine_process_terminate(pid_t pid) {
	(void) pid;
	errno = ENOSYS;
	return -1;
}

int spine_process_spawn_retry(
	pid_t *pid,
	const char *path,
	void *file_actions,
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
) {
	(void) pid;
	(void) path;
	(void) file_actions;
	(void) argv;
	(void) envp;
	(void) retry_limit;
	(void) retry_sleep_us;
	errno = ENOSYS;
	return ENOSYS;
}

#endif
