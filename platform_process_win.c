#include "platform_process.h"

#ifdef _WIN32

#include <fcntl.h>
#include <io.h>
#include <errno.h>
#include <stdlib.h>
#include <process.h>
#include <windows.h>

#include "platform.h"

int spine_process_pipe(int pipe_fds[2]) {
	return _pipe(pipe_fds, 4096, _O_BINARY);
}

int spine_process_close_fd(int fd) {
	return _close(fd);
}

int spine_process_wait(spine_pid_t pid, int *status) {
	HANDLE process_handle;
	DWORD wait_result;
	DWORD exit_code;

	process_handle = (HANDLE) pid;
	if (process_handle == NULL || process_handle == INVALID_HANDLE_VALUE) {
		errno = ESRCH;
		return -1;
	}

	wait_result = WaitForSingleObject(process_handle, INFINITE);
	if (wait_result != WAIT_OBJECT_0) {
		CloseHandle(process_handle);
		errno = ECHILD;
		return -1;
	}

	if (status != NULL) {
		if (GetExitCodeProcess(process_handle, &exit_code) == 0) {
			CloseHandle(process_handle);
			errno = ECHILD;
			return -1;
		}

		*status = (int) exit_code;
	}

	CloseHandle(process_handle);
	return 0;
}

int spine_process_terminate(spine_pid_t pid) {
	HANDLE process_handle;
	BOOL terminate_result;

	process_handle = (HANDLE) pid;
	if (process_handle == NULL || process_handle == INVALID_HANDLE_VALUE) {
		errno = ESRCH;
		return -1;
	}

	terminate_result = TerminateProcess(process_handle, 1);

	if (terminate_result == 0) {
		errno = ESRCH;
		return -1;
	}

	return 0;
}

int spine_process_spawn_retry(
	spine_pid_t *pid,
	const char *path,
	void *file_actions,
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
) {
	intptr_t spawn_result;
	int retry_count;
	int spawn_error;
	char *const *spawn_envp;

	(void) file_actions;

	retry_count = 0;
	spawn_envp = envp == NULL ? _environ : envp;

	do {
		spawn_result = _spawnve(_P_NOWAIT, path, (const char * const *) argv, (const char * const *) spawn_envp);
		if (spawn_result != -1) {
			*pid = (spine_pid_t) spawn_result;
			return 0;
		}

		spawn_error = errno;
		if ((spawn_error == EAGAIN || spawn_error == ENOMEM) && retry_count < retry_limit) {
			retry_count++;
			spine_platform_sleep_us(retry_sleep_us);
			continue;
		}

		return spawn_error;
	} while (1);
}

#endif
