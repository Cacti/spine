#include "platform_process.h"

#ifdef _WIN32

#include <fcntl.h>
#include <io.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <windows.h>

#include "platform.h"

static size_t spine_windows_quoted_arg_length(const char *arg) {
	size_t extra;
	const char *cursor;

	extra = 2; /* opening and closing quotes */
	for (cursor = arg; *cursor != '\0'; cursor++) {
		if (*cursor == '"' || *cursor == '\\') {
			extra++;
		}
		extra++;
	}

	return extra;
}

static char *spine_windows_build_command_line(char *const argv[]) {
	size_t total_len;
	size_t arg_count;
	size_t arg_index;
	char *command_line;
	char *output;
	const char *input;

	total_len = 1; /* trailing NUL */
	arg_count = 0;
	while (argv[arg_count] != NULL) {
		total_len += spine_windows_quoted_arg_length(argv[arg_count]) + 1;
		arg_count++;
	}

	command_line = (char *) malloc(total_len);
	if (command_line == NULL) {
		return NULL;
	}

	output = command_line;
	for (arg_index = 0; arg_index < arg_count; arg_index++) {
		if (arg_index > 0) {
			*output++ = ' ';
		}

		*output++ = '"';
		for (input = argv[arg_index]; *input != '\0'; input++) {
			if (*input == '"' || *input == '\\') {
				*output++ = '\\';
			}
			*output++ = *input;
		}
		*output++ = '"';
	}
	*output = '\0';

	return command_line;
}

static int spine_windows_map_error_to_errno(DWORD error_code) {
	switch (error_code) {
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_ACCESS_DENIED:
	case ERROR_INVALID_ACCESS:
		return EACCES;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_INVALID_PARAMETER:
		return EINVAL;
	case ERROR_TOO_MANY_OPEN_FILES:
		return EMFILE;
	case ERROR_RETRY:
	case ERROR_NOT_READY:
	case ERROR_BUSY:
		return EAGAIN;
	default:
		return EINVAL;
	}
}

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
	DWORD last_error;

	process_handle = (HANDLE) pid;
	if (process_handle == NULL || process_handle == INVALID_HANDLE_VALUE) {
		errno = ESRCH;
		return -1;
	}

	wait_result = WaitForSingleObject(process_handle, INFINITE);
	if (wait_result != WAIT_OBJECT_0) {
		last_error = GetLastError();
		CloseHandle(process_handle);
		if (last_error != 0) {
			errno = spine_windows_map_error_to_errno(last_error);
		} else {
			errno = ECHILD;
		}
		return -1;
	}

	if (status != NULL) {
		if (GetExitCodeProcess(process_handle, &exit_code) == 0) {
			last_error = GetLastError();
			CloseHandle(process_handle);
			if (last_error != 0) {
				errno = spine_windows_map_error_to_errno(last_error);
			} else {
				errno = ECHILD;
			}
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
	DWORD last_error;

	process_handle = (HANDLE) pid;
	if (process_handle == NULL || process_handle == INVALID_HANDLE_VALUE) {
		errno = ESRCH;
		return -1;
	}

	terminate_result = TerminateProcess(process_handle, 1);

	if (terminate_result == 0) {
		last_error = GetLastError();
		if (last_error != 0) {
			errno = spine_windows_map_error_to_errno(last_error);
		} else {
			errno = ESRCH;
		}
		CloseHandle(process_handle);
		return -1;
	}

	CloseHandle(process_handle);
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
	STARTUPINFOA startup_info;
	PROCESS_INFORMATION process_info;
	char *command_line_template;
	char *command_line;
	BOOL create_result;
	int retry_count;
	int spawn_error;
	DWORD last_error;
	DWORD creation_flags;

	(void) file_actions;
	(void) envp;

	retry_count = 0;
	creation_flags = CREATE_NO_WINDOW;
	command_line_template = spine_windows_build_command_line(argv);
	if (command_line_template == NULL) {
		return ENOMEM;
	}

	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	memset(&process_info, 0, sizeof(process_info));

	do {
		command_line = _strdup(command_line_template);
		if (command_line == NULL) {
			free(command_line_template);
			return ENOMEM;
		}

		create_result = CreateProcessA(
			path,
			command_line,
			NULL,
			NULL,
			FALSE,
			creation_flags,
			NULL,
			NULL,
			&startup_info,
			&process_info
		);
		free(command_line);
		if (create_result != 0) {
			CloseHandle(process_info.hThread);
			*pid = (spine_pid_t) process_info.hProcess;
			free(command_line_template);
			return 0;
		}

		last_error = GetLastError();
		spawn_error = last_error != 0 ? spine_windows_map_error_to_errno(last_error) : EINVAL;
		if ((spawn_error == EAGAIN || spawn_error == ENOMEM) && retry_count < retry_limit) {
			retry_count++;
			spine_platform_sleep_us(retry_sleep_us);
			continue;
		}

		free(command_line_template);
		errno = spawn_error;
		return spawn_error;
	} while (1);
}

#endif
