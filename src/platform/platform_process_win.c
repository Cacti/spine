#include "platform_process.h"

#ifdef _WIN32

#include <fcntl.h>
#include <io.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

#include "platform.h"

static wchar_t *spine_windows_utf8_to_wide(const char *input) {
	int required_chars;
	wchar_t *output;

	if (input == NULL) {
		return NULL;
	}

	/* Strict UTF-8 only: a CP_ACP fallback would silently mojibake the active
	 * code page into UTF-16 and pass it to CreateProcessW, which is unsafe for
	 * argv carrying paths or shell metacharacters. Callers must supply UTF-8. */
	required_chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, NULL, 0);
	if (required_chars <= 0) {
		errno = EILSEQ;
		return NULL;
	}

	output = (wchar_t *) malloc((size_t) required_chars * sizeof(wchar_t));
	if (output == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1, output, required_chars) <= 0) {
		free(output);
		errno = EILSEQ;
		return NULL;
	}

	return output;
}

/* The sizer and emitter below MUST stay byte-for-byte equivalent. They follow
 * the Microsoft CommandLineToArgvW reverse rules: inside double quotes a literal
 * `"` requires a preceding `\`, and any run of backslashes immediately before a
 * `"` (including the closing one) must be doubled. Verified by hand for:
 *   "a\"b"  -> "a\\\"b"   (bs+quote pair)
 *   "a "    -> "a "       (no quote needed -> trailing chars unchanged)
 *   "a \\"  -> "a \\\\"   (trailing backslash inside quotes -> doubled)
 *   "\\\""  -> "\\\\\\\"" (3-bs-quote canonical form)
 * Edits to one function MUST be mirrored in the other, or CreateProcessW will
 * receive an argv that no longer round-trips through CommandLineToArgvW. */
static size_t spine_windows_quoted_arg_length(const wchar_t *arg) {
	size_t extra;
	size_t backslash_count;
	const wchar_t *cursor;
	int needs_quotes;

	needs_quotes = (*arg == L'\0' || wcspbrk(arg, L" \t\n\v\"") != NULL);
	extra = needs_quotes ? 2 : 0;
	backslash_count = 0;
	for (cursor = arg; *cursor != '\0'; cursor++) {
		if (*cursor == L'\\') {
			backslash_count++;
			extra++;
			continue;
		}

		if (*cursor == L'"') {
			extra += backslash_count + 1;
			backslash_count = 0;
		} else {
			backslash_count = 0;
		}

		extra++;
	}
	if (needs_quotes) {
		extra += backslash_count;
	}

	return extra;
}

static wchar_t *spine_windows_build_command_line(char *const argv[]) {
	size_t total_len;
	size_t arg_count;
	size_t arg_index;
	wchar_t *command_line;
	wchar_t *output;
	const wchar_t *input;
	wchar_t *wide_arg;

	total_len = 1; /* trailing NUL */
	arg_count = 0;
	while (argv[arg_count] != NULL) {
		wide_arg = spine_windows_utf8_to_wide(argv[arg_count]);
		if (wide_arg == NULL) {
			return NULL;
		}
		total_len += spine_windows_quoted_arg_length(wide_arg) + 1;
		free(wide_arg);
		arg_count++;
	}

	command_line = (wchar_t *) malloc(total_len * sizeof(wchar_t));
	if (command_line == NULL) {
		return NULL;
	}

	output = command_line;
	for (arg_index = 0; arg_index < arg_count; arg_index++) {
		size_t backslash_count;
		int needs_quotes;

		if (arg_index > 0) {
			*output++ = L' ';
		}

		wide_arg = spine_windows_utf8_to_wide(argv[arg_index]);
		if (wide_arg == NULL) {
			free(command_line);
			return NULL;
		}

		needs_quotes = (*wide_arg == L'\0' || wcspbrk(wide_arg, L" \t\n\v\"") != NULL);
		if (needs_quotes) {
			*output++ = L'"';
		}
		backslash_count = 0;
		for (input = wide_arg; *input != L'\0'; input++) {
			if (*input == L'\\') {
				backslash_count++;
				*output++ = L'\\';
				continue;
			}

			if (*input == L'"') {
				while (backslash_count-- > 0) {
					*output++ = L'\\';
				}
				backslash_count = 0;
				*output++ = L'\\';
			} else {
				backslash_count = 0;
			}

			*output++ = *input;
		}
		if (needs_quotes) {
			while (backslash_count-- > 0) {
				*output++ = L'\\';
			}
			*output++ = L'"';
		}
		free(wide_arg);
	}
	*output = L'\0';

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
		return -1;
	}

	return 0;
}

int spine_process_spawn_retry(
	spine_pid_t *pid,
	const char *path,
	void *file_actions,
	void *spawn_attr,
	char *const argv[],
	char *const envp[],
	int retry_limit,
	unsigned int retry_sleep_us
) {
	STARTUPINFOW startup_info;
	PROCESS_INFORMATION process_info;
	wchar_t *command_line_template;
	wchar_t *command_line;
	wchar_t *wide_path;
	BOOL create_result;
	int retry_count;
	int spawn_error;
	DWORD last_error;
	DWORD creation_flags;

	(void) file_actions;
	(void) spawn_attr;

	retry_count = 0;
	creation_flags = CREATE_NO_WINDOW;
	if (envp != NULL) {
		errno = ENOTSUP;
		return ENOTSUP;
	}
	wide_path = spine_windows_utf8_to_wide(path);
	command_line_template = spine_windows_build_command_line(argv);
	if (wide_path == NULL || command_line_template == NULL) {
		free(wide_path);
		free(command_line_template);
		return ENOMEM;
	}

	memset(&startup_info, 0, sizeof(startup_info));
	startup_info.cb = sizeof(startup_info);
	memset(&process_info, 0, sizeof(process_info));

	do {
		command_line = _wcsdup(command_line_template);
		if (command_line == NULL) {
			free(wide_path);
			free(command_line_template);
			return ENOMEM;
		}

		create_result = CreateProcessW(
			wide_path,
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
			free(wide_path);
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

		free(wide_path);
		free(command_line_template);
		errno = spawn_error;
		return spawn_error;
	} while (1);
}

#endif
