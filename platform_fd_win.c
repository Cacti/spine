#include "platform_fd.h"

#ifdef _WIN32

#include <errno.h>
#include <io.h>
#include <windows.h>

#include "platform.h"

ssize_t spine_fd_read(int fd, void *buffer, size_t buffer_len) {
	return _read(fd, buffer, (unsigned int) buffer_len);
}

ssize_t spine_fd_write(int fd, const void *buffer, size_t buffer_len) {
	return _write(fd, buffer, (unsigned int) buffer_len);
}

int spine_fd_wait_readable(int fd, struct timeval *timeout) {
	HANDLE handle;
	ULONGLONG timeout_ms;
	ULONGLONG waited_ms;

	handle = (HANDLE) _get_osfhandle(fd);
	if (handle == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	timeout_ms = (ULONGLONG) timeout->tv_sec * 1000ULL + (ULONGLONG) timeout->tv_usec / 1000ULL;
	waited_ms = 0;

	for (;;) {
		DWORD available_bytes = 0;
		BOOL peek_result;

		peek_result = PeekNamedPipe(handle, NULL, 0, NULL, &available_bytes, NULL);
		if (peek_result != 0) {
			if (available_bytes > 0) {
				return 1;
			}
		} else {
			DWORD last_error = GetLastError();

			if (last_error == ERROR_BROKEN_PIPE || last_error == ERROR_HANDLE_EOF) {
				return 1;
			}

			errno = EINVAL;
			return -1;
		}

		if (waited_ms >= timeout_ms) {
			return 0;
		}

		Sleep(1);
		waited_ms++;
	}
}

int spine_fd_last_error(void) {
	return errno;
}

int spine_fd_error_is_interrupted(int error_code) {
	return error_code == EINTR;
}

int spine_fd_error_is_badf(int error_code) {
	return error_code == EBADF;
}

int spine_fd_error_is_invalid(int error_code) {
	return error_code == EINVAL;
}

int spine_fd_error_is_nomem(int error_code) {
	return error_code == ENOMEM;
}

#endif
