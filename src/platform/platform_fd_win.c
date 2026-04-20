#include "platform_fd.h"

#ifdef _WIN32

#include <errno.h>
#include <io.h>
#include <limits.h>
#include <windows.h>

#include "platform.h"
#include "platform_win_error.h"

static int spine_windows_size_to_uint(size_t value, unsigned int *out_value) {
	if (out_value == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (value > (size_t) UINT_MAX) {
		errno = EINVAL;
		return -1;
	}

	*out_value = (unsigned int) value;
	return 0;
}

ssize_t spine_fd_read(int fd, void *buffer, size_t buffer_len) {
	unsigned int read_len;

	if (spine_windows_size_to_uint(buffer_len, &read_len) != 0) {
		return -1;
	}

	return _read(fd, buffer, read_len);
}

ssize_t spine_fd_write(int fd, const void *buffer, size_t buffer_len) {
	unsigned int write_len;

	if (spine_windows_size_to_uint(buffer_len, &write_len) != 0) {
		return -1;
	}

	return _write(fd, buffer, write_len);
}

int spine_fd_wait_readable(int fd, struct timeval *timeout) {
	HANDLE handle;
	ULONGLONG timeout_ms_ull;
	DWORD timeout_ms;
	DWORD wait_result;

	if (timeout == NULL || timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000) {
		errno = EINVAL;
		return -1;
	}

	handle = (HANDLE) _get_osfhandle(fd);
	if (handle == INVALID_HANDLE_VALUE) {
		errno = EBADF;
		return -1;
	}

	timeout_ms_ull = (ULONGLONG) timeout->tv_sec * 1000ULL + (ULONGLONG) timeout->tv_usec / 1000ULL;
	if (timeout_ms_ull > (ULONGLONG) MAXDWORD) {
		timeout_ms = INFINITE;
	} else {
		timeout_ms = (DWORD) timeout_ms_ull;
	}

	wait_result = WaitForSingleObject(handle, timeout_ms);
	if (wait_result == WAIT_OBJECT_0) {
		return 1;
	}
	if (wait_result == WAIT_TIMEOUT) {
		return 0;
	}
	if (wait_result == WAIT_FAILED) {
		errno = spine_win32_error_to_errno(GetLastError());
	} else {
		errno = EINVAL;
	}
	return -1;
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
