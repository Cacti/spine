#include "platform_win_error.h"

#ifdef _WIN32

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

int spine_win32_error_to_errno(DWORD error_code) {
	switch (error_code) {
	case ERROR_NOT_ENOUGH_MEMORY:
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_FILE_NOT_FOUND:
	case ERROR_PATH_NOT_FOUND:
	case ERROR_MOD_NOT_FOUND:
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
	case ERROR_LOCK_VIOLATION:
		return EAGAIN;
	case ERROR_BROKEN_PIPE:
	case ERROR_HANDLE_EOF:
		return EPIPE;
	default:
		return EINVAL;
	}
}

int spine_wsa_error_to_errno(int error_code) {
	switch (error_code) {
	case WSAEINTR:
		return EINTR;
	case WSAEWOULDBLOCK:
	case WSAEALREADY:
	case WSAEINPROGRESS:
		return EAGAIN;
	case WSAEINVAL:
		return EINVAL;
	case WSAENOTSOCK:
	case WSAEBADF:
		return EBADF;
	case WSAEACCES:
		return EACCES;
	case WSAEMFILE:
		return EMFILE;
	case WSAECONNRESET:
		return ECONNRESET;
	case WSAECONNREFUSED:
		return ECONNREFUSED;
	case WSAEHOSTUNREACH:
	case WSAENETUNREACH:
		return EHOSTUNREACH;
	case WSAETIMEDOUT:
		return ETIMEDOUT;
	case WSAENOBUFS:
	case WSA_NOT_ENOUGH_MEMORY:
		return ENOMEM;
	default:
		return EINVAL;
	}
}

const char *spine_win32_error_string(DWORD error_code, char *buffer, size_t buffer_size) {
	DWORD flags;
	DWORD result;
	wchar_t wide_buffer[512];
	int utf8_size;

	if (buffer == NULL || buffer_size == 0) {
		return "invalid error buffer";
	}

	flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	result = FormatMessageW(flags, NULL, error_code, 0, wide_buffer,
		(DWORD) (sizeof(wide_buffer) / sizeof(wide_buffer[0])), NULL);
	if (result == 0) {
		snprintf(buffer, buffer_size, "error %lu", (unsigned long) error_code);
		return buffer;
	}

	while (result > 0 && (wide_buffer[result - 1] == L'\r' || wide_buffer[result - 1] == L'\n')) {
		wide_buffer[result - 1] = L'\0';
		result--;
	}

	utf8_size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide_buffer, -1, buffer, (int) buffer_size, NULL, NULL);
	if (utf8_size <= 0) {
		snprintf(buffer, buffer_size, "error %lu", (unsigned long) error_code);
	}

	return buffer;
}

#endif
