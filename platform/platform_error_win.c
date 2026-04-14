#include "platform_error.h"

#ifdef _WIN32

#include <stdio.h>
#include <string.h>
#include <windows.h>

const char *spine_platform_error_string(int error_code, char *buffer, size_t buffer_size) {
	DWORD flags;
	DWORD result;

	if (buffer == NULL || buffer_size == 0) {
		return "invalid error buffer";
	}

	flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
	result = FormatMessageA(flags, NULL, (DWORD) error_code, 0, buffer, (DWORD) buffer_size, NULL);

	if (result == 0) {
		snprintf(buffer, buffer_size, "error %d", error_code);
		return buffer;
	}

	while (result > 0 && (buffer[result - 1] == '\r' || buffer[result - 1] == '\n')) {
		buffer[result - 1] = '\0';
		result--;
	}

	return buffer;
}

#endif
