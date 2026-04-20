#include "platform_error.h"

#ifndef _WIN32

#include <stdio.h>
#include <string.h>

const char *spine_platform_error_string(int error_code, char *buffer, size_t buffer_size) {
	if (buffer == NULL || buffer_size == 0) {
		return "invalid error buffer";
	}

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
	return strerror_r(error_code, buffer, buffer_size);
#else
	if (strerror_r(error_code, buffer, buffer_size) != 0) {
		snprintf(buffer, buffer_size, "error %d", error_code);
	}

	return buffer;
#endif
}

#endif
