#include "platform_error.h"

#ifdef _WIN32

#include "platform_win_error.h"

const char *spine_platform_error_string(int error_code, char *buffer, size_t buffer_size) {
	return spine_win32_error_string((DWORD) error_code, buffer, buffer_size);
}

#endif
