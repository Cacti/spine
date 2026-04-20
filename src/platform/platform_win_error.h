#ifndef SPINE_PLATFORM_WIN_ERROR_H
#define SPINE_PLATFORM_WIN_ERROR_H

#ifdef _WIN32

#include <stddef.h>
#include <windows.h>

int spine_win32_error_to_errno(DWORD error_code);
int spine_wsa_error_to_errno(int error_code);
const char *spine_win32_error_string(DWORD error_code, char *buffer, size_t buffer_size);

#endif

#endif
