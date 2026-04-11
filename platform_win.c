#include "platform.h"

#ifdef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winsock2.h>
#include <process.h>
#include <io.h>

int spine_platform_init_once(void) {
	WSADATA wsa_data;

	return WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0 ? 0 : -1;
}

void spine_platform_cleanup_once(void) {
	WSACleanup();
}

int spine_platform_setenv(const char *name, const char *value, int overwrite) {
	if (!overwrite && getenv(name) != NULL) {
		return 0;
	}

	return _putenv_s(name, value);
}

int spine_platform_localtime(const time_t *when, struct tm *out) {
	return localtime_s(out, when);
}

void spine_platform_sleep_ms(unsigned int milliseconds) {
	Sleep(milliseconds);
}

void spine_platform_sleep_us(unsigned int microseconds) {
	unsigned int rounded_ms;

	rounded_ms = microseconds / 1000U;
	if (rounded_ms == 0 && microseconds > 0) {
		rounded_ms = 1;
	}

	Sleep(rounded_ms);
}

void spine_platform_sleep_s(unsigned int seconds) {
	Sleep(seconds * 1000U);
}

unsigned long spine_platform_process_id(void) {
	return (unsigned long) _getpid();
}

int spine_platform_stdout_is_terminal(void) {
	return _isatty(_fileno(stdout));
}

int spine_platform_stderr_is_terminal(void) {
	return _isatty(_fileno(stderr));
}

#endif
