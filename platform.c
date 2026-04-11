#include "platform.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#endif

static int spine_platform_initialized = 0;

int spine_platform_init(void) {
#ifdef _WIN32
	WSADATA wsa_data;

	if (spine_platform_initialized == 0) {
		if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
			return -1;
		}
	}
#endif

	spine_platform_initialized++;

	return 0;
}

void spine_platform_cleanup(void) {
	if (spine_platform_initialized <= 0) {
		return;
	}

	spine_platform_initialized--;

#ifdef _WIN32
	if (spine_platform_initialized == 0) {
		WSACleanup();
	}
#endif
}

int spine_platform_setenv(const char *name, const char *value, int overwrite) {
#ifdef _WIN32
	if (!overwrite && getenv(name) != NULL) {
		return 0;
	}

	return _putenv_s(name, value);
#else
	return setenv(name, value, overwrite);
#endif
}

int spine_platform_localtime(const time_t *when, struct tm *out) {
#ifdef _WIN32
	return localtime_s(out, when);
#else
	return localtime_r(when, out) == NULL ? -1 : 0;
#endif
}

void spine_platform_sleep_ms(unsigned int milliseconds) {
#ifdef _WIN32
	Sleep(milliseconds);
#else
	usleep(milliseconds * 1000U);
#endif
}

void spine_platform_sleep_us(unsigned int microseconds) {
#ifdef _WIN32
	unsigned int rounded_ms;

	rounded_ms = microseconds / 1000U;
	if (rounded_ms == 0 && microseconds > 0) {
		rounded_ms = 1;
	}

	Sleep(rounded_ms);
#else
	usleep(microseconds);
#endif
}

void spine_platform_sleep_s(unsigned int seconds) {
#ifdef _WIN32
	Sleep(seconds * 1000U);
#else
	sleep(seconds);
#endif
}

unsigned long spine_platform_process_id(void) {
#ifdef _WIN32
	return (unsigned long) _getpid();
#else
	return (unsigned long) getpid();
#endif
}

int spine_platform_stdout_is_terminal(void) {
#ifdef _WIN32
	return _isatty(_fileno(stdout));
#else
	return isatty(fileno(stdout));
#endif
}

int spine_platform_stderr_is_terminal(void) {
#ifdef _WIN32
	return _isatty(_fileno(stderr));
#else
	return isatty(fileno(stderr));
#endif
}
