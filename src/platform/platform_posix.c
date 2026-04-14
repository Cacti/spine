#include "platform.h"

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int spine_platform_init_once(void) {
	return 0;
}

void spine_platform_cleanup_once(void) {
}

int spine_platform_setenv(const char *name, const char *value, int overwrite) {
	return setenv(name, value, overwrite);
}

int spine_platform_localtime(const time_t *when, struct tm *out) {
	return localtime_r(when, out) == NULL ? -1 : 0;
}

void spine_platform_sleep_ms(unsigned int milliseconds) {
	usleep(milliseconds * 1000U);
}

void spine_platform_sleep_us(unsigned int microseconds) {
	usleep(microseconds);
}

void spine_platform_sleep_s(unsigned int seconds) {
	sleep(seconds);
}

unsigned long spine_platform_process_id(void) {
	return (unsigned long) getpid();
}

int spine_platform_stdout_is_terminal(void) {
	return isatty(fileno(stdout));
}

int spine_platform_stderr_is_terminal(void) {
	return isatty(fileno(stderr));
}

#endif
