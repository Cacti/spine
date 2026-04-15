#include "platform.h"

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

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

void spine_platform_set_thread_name(const char *name) {
	if (name == NULL) {
		return;
	}
#if defined(__linux__)
	(void) pthread_setname_np(pthread_self(), name);
#elif defined(__APPLE__)
	/* Darwin's pthread_setname_np sets the calling thread only. */
	(void) pthread_setname_np(name);
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
	pthread_set_name_np(pthread_self(), name);
#elif defined(__NetBSD__)
	(void) pthread_setname_np(pthread_self(), "%s", (void *) name);
#elif defined(__sun) || defined(__sun__)
	(void) pthread_setname_np(pthread_self(), name);
#else
	(void) name;
#endif
}

#endif
