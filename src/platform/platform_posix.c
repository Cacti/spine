/* pthread_setname_np (glibc) and other GNU extensions are gated by
 * _GNU_SOURCE. CMake injects this via spine_posix_features / spine_platform
 * PUBLIC defines for every Linux TU. The explicit define here guards against
 * header-include order hazards: glibc's <features.h> freezes the feature
 * bitmap on first inclusion, so the macro must be visible before any system
 * header reaches it -- including those pulled in transitively by platform.h. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "platform.h"

#ifndef _WIN32

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <pthread_np.h>
#endif

/* usleep was removed from POSIX.1-2008; under strict _POSIX_C_SOURCE the
 * declaration is hidden on FreeBSD and others. nanosleep is the portable
 * POSIX-standard replacement and has always been in the issue-6 specification. */
static void spine_nanosleep_us(unsigned long microseconds) {
	struct timespec req;
	req.tv_sec  = (time_t)(microseconds / 1000000UL);
	req.tv_nsec = (long)((microseconds % 1000000UL) * 1000UL);
	while (nanosleep(&req, &req) == -1 && (req.tv_sec > 0 || req.tv_nsec > 0)) {
		/* Resume after EINTR with remaining time. */
	}
}

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
	spine_nanosleep_us((unsigned long)milliseconds * 1000UL);
}

void spine_platform_sleep_us(unsigned int microseconds) {
	spine_nanosleep_us((unsigned long)microseconds);
}

void spine_platform_sleep_s(unsigned int seconds) {
	struct timespec req;
	req.tv_sec = (time_t)seconds;
	req.tv_nsec = 0;
	while (nanosleep(&req, &req) == -1 && (req.tv_sec > 0 || req.tv_nsec > 0)) {
		/* Resume after EINTR. */
	}
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
	/* Linux caps pthread_setname_np at 15 bytes + NUL; anything longer
	 * returns ERANGE and leaves the thread name unchanged. Truncate so
	 * long identifiers still produce a visible prefix in top / ps. */
	char truncated[16];
	size_t n = strlen(name);
	if (n >= sizeof(truncated)) {
		memcpy(truncated, name, sizeof(truncated) - 1);
		truncated[sizeof(truncated) - 1] = '\0';
		(void) pthread_setname_np(pthread_self(), truncated);
	} else {
		(void) pthread_setname_np(pthread_self(), name);
	}
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
