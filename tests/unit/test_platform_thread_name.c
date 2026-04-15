/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Thread-name wrapper: best-effort smoke test. We set a short name and,
 | where the OS also exposes a pthread_get*_name_np(), read it back and
 | compare. Unsupported platforms must simply not crash.
 +-------------------------------------------------------------------------+
*/

/* pthread_getname_np on glibc needs _GNU_SOURCE before <pthread.h>. */
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif

#include <string.h>

#include "platform/platform.h"
#include "test_platform_helpers.h"

#if !defined(_WIN32)
#include <pthread.h>
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
#include <pthread_np.h>
#endif
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#include <pthread_np.h>
#endif

static void test_thread_name_null_is_noop(void) {
	/* NULL must not crash and must not alter the thread name. */
	spine_platform_set_thread_name(NULL);
}

static void test_thread_name_short(void) {
	const char *name = "spine-test";
	spine_platform_set_thread_name(name);

#if defined(__linux__)
	char buf[16] = {0};
	if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) == 0) {
		/* Linux caps at 15 bytes + NUL. "spine-test" is 10 bytes so no
		 * truncation expected. */
		ASSERT_TRUE(strcmp(buf, name) == 0);
	}
#elif defined(__APPLE__)
	char buf[64] = {0};
	if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) == 0) {
		ASSERT_TRUE(strcmp(buf, name) == 0);
	}
#elif defined(__FreeBSD__) || defined(__DragonFly__)
	char buf[64] = {0};
	pthread_get_name_np(pthread_self(), buf, sizeof(buf));
	ASSERT_TRUE(strcmp(buf, name) == 0);
#else
	/* NetBSD, OpenBSD older releases, Solaris, AIX, Windows: no portable
	 * readback. Pass if the set call did not crash. */
#endif
}

static void test_thread_name_long_truncates(void) {
	/* Linux truncates anything beyond 15 bytes. Longer-name-limit platforms
	 * (macOS 63) keep the full string. Either way, no crash and readback
	 * must be a prefix of the request. */
	const char *name = "spine-very-long-thread-name-that-overflows";
	spine_platform_set_thread_name(name);

#if defined(__linux__)
	char buf[16] = {0};
	if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) == 0) {
		ASSERT_TRUE(strlen(buf) <= 15);
		ASSERT_TRUE(strncmp(buf, name, strlen(buf)) == 0);
	}
#elif defined(__APPLE__)
	char buf[64] = {0};
	if (pthread_getname_np(pthread_self(), buf, sizeof(buf)) == 0) {
		ASSERT_TRUE(strncmp(buf, name, strlen(buf)) == 0);
	}
#endif
}

int main(void) {
	test_thread_name_null_is_noop();
	test_thread_name_short();
	test_thread_name_long_truncates();
	return finish_tests("platform thread name tests");
}
