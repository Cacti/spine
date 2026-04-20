/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Source-scan invariants. Lightweight regression guards that read the
 | production source files at test time and assert key structural
 | properties that silent-drop a behaviour change the rest of the test
 | suite would not notice:
 |
 |   1. spine_async_exec always routes through /bin/sh -c (the dropped
 |      metachar-detect hybrid must not come back).
 |   2. spine.c shutdown flushes the batch BEFORE flipping the async
 |      mysql shutdown fence (the correct ordering; reversing it re-
 |      introduces silent data loss).
 +-------------------------------------------------------------------------+
*/

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

/* CMake pins this to ${CMAKE_SOURCE_DIR}. Fallback is the relative
 * path - useful when running the binary manually from the project
 * root but not trusted in CI. */
#ifndef SPINE_SOURCE_ROOT
#define SPINE_SOURCE_ROOT "."
#endif

static char *slurp(const char *relpath) {
	char path[PATH_MAX];
	snprintf(path, sizeof(path), "%s/%s", SPINE_SOURCE_ROOT, relpath);

	FILE *f = fopen(path, "rb");
	if (!f) return NULL;

	if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
	long n = ftell(f);
	if (n < 0) { fclose(f); return NULL; }
	if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }

	char *buf = (char *)malloc((size_t)n + 1);
	if (!buf) { fclose(f); return NULL; }

	size_t got = fread(buf, 1, (size_t)n, f);
	buf[got] = '\0';
	fclose(f);
	return buf;
}

static void test_sh_c_is_hardcoded(void) {
	char *src = slurp("src/async_exec.c");
	ASSERT_TRUE(src != NULL);
	if (!src) return;

	ASSERT_TRUE(strstr(src, "/bin/sh") != NULL);
	ASSERT_TRUE(strstr(src, "strdup(\"-c\")") != NULL);

	free(src);
}

static void test_no_metachar_detection(void) {
	char *src = slurp("src/async_exec.c");
	ASSERT_TRUE(src != NULL);
	if (!src) return;

	/* Dropped symbols from the earlier hybrid. If they return, someone
	 * reintroduced the behaviour split between argv-tokenizer and
	 * sh -c based on command content. */
	ASSERT_TRUE(strstr(src, "needs_shell") == NULL);
	ASSERT_TRUE(strstr(src, "async_exec_parse_argv") == NULL);

	free(src);
}

static void test_flush_before_fence(void) {
	char *src = slurp("src/spine.c");
	ASSERT_TRUE(src != NULL);
	if (!src) return;

	const char *flush = strstr(src, "spine_async_batch_flush(");
	const char *fence = strstr(src, "spine_async_mysql_shutdown_begin(");

	ASSERT_TRUE(flush != NULL);
	ASSERT_TRUE(fence != NULL);
	if (flush && fence) {
		/* Flush must come before the fence so pending batched writes
		 * still reach MySQL. Reversing the order silently drops the
		 * batch at shutdown. */
		ASSERT_TRUE(flush < fence);
	}

	free(src);
}

int main(void) {
	test_sh_c_is_hardcoded();
	test_no_metachar_detection();
	test_flush_before_fence();
	return finish_tests("async_exec_shell_invariants");
}
