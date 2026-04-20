/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Source-scan invariant: spine_async_exec always routes through
 | /bin/sh -c. An earlier hybrid picked argv-tokenizer for 'simple'
 | commands and sh -c for shell-metachar commands, creating a behaviour
 | split users could not control. The invariant prevents a future
 | refactor from reintroducing the split; if anyone adds metachar
 | detection back this test fails immediately.
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

static char *slurp(const char *path) {
	FILE *f = fopen(path, "rb");
	if (!f) return NULL;

	fseek(f, 0, SEEK_END);
	long n = ftell(f);
	fseek(f, 0, SEEK_SET);

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

	/* Must contain the literal /bin/sh + -c argv setup. */
	ASSERT_TRUE(strstr(src, "/bin/sh") != NULL);
	ASSERT_TRUE(strstr(src, "strdup(\"-c\")") != NULL);

	free(src);
}

static void test_no_metachar_detection(void) {
	char *src = slurp("src/async_exec.c");
	ASSERT_TRUE(src != NULL);
	if (!src) return;

	/* These strings were part of the dropped metachar scanner. If they
	 * come back, someone reintroduced the behaviour split. */
	ASSERT_TRUE(strstr(src, "needs_shell") == NULL);
	ASSERT_TRUE(strstr(src, "async_exec_parse_argv") == NULL);

	free(src);
}

int main(void) {
	test_sh_c_is_hardcoded();
	test_no_metachar_detection();
	return finish_tests("async_exec_shell_invariant");
}
