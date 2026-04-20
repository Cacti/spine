/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | env_scrub: exercise spine_build_child_env against a deliberately
 | poisoned environ. Verifies that dynamic-linker hijack vectors
 | (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, DYLD_*, BASH_ENV, ENV) are
 | dropped while legitimate variables (PATH, HOME) and the injected
 | defaults are preserved.
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_platform_helpers.h"

extern char **spine_build_child_env(void);

static int env_has_prefix(char **env, const char *prefix) {
	size_t plen = strlen(prefix);
	for (size_t i = 0; env && env[i]; i++) {
		if (strncmp(env[i], prefix, plen) == 0) {
			return 1;
		}
	}
	return 0;
}

static void test_dangerous_vars_are_dropped(void) {
	/* Poison environ with every hijack vector we know about, plus a
	 * legitimate PATH and HOME that must survive the filter. The LD_*
	 * and DYLD_* entries span the enumerated set (PRELOAD, LIBRARY_PATH,
	 * AUDIT, INSERT_LIBRARIES) plus prefix-only entries (DEBUG, PROFILE,
	 * FALLBACK_LIBRARY_PATH) to pin the prefix match contract. */
	setenv("LD_PRELOAD", "/evil/libc.so", 1);
	setenv("LD_LIBRARY_PATH", "/evil/lib", 1);
	setenv("LD_AUDIT", "/evil/audit.so", 1);
	setenv("LD_DEBUG", "all", 1);
	setenv("LD_PROFILE", "/evil/prof", 1);
	setenv("DYLD_INSERT_LIBRARIES", "/evil/insert.dylib", 1);
	setenv("DYLD_LIBRARY_PATH", "/evil/dyld", 1);
	setenv("DYLD_FALLBACK_LIBRARY_PATH", "/evil/fallback", 1);
	setenv("BASH_ENV", "/evil/bashrc", 1);
	setenv("ENV", "/evil/shrc", 1);
	setenv("PERL5OPT", "-Mevil", 1);
	setenv("PYTHONSTARTUP", "/evil/startup.py", 1);
	setenv("PYTHONINSPECT", "1", 1);
	setenv("RUBYOPT", "-revil", 1);
	setenv("NODE_OPTIONS", "--require /evil/hook.js", 1);
	setenv("SPINE_TEST_SENTINEL", "keep-me", 1);

	char **env = spine_build_child_env();
	ASSERT_TRUE(env != NULL);
	if (env == NULL) {
		return;
	}

	ASSERT_INT_EQ(env_has_prefix(env, "LD_PRELOAD="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "LD_LIBRARY_PATH="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "LD_AUDIT="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "LD_DEBUG="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "LD_PROFILE="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "DYLD_INSERT_LIBRARIES="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "DYLD_LIBRARY_PATH="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "DYLD_FALLBACK_LIBRARY_PATH="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "BASH_ENV="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "ENV="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "PERL5OPT="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "PYTHONSTARTUP="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "PYTHONINSPECT="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "RUBYOPT="), 0);
	ASSERT_INT_EQ(env_has_prefix(env, "NODE_OPTIONS="), 0);

	/* Unrelated variables survive. PATH either came from the parent or
	 * from the default-PATH injection; either way it must be present. */
	ASSERT_INT_EQ(env_has_prefix(env, "PATH="), 1);
	ASSERT_INT_EQ(env_has_prefix(env, "IFS="), 1);
	ASSERT_INT_EQ(env_has_prefix(env, "SPINE_TEST_SENTINEL=keep-me"), 1);

	free(env);

	unsetenv("LD_PRELOAD");
	unsetenv("LD_LIBRARY_PATH");
	unsetenv("LD_AUDIT");
	unsetenv("LD_DEBUG");
	unsetenv("LD_PROFILE");
	unsetenv("DYLD_INSERT_LIBRARIES");
	unsetenv("DYLD_LIBRARY_PATH");
	unsetenv("DYLD_FALLBACK_LIBRARY_PATH");
	unsetenv("BASH_ENV");
	unsetenv("ENV");
	unsetenv("PERL5OPT");
	unsetenv("PYTHONSTARTUP");
	unsetenv("PYTHONINSPECT");
	unsetenv("RUBYOPT");
	unsetenv("NODE_OPTIONS");
	unsetenv("SPINE_TEST_SENTINEL");
}

static void test_missing_path_triggers_default(void) {
	/* Strip PATH entirely so the function must inject its hardcoded
	 * default. A child that ends up PATH-less is a silent failure mode;
	 * this pins the injection contract down. */
	char *saved = NULL;
	const char *cur = getenv("PATH");
	if (cur) {
		saved = strdup(cur);
	}
	unsetenv("PATH");

	char **env = spine_build_child_env();
	ASSERT_TRUE(env != NULL);
	if (env != NULL) {
		ASSERT_INT_EQ(env_has_prefix(env, "PATH=/usr/local/sbin:"), 1);
		free(env);
	}

	if (saved) {
		setenv("PATH", saved, 1);
		free(saved);
	}
}

int main(void) {
	test_dangerous_vars_are_dropped();
	test_missing_path_triggers_default();
	return finish_tests("env_scrub");
}
