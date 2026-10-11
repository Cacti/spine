/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "internal/common.h"
#include "app/spine.h"
#include <sys/resource.h>
#include <limits.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

config_t set;
static int path_error;
static int resolve_error;
static int resolve_long;
static int limit_get_error;
static int limit_set_error;
static int limits_set;
static int executed;
static struct rlimit inherited;
static struct rlimit applied;

#ifdef __linux__
static ssize_t fake_readlink(const char *path, char *buffer, size_t capacity) {
	(void) path;
	if (path_error) return path_error == 1 ? -1 : (ssize_t) capacity;
	strcpy(buffer, "/tmp/spine");
	return strlen(buffer);
}
#endif
#ifdef __APPLE__
static int fake_executable(char *buffer, uint32_t *capacity) {
	(void) capacity;
	if (path_error) return -1;
	strcpy(buffer, "/tmp/spine");
	return 0;
}
#endif
static char *fake_realpath(const char *path, char *resolved) {
	(void) path;
	if (resolve_error) return NULL;
	if (resolve_long && PATH_MAX > BUFSIZE) {
		memset(resolved, 'a', BUFSIZE);
		resolved[BUFSIZE] = '\0';
	} else strcpy(resolved, "/tmp/spine");
	return resolved;
}
static int fake_getrlimit(int resource, struct rlimit *limit) {
	(void) resource;
	*limit = inherited;
	return limit_get_error ? -1 : 0;
}
static int fake_setrlimit(int resource, const struct rlimit *limit) {
	(void) resource;
	limits_set++;
	applied = *limit;
	return limit_set_error ? -1 : 0;
}
static int fake_execve(const char *file, char *const argv[], char *const environment[]) {
	(void) environment;
	assert_string_equal(file, "/bin/sh");
	assert_string_equal(argv[0], "sh");
	assert_string_equal(argv[1], "-c");
	assert_string_equal(argv[2], "printf 42");
	assert_null(argv[3]);
	executed++;
	return -1;
}
#define readlink fake_readlink
#define realpath fake_realpath
#define getrlimit fake_getrlimit
#define setrlimit fake_setrlimit
#ifdef execve
#undef execve
#endif
#define execve fake_execve
#ifdef __APPLE__
#define _NSGetExecutablePath fake_executable
#endif
#include "../../src/process/resource.c"

static int reset(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	path_error = resolve_error = resolve_long = limit_get_error = limit_set_error = limits_set = executed = 0;
	inherited.rlim_cur = inherited.rlim_max = RLIM_INFINITY;
	return 0;
}

static void test_executable_resolution(void **state) {
	(void) state;
	path_error = 1;
	spine_script_executable("spine");
	assert_string_equal(set.php.script_executable, "");
#ifdef __linux__
	path_error = 2;
	spine_script_executable("spine");
	assert_string_equal(set.php.script_executable, "");
#endif
	path_error = 0;
	resolve_error = 1;
	spine_script_executable("spine");
	assert_string_equal(set.php.script_executable, "");
	resolve_error = 0;
#if PATH_MAX > BUFSIZE
	resolve_long = 1;
	spine_script_executable("spine");
	assert_string_equal(set.php.script_executable, "");
	resolve_long = 0;
#endif
	spine_script_executable("spine");
	assert_string_equal(set.php.script_executable, "/tmp/spine");
}

static void test_child_policy_validation(void **state) {
	char *arguments[] = {"spine", "--internal-script-child", "0", "0", "printf 42"};
	char *invalid[] = {"", "-1", "+1", "1x", "4294967296", "999999999999999999999999"};
	size_t i;
	(void) state;
	assert_int_equal(spine_script_resource_child(4, arguments), 125);
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		arguments[2] = invalid[i];
		assert_int_equal(spine_script_resource_child(5, arguments), 125);
		assert_int_equal(executed, 0);
	}
	arguments[2] = "0";
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(limits_set, 0);
	assert_int_equal(executed, 1);
}

static void test_resource_failures_and_inheritance(void **state) {
	char *arguments[] = {"spine", "--internal-script-child", "2", "0", "printf 42"};
	(void) state;
	limit_get_error = 1;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(executed, 0);
	limit_get_error = 0;
	limit_set_error = 1;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(executed, 0);
	limit_set_error = 0;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(applied.rlim_cur, 2);
	assert_int_equal(applied.rlim_max, 2);
	inherited.rlim_cur = 1;
	inherited.rlim_max = 2;
	arguments[2] = "5";
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(applied.rlim_cur, 1);
	assert_int_equal(applied.rlim_max, 2);
	arguments[2] = "0";
	arguments[3] = "64";
#ifdef __linux__
	inherited.rlim_cur = inherited.rlim_max = RLIM_INFINITY;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(applied.rlim_cur, 64 * 1024 * 1024);
	limit_get_error = 1;
	executed = 0;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(executed, 0);
#else
	executed = 0;
	assert_int_equal(spine_script_resource_child(5, arguments), 125);
	assert_int_equal(executed, 0);
#endif
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_executable_resolution, reset),
		cmocka_unit_test_setup(test_child_policy_validation, reset),
		cmocka_unit_test_setup(test_resource_failures_and_inheritance, reset),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
