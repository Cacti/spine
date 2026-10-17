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
static char resolved_input[PATH_MAX];
static int path_error;
static int resolve_error;
static int resolve_long;
static int limit_get_error;
static int limit_set_error;
static int limits_set;
static int executed;
static struct rlimit inherited;
static struct rlimit applied;

#ifdef __APPLE__
static int fake_executable(char *buffer, uint32_t *capacity) {
	(void) capacity;
	if (path_error) return -1;
	strcpy(buffer, "/tmp/spine");
	return 0;
}
#endif
static char *fake_realpath(const char *path, char *resolved) {
	char *result;
	snprintf(resolved_input, sizeof(resolved_input), "%s", path);
	assert_null(resolved);
	if (resolve_error) return NULL;
	result = malloc(BUFSIZE + 1);
	assert_non_null(result);
	if (resolve_long) {
		memset(result, 'a', BUFSIZE);
		result[BUFSIZE] = '\0';
	} else memcpy(result, "/tmp/spine", sizeof("/tmp/spine"));
	return result;
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
#ifdef __APPLE__
	path_error = 1;
	spine_script_executable("/tmp/spine");
	assert_string_equal(set.php.script_executable, "");
	path_error = 0;
#endif
	resolve_error = 1;
	spine_script_executable("/tmp/spine");
	assert_string_equal(set.php.script_executable, "");
	resolve_error = 0;
	resolve_long = 1;
	spine_script_executable("/tmp/spine");
	assert_string_equal(set.php.script_executable, "");
	resolve_long = 0;
	spine_script_executable("/tmp/spine");
	assert_string_equal(set.php.script_executable, "/tmp/spine");
}

#if !defined(__linux__) && !defined(__APPLE__)
static void test_executable_path_search(void **state) {
	char directory[] = "/tmp/spine-path-XXXXXX";
	char executable[PATH_MAX];
	char search[PATH_MAX];
	char *saved = getenv("PATH") == NULL ? NULL : strdup(getenv("PATH"));
	char *resolved;
	FILE *file;
	(void) state;
	assert_non_null(mkdtemp(directory));
	snprintf(executable, sizeof(executable), "%s/spine", directory);
	file = fopen(executable, "w");
	assert_non_null(file);
	assert_int_equal(fchmod(fileno(file), 0700), 0);
	snprintf(search, sizeof(search), "/missing-spine-directory:%s", directory);
	assert_int_equal(setenv("PATH", search, 1), 0);
	resolved = script_executable_from_path("spine");
	assert_non_null(resolved);
	assert_string_equal(resolved_input, executable);
	free(resolved);
	assert_int_equal(fchmod(fileno(file), 0600), 0);
	assert_null(script_executable_from_path("spine"));
	assert_int_equal(fclose(file), 0);
	assert_int_equal(unlink(executable), 0);
	assert_int_equal(mkdir(executable, 0700), 0);
	assert_null(script_executable_from_path("spine"));
	assert_int_equal(unsetenv("PATH"), 0);
	assert_null(script_executable_from_path("spine"));
	resolved = script_executable_from_path(executable);
	assert_non_null(resolved);
	assert_string_equal(resolved_input, executable);
	free(resolved);
	assert_int_equal(rmdir(executable), 0);
	assert_int_equal(rmdir(directory), 0);
	if (saved != NULL) {
		setenv("PATH", saved, 1);
		free(saved);
	} else unsetenv("PATH");
}

#endif

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
#if !defined(__linux__) && !defined(__APPLE__)
		cmocka_unit_test_setup(test_executable_path_search, reset),
#endif
		cmocka_unit_test_setup(test_child_policy_validation, reset),
		cmocka_unit_test_setup(test_resource_failures_and_inheritance, reset),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
