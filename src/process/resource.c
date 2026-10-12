/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal/common.h"
#include "app/spine.h"
#include "process/resource.h"
#include <sys/resource.h>
#include <limits.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

/* Used after dropping privileges on platforms without an executable-path API. */
static inline char *script_executable_from_path(const char *argument) {
	const char *search;
	const char *end;
	size_t directory_length;
	size_t name_length;
	char candidate[PATH_MAX];
	struct stat status;
	char *resolved;
	if (argument == NULL || argument[0] == '\0') return NULL;
	name_length = strlen(argument);
	if (name_length >= sizeof(candidate)) return NULL;
	if (strchr(argument, '/') != NULL) return realpath(argument, NULL);
	search = getenv("PATH");
	if (search == NULL) return NULL;
	for (;;) {
		end = strchr(search, ':');
		directory_length = end == NULL ? strlen(search) : (size_t) (end - search);
		if (directory_length + name_length + 1 < sizeof(candidate)) {
			if (directory_length != 0) {
				memcpy(candidate, search, directory_length);
				candidate[directory_length] = '/';
				memcpy(candidate + directory_length + 1, argument, name_length + 1);
			} else memcpy(candidate, argument, name_length + 1);
			if (access(candidate, X_OK) == 0 && stat(candidate, &status) == 0 && S_ISREG(status.st_mode)) {
				resolved = realpath(candidate, NULL);
				if (resolved != NULL) return resolved;
			}
		}
		if (end == NULL) return NULL;
		search = end + 1;
	}
}

void spine_script_executable(const char *argument) {
	char *resolved;
	size_t length;
#if defined(__linux__)
	/* Let libc allocate the canonical path; /proc/self is owned by this process. */
	resolved = realpath("/proc/self/exe", NULL);
#elif defined(__APPLE__)
	char path[PATH_MAX];
	uint32_t capacity = sizeof(path);
	if (_NSGetExecutablePath(path, &capacity) != 0) return;
	resolved = realpath(path, NULL);
#else
	resolved = script_executable_from_path(argument);
#endif
	(void) argument;
	if (resolved == NULL) return;
	length = strlen(resolved);
	if (length < sizeof(set.php.script_executable)) memcpy(set.php.script_executable, resolved, length + 1);
	free(resolved);
}

static int lower_limit(int resource, rlim_t requested) {
	struct rlimit limit;
	if (requested == 0) return 0;
	if (getrlimit(resource, &limit) != 0) return -1;
	/* Never raise inherited soft or hard limits. */
	if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur > requested) limit.rlim_cur = requested;
	if (limit.rlim_max == RLIM_INFINITY || limit.rlim_max > requested) limit.rlim_max = requested;
	return setrlimit(resource, &limit);
}

int spine_script_resource_child(int argc, char *argv[]) {
	unsigned long limits[2];
	char *end;
	int index;
	char *shell_args[] = {"sh", "-c", NULL, NULL};
	extern char **environ;
	if (argc != 5) return 125;
	for (index = 0; index < 2; index++) {
		errno = 0;
		limits[index] = strtoul(argv[index + 2], &end, 10);
		if (argv[index + 2][0] < '0' || argv[index + 2][0] > '9' || *end != '\0' || errno != 0 || limits[index] > UINT_MAX) return 125;
	}
	if (lower_limit(RLIMIT_CPU, (rlim_t) limits[0]) != 0) return 125;
#if defined(__linux__)
	if ((uint64_t) limits[1] * 1024 * 1024 > (uint64_t) (rlim_t) -1 ||
		lower_limit(RLIMIT_AS, (rlim_t) limits[1] * 1024 * 1024) != 0) return 125;
#else
	if (limits[1] != 0) return 125;
#endif
	shell_args[2] = argv[4];
	execve("/bin/sh", shell_args, environ);
	return 125;
}
