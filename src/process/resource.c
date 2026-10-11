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

void spine_script_executable(const char *argument) {
	char path[PATH_MAX];
	char resolved[PATH_MAX];
#if defined(__linux__)
	ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
	if (length <= 0 || (size_t) length >= sizeof(path) - 1) return;
	path[length] = '\0';
#elif defined(__APPLE__)
	uint32_t capacity = sizeof(path);
	if (_NSGetExecutablePath(path, &capacity) != 0) return;
#else
	if (argument == NULL || strlen(argument) >= sizeof(path)) return;
	strcpy(path, argument);
#endif
	(void) argument;
	if (realpath(path, resolved) == NULL || strlen(resolved) >= sizeof(set.php.script_executable)) return;
	strcpy(set.php.script_executable, resolved);
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
