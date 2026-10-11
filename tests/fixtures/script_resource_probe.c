/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Disposable external workload, deliberately built without sanitizers so
 * virtual-memory caps measure the child rather than sanitizer address space.
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(int argc, char **argv) {
	struct rlimit limit;
	void *memory;
	int index;
	int fd;
	char block[4096] = {0};
	volatile unsigned int counter = 0;
	if (argc < 2) return 2;
	if (strcmp(argv[1], "cpu") == 0) {
		for (;;) counter++;
	}
	if (strcmp(argv[1], "memory") == 0) {
		memory = malloc(64 * 1024 * 1024);
		if (memory == NULL) return 42;
		memset(memory, 1, 64 * 1024 * 1024);
		free(memory);
	} else if (strcmp(argv[1], "files") == 0) {
		for (index = 0; index < 64; index++) {
			if (open("/dev/null", O_RDONLY) < 0) return 42;
		}
	} else if (strcmp(argv[1], "size") == 0) {
		if (argc != 3) return 2;
		fd = open(argv[2], O_WRONLY | O_TRUNC);
		if (fd < 0) return 2;
		if (write(fd, block, sizeof(block)) != sizeof(block)) return 42;
		if (close(fd) != 0) return 42;
	} else if (strcmp(argv[1], "policy") == 0) {
		if (getrlimit(RLIMIT_CPU, &limit) != 0 || limit.rlim_cur != 1 || limit.rlim_max != 1) return 42;
		if (getrlimit(RLIMIT_AS, &limit) != 0 || limit.rlim_cur != 16 * 1024 * 1024 || limit.rlim_max != 16 * 1024 * 1024) return 42;
		if (getrlimit(RLIMIT_FSIZE, &limit) != 0 || limit.rlim_cur != 1024 || limit.rlim_max != 1024) return 42;
		if (getrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur != 16 || limit.rlim_max != 16) return 42;
	}
	return fputs("1", stdout) < 0 ? 2 : 0;
}
