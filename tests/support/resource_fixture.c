/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <signal.h>
int main(int argc, char *argv[]) {
	struct rlimit limit;
	volatile unsigned long work = 0;
	void *allocations[256];
	int allocated = 0;
	int result = 0;
	int i;
	if (argc != 2) return 2;
	if (strcmp(argv[1], "cpu") == 0) {
		for (;;) work++;
	}
	if (strcmp(argv[1], "memory") == 0) {
		for (i = 0; i < 256; i++) {
			allocations[i] = malloc(1024 * 1024);
			if (allocations[i] == NULL) {
				result = 42;
				break;
			}
			allocated++;
			memset(allocations[i], 0x5a, 1024 * 1024);
		}
		for (i = 0; i < allocated; i++) free(allocations[i]);
		return result;
	}
	if (strcmp(argv[1], "limits") == 0) {
		if (getrlimit(RLIMIT_CPU, &limit) != 0) return 2;
		printf("%llu", (unsigned long long) limit.rlim_cur);
		return 0;
	}
	if (strcmp(argv[1], "linger") == 0) {
		(void) signal(SIGTERM, SIG_IGN);
		if (write(STDOUT_FILENO, "42", 2) != 2) return 2;
		sleep(30);
		return 0;
	}
	if (strcmp(argv[1], "chunked") == 0) {
		if (write(STDOUT_FILENO, "4", 1) != 1) return 2;
		usleep(100000);
		if (write(STDOUT_FILENO, "2", 1) != 1) return 2;
		return 0;
	}
	return 2;
}
