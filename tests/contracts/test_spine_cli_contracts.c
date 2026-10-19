/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"

/* Exercise the built command-line entry point, without reaching a DB.
 * An explicit absent config keeps a misparsed --version from polling. */
static void run_cli_contract(char *const arguments[], int expected, char *output, size_t capacity) {
	int descriptors[2];
	assert(pipe(descriptors) == 0);
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(15);
		assert(close(descriptors[0]) == 0);
		assert(dup2(descriptors[1], STDOUT_FILENO) == STDOUT_FILENO);
		assert(dup2(descriptors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(descriptors[1]) == 0);
		execv("./spine", arguments);
		_exit(127);
	}
	assert(close(descriptors[1]) == 0);
	size_t used = 0;
	for (;;) {
		assert(used < capacity - 1);
		ssize_t received = read(descriptors[0], output + used, capacity - used - 1);
		if (received < 0 && errno == EINTR) continue;
		assert(received >= 0);
		if (received == 0) break;
		used += (size_t) received;
	}
	output[used] = '\0';
	assert(close(descriptors[0]) == 0);
	int status;
	while (waitpid(child, &status, 0) < 0) assert(errno == EINTR);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

void test_cli_alias_contracts(void) {
	char output[8192];
	char version[8192];
	char help[8192];
	char *version_args[] = {"spine", "--version", NULL};
	run_cli_contract(version_args, EXIT_SUCCESS, version, sizeof(version));
	assert(strstr(version, "SPINE ") != NULL && strstr(version, "Usage:") == NULL);
	char *help_args[] = {"spine", "--help", NULL};
	run_cli_contract(help_args, EXIT_SUCCESS, help, sizeof(help));
	assert(strstr(help, "-h/--help") != NULL && strstr(help, "-H/--hostlist") != NULL);
	assert(strstr(help, "-p/--poller") != NULL && strstr(help, "-P/--pingonly") != NULL);
	char *short_help[] = {"spine", "-h", NULL};
	run_cli_contract(short_help, EXIT_SUCCESS, output, sizeof(output));
	assert(strcmp(help, output) == 0);
	char *value_forms[][6] = {
		{"spine", "-p", "17", "--version", NULL},
		{"spine", "-p=17", "--version", NULL},
		{"spine", "--poller=17", "--version", NULL},
		{"spine", "-H", "17,18", "--version", NULL},
		{"spine", "-H=17,18", "--version", NULL},
		{"spine", "--hostlist=17,18", "--version", NULL},
		{"spine", "-H", " 0 , 0017, 18 ", "--version", NULL},
		{"spine", "-H", "2147483647", "--version", NULL},
		{"spine", "-H", "17,17", "--version", NULL},
	};
	for (size_t index = 0; index < sizeof(value_forms) / sizeof(value_forms[0]); index++) {
		run_cli_contract(value_forms[index], EXIT_SUCCESS, output, sizeof(output));
		assert(strcmp(version, output) == 0);
	}
	char *ping_forms[][6] = {
		{"spine", "-C", "/nonexistent/spine-cli-contract.conf", "-P", "--version", NULL},
		{"spine", "-C", "/nonexistent/spine-cli-contract.conf", "--pingonly", "--version", NULL},
	};
	for (size_t index = 0; index < sizeof(ping_forms) / sizeof(ping_forms[0]); index++) {
		run_cli_contract(ping_forms[index], EXIT_SUCCESS, output, sizeof(output));
		assert(strcmp(version, output) == 0);
	}
	char *missing_poller[] = {"spine", "-p", NULL};
	run_cli_contract(missing_poller, EXIT_FAILURE, output, sizeof(output));
	assert(strstr(output, "ERROR: option -p requires a parameter") != NULL);
	char *missing_hostlist[] = {"spine", "-H", NULL};
	run_cli_contract(missing_hostlist, EXIT_FAILURE, output, sizeof(output));
	assert(strstr(output, "ERROR: option -H requires a parameter") != NULL);
	char invalid_lists[][48] = {"", " ", ",17", "17,", "17,,18", "17 18", "-1", "+1", "1.5", "1e2", "17x", "17;18", "2147483648", "999999999999999999999999999999999999"};
	for (size_t index = 0; index < sizeof(invalid_lists) / sizeof(invalid_lists[0]); index++) {
		char *arguments[] = {"spine", "-H", invalid_lists[index], "--version", NULL};
		run_cli_contract(arguments, EXIT_FAILURE, output, sizeof(output));
		assert(strstr(output, "ERROR: invalid or oversized host list") != NULL);
	}
	/* the longest list that fits host_id_list is accepted whole */
	char *longest = malloc(BIG_BUFSIZE);
	assert(longest != NULL);
	for (size_t index = 0; index < BIG_BUFSIZE - 1; index++) longest[index] = index % 2 == 0 ? '7' : ',';
	longest[BIG_BUFSIZE - 1] = '\0';
	if (longest[BIG_BUFSIZE - 2] == ',') longest[BIG_BUFSIZE - 2] = '\0';
	char *longest_args[] = {"spine", "-H", longest, "--version", NULL};
	run_cli_contract(longest_args, EXIT_SUCCESS, output, sizeof(output));
	assert(strcmp(version, output) == 0);
	free(longest);
	char *oversized = malloc(BIG_BUFSIZE + 1);
	assert(oversized != NULL);
	memset(oversized, '0', BIG_BUFSIZE);
	oversized[BIG_BUFSIZE] = '\0';
	char *oversized_args[] = {"spine", "-H", oversized, "--version", NULL};
	run_cli_contract(oversized_args, EXIT_FAILURE, output, sizeof(output));
	assert(strstr(output, "ERROR: invalid or oversized host list") != NULL);
	free(oversized);
	puts("production CLI alias regressions passed");
}
