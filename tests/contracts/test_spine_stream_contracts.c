/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"

/* Dispatch before regression initialization: this is a real child producer,
 * not a replacement implementation of exec_poll or its pipe reader. */
int run_script_stream_fixture(const char *scenario) {
	const char *bytes;
	int status = 0;
	if (strcmp(scenario, "empty") == 0) bytes = "";
	else if (strcmp(scenario, "partial") == 0) bytes = "partial-7";
	else if (strcmp(scenario, "lines") == 0) bytes = "7\n8\n";
	else if (strcmp(scenario, "failure-output") == 0) {
		bytes = "9";
		status = 23;
	} else if (strcmp(scenario, "failure-empty") == 0) {
		bytes = "";
		status = 23;
	} else return 99;
	size_t length = strlen(bytes);
	assert(length <= _POSIX_PIPE_BUF);
	if (length != 0) {
		ssize_t sent;
		do { sent = write(STDOUT_FILENO, bytes, length); } while (sent < 0 && errno == EINTR);
		assert(sent == (ssize_t) length);
	}
	return status;
}

static void assert_stream_result(host_t *host, const char *scenario, const char *type, const char *expected) {
	char command[BUFSIZE];
	spine_snprintf(command, sizeof(command), "./test_spine_regressions --script-stream %s", scenario);
	char *result = exec_poll(host, command, 991, type);
	assert(result != NULL && strcmp(result, expected) == 0);
	free(result);
	assert(spine_permits_available(&available_scripts) == 1);
}

void test_script_stream_contracts(void) {
	int previous_timeout = set.php.script_timeout;
	set.php.script_timeout = 5;
	assert(spine_permits_init(&available_scripts, 1) == 0);
	host_t host = {0};
	host.id = 991;
	STRNCOPY(host.hostname, "owned-stream-fixture");
	assert_stream_result(&host, "empty", "DS", "U");
	assert_stream_result(&host, "empty", "DQ", "U");
	assert_stream_result(&host, "partial", "DS", "partial-7");
	assert_stream_result(&host, "lines", "DS", "7\n8\n");
	/* Legacy script results are determined by bytes, not child exit status.
	 * Preserve this contract while verifying the pipe backend exposes status. */
	assert_stream_result(&host, "failure-output", "DS", "9");
	assert_stream_result(&host, "failure-empty", "DQ", "U");
	assert(spine_permits_destroy(&available_scripts) == 0);
	set.php.script_timeout = previous_timeout;

	int descriptor = nft_popen("./test_spine_regressions --script-stream failure-output", "r");
	assert(descriptor >= 0);
	pid_t child = nft_pchild(descriptor);
	assert(child > 0);
	assert(spine_wait_readable(descriptor, spine_monotonic_time() + 5) == 1);
	char output[8] = {0};
	ssize_t received;
	do { received = read(descriptor, output, sizeof(output)); } while (received < 0 && errno == EINTR);
	assert(received == 1 && output[0] == '9');
	do { received = read(descriptor, output, sizeof(output)); } while (received < 0 && errno == EINTR);
	assert(received == 0);
	int status = nft_pclose(descriptor);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 23);
	assert(nft_pchild(descriptor) == -1 && errno == EBADF);
	assert(nft_pclose(descriptor) == -1 && errno == EBADF);
	assert(waitpid(child, &status, WNOHANG) == -1 && errno == ECHILD);
	puts("production script stream regressions passed");
}
