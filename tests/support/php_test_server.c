/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
	char command[4096];
	const char *mode = argc > 2 ? argv[2] : "";
	if (strstr(mode, "exit-before-start") != NULL) return 0;
	/* Only the first server to claim the named file answers, so a test can
	 * start a pool in which every later server stays silent. */
	if (strstr(mode, "first-only:") != NULL) {
		int claim = open(strstr(mode, "first-only:") + strlen("first-only:"), O_CREAT | O_EXCL | O_WRONLY, 0600);

		if (claim < 0) mode = "silent";
		else close(claim);
	}
	/* Longer than the recovery handshake cap, shorter than script_timeout. */
	if (strstr(mode, "slow-start") != NULL) sleep(3);

	if (strstr(mode, "silent") == NULL) {
		struct sigaction action;
		int bad_start = strstr(mode, "bad-start") != NULL;

		if (strstr(mode, "check-sigpipe") != NULL &&
			(sigaction(SIGPIPE, NULL, &action) != 0 || action.sa_handler != SIG_DFL)) {
			bad_start = 1;
		}
		puts(bad_start ? "Not ready" : "Started");
		fflush(stdout);
	}

	while (fgets(command, sizeof(command), stdin) != NULL) {
		if (strcmp(command, "quit\r\n") == 0 || strcmp(command, "quit\n") == 0) {
			break;
		}

		puts(strcmp(command, "poll 7\r\n") == 0 ? "42" : "unexpected command");
		fflush(stdout);
	}

	return 0;
}
