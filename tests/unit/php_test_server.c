#include <stdio.h>
#include <signal.h>
#include <string.h>

int main(int argc, char **argv) {
	char command[4096];
	const char *mode = argc > 2 ? argv[2] : "";
	if (strstr(mode, "exit-before-start") != NULL) return 0;

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
