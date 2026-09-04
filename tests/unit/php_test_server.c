#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
	char command[4096];
	const char *mode = argc > 2 ? argv[2] : "";

	if (strstr(mode, "silent") == NULL) {
		puts(strstr(mode, "bad-start") != NULL ? "Not ready" : "Started");
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
