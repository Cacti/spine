#include <string.h>

int main(int argc, char **argv) {
	if (argc != 5) {
		return 10;
	}
	if (strcmp(argv[1], "a\"b") != 0) {
		return 11;
	}
	if (strcmp(argv[2], "a \\") != 0) {
		return 12;
	}
	if (strcmp(argv[3], "\\\"") != 0) {
		return 13;
	}
	if (strcmp(argv[4], "") != 0) {
		return 14;
	}

	return 0;
}
