/* libFuzzer target for get_namebyhost().
 *
 * host.hostname comes from the Cacti database and is parsed here into a
 * method/host/port triple, so the parser sees operator-supplied text.  The
 * real ping.o is linked, not a copy, so a regression in the shipped function
 * is what fails.
 *
 * Build:
 *   clang -fsanitize=fuzzer,address,undefined tests/fuzz/fuzz_namebyhost.c \
 *         ping.o tests/fuzz/stubs.c -o fuzz_namebyhost -lnetsnmp
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "spine.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char   *input;
	name_t  name;

	/* the parser takes a NUL-terminated string */
	if (size > 4096) return 0;

	input = malloc(size + 1);
	if (input == NULL) return 0;

	memcpy(input, data, size);
	input[size] = '\0';

	memset(&name, 0, sizeof(name));
	get_namebyhost(input, &name);

	/* the contract is a NUL-terminated hostname inside the buffer */
	if (memchr(name.hostname, '\0', sizeof(name.hostname)) == NULL) {
		abort();
	}

	free(input);
	return 0;
}
