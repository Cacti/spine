/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | arc4random smoke test. On the BSDs arc4random(3) lives in libc and is
 | the preferred source for ICMP sequence / request-id nonces. Confirm
 | that repeated calls diverge: 10 consecutive reads must not all be the
 | same 32-bit value. The probability of a false negative against a real
 | CSPRNG is 2^-288, rounded.
 +-------------------------------------------------------------------------+
*/

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#include "test_platform_helpers.h"

static void test_arc4random_values_differ(void) {
	uint32_t values[10];
	for (int i = 0; i < 10; i++) {
		values[i] = arc4random();
	}

	int seen_difference = 0;
	for (int i = 1; i < 10 && !seen_difference; i++) {
		if (values[i] != values[0]) {
			seen_difference = 1;
		}
	}
	ASSERT_TRUE(seen_difference);
}

int main(void) {
	test_arc4random_values_differ();
	return finish_tests("arc4random tests");
}

#else

int main(void) {
	return 0;
}

#endif
