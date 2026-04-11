#ifndef SPINE_TEST_PLATFORM_HELPERS_H
#define SPINE_TEST_PLATFORM_HELPERS_H

#include <stdio.h>
#include <stdlib.h>

static int test_failures = 0;

#define ASSERT_TRUE(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "assertion failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		test_failures++; \
	} \
} while (0)

#define ASSERT_INT_EQ(actual, expected) do { \
	int _actual = (actual); \
	int _expected = (expected); \
	if (_actual != _expected) { \
		fprintf(stderr, "assertion failed: %s:%d: %s == %s (actual=%d expected=%d)\n", \
			__FILE__, __LINE__, #actual, #expected, _actual, _expected); \
		test_failures++; \
	} \
} while (0)

static int finish_tests(const char *suite_name) {
	if (test_failures != 0) {
		fprintf(stderr, "%s failed: %d\n", suite_name, test_failures);
		return EXIT_FAILURE;
	}

	printf("%s passed\n", suite_name);
	return EXIT_SUCCESS;
}

#endif
