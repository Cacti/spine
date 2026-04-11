#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../platform.h"

static int failures = 0;

#define ASSERT_TRUE(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "assertion failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
		failures++; \
	} \
} while (0)

#define ASSERT_INT_EQ(actual, expected) do { \
	int _actual = (actual); \
	int _expected = (expected); \
	if (_actual != _expected) { \
		fprintf(stderr, "assertion failed: %s:%d: %s == %s (actual=%d expected=%d)\n", \
			__FILE__, __LINE__, #actual, #expected, _actual, _expected); \
		failures++; \
	} \
} while (0)

static void test_platform_init_and_cleanup(void) {
	ASSERT_INT_EQ(spine_platform_init(), 0);
	spine_platform_cleanup();
}

static void test_platform_setenv_respects_overwrite(void) {
	const char *name = "SPINE_PLATFORM_TEST_ENV";
	const char *value;

	ASSERT_INT_EQ(spine_platform_setenv(name, "initial", 1), 0);
	value = getenv(name);
	ASSERT_TRUE(value != NULL);
	ASSERT_TRUE(strcmp(value, "initial") == 0);

	ASSERT_INT_EQ(spine_platform_setenv(name, "kept", 0), 0);
	value = getenv(name);
	ASSERT_TRUE(value != NULL);
	ASSERT_TRUE(strcmp(value, "initial") == 0);

	ASSERT_INT_EQ(spine_platform_setenv(name, "updated", 1), 0);
	value = getenv(name);
	ASSERT_TRUE(value != NULL);
	ASSERT_TRUE(strcmp(value, "updated") == 0);
}

static void test_platform_localtime_matches_libc(void) {
	time_t now;
	struct tm expected_tm;
	struct tm actual_tm;
	struct tm *baseline_tm;

	now = time(NULL);
	baseline_tm = localtime(&now);
	ASSERT_TRUE(baseline_tm != NULL);
	if (baseline_tm == NULL) {
		return;
	}

	expected_tm = *baseline_tm;
	ASSERT_INT_EQ(spine_platform_localtime(&now, &actual_tm), 0);
	ASSERT_INT_EQ(actual_tm.tm_year, expected_tm.tm_year);
	ASSERT_INT_EQ(actual_tm.tm_mon, expected_tm.tm_mon);
	ASSERT_INT_EQ(actual_tm.tm_mday, expected_tm.tm_mday);
	ASSERT_INT_EQ(actual_tm.tm_hour, expected_tm.tm_hour);
	ASSERT_INT_EQ(actual_tm.tm_min, expected_tm.tm_min);
}

static void test_platform_misc_helpers(void) {
	ASSERT_TRUE(spine_platform_process_id() > 0);
	ASSERT_TRUE(spine_platform_stdout_is_terminal() == 0 || spine_platform_stdout_is_terminal() == 1);
	ASSERT_TRUE(spine_platform_stderr_is_terminal() == 0 || spine_platform_stderr_is_terminal() == 1);

	spine_platform_sleep_ms(1);
	spine_platform_sleep_us(500);
	spine_platform_sleep_s(0);
}

int main(void) {
	test_platform_init_and_cleanup();
	test_platform_setenv_respects_overwrite();
	test_platform_localtime_matches_libc();
	test_platform_misc_helpers();

	if (failures != 0) {
		fprintf(stderr, "platform smoke tests failed: %d\n", failures);
		return EXIT_FAILURE;
	}

	printf("platform smoke tests passed\n");
	return EXIT_SUCCESS;
}
