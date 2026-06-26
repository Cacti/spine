#include <time.h>

#include "platform/platform.h"
#include "test_platform_helpers.h"

static void test_platform_init_and_cleanup(void) {
	ASSERT_INT_EQ(spine_platform_init(), 0);
	spine_platform_cleanup();
}

static void test_platform_localtime_matches_libc(void) {
	time_t now;
	struct tm expected_tm;
	struct tm actual_tm;
	const struct tm *baseline_tm;

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

static void test_platform_sleep_helpers(void) {
	spine_platform_sleep_ms(1);
	spine_platform_sleep_us(500);
	spine_platform_sleep_s(0);
}

int main(void) {
	test_platform_init_and_cleanup();
	test_platform_localtime_matches_libc();
	test_platform_sleep_helpers();
	return finish_tests("platform time tests");
}
