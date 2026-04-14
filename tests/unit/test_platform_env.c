#include <stdlib.h>
#include <string.h>

#include "platform/platform.h"
#include "test_platform_helpers.h"

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

int main(void) {
	test_platform_setenv_respects_overwrite();
	return finish_tests("platform env tests");
}
