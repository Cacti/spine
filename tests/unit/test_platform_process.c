#include "../../platform.h"
#include "test_platform_helpers.h"

static void test_platform_misc_helpers(void) {
	ASSERT_TRUE(spine_platform_process_id() > 0);
	ASSERT_TRUE(spine_platform_stdout_is_terminal() == 0 || spine_platform_stdout_is_terminal() == 1);
	ASSERT_TRUE(spine_platform_stderr_is_terminal() == 0 || spine_platform_stderr_is_terminal() == 1);
}

int main(void) {
	test_platform_misc_helpers();
	return finish_tests("platform process tests");
}
