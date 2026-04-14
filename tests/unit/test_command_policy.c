#include "../../command_policy.h"
#include "test_platform_helpers.h"

#include <string.h>

static void test_safe_command_patterns(void) {
	char reason[128];

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("/usr/bin/php /opt/spine/probe.php", reason, sizeof(reason)), 1);
	ASSERT_TRUE(reason[0] == '\0');

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("python3 /tmp/check.py --mode fast", reason, sizeof(reason)), 1);
	ASSERT_TRUE(reason[0] == '\0');
}

static void test_rejects_empty_and_null_commands(void) {
	char reason[128];

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("", reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "empty") != NULL);

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe(NULL, reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "empty") != NULL);
}

static void test_rejects_blocked_metacharacters(void) {
	char reason[128];

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("echo 1; id", reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "blocked") != NULL);

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("echo 1 | wc -c", reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "blocked") != NULL);

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("echo $HOME", reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "blocked") != NULL);

	memset(reason, 0, sizeof(reason));
	ASSERT_INT_EQ(spine_script_command_is_safe("echo ok\nid", reason, sizeof(reason)), 0);
	ASSERT_TRUE(strstr(reason, "blocked") != NULL);
}

int main(void) {
	test_safe_command_patterns();
	test_rejects_empty_and_null_commands();
	test_rejects_blocked_metacharacters();
	return finish_tests("command policy tests");
}
