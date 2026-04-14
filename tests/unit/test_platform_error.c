#include <errno.h>
#include <string.h>

#include "platform/platform_error.h"
#include "test_platform_helpers.h"

static void test_error_string_returns_text(void) {
	char buffer[128];
	const char *message;

	message = spine_platform_error_string(EINVAL, buffer, sizeof(buffer));
	ASSERT_TRUE(message != NULL);
	ASSERT_TRUE(strlen(message) > 0);
}

int main(void) {
	test_error_string_returns_text();
	return finish_tests("platform error tests");
}
