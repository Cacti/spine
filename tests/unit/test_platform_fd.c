#include <string.h>

#include "platform/platform_fd.h"
#include "platform/platform_process.h"
#include "test_platform_helpers.h"

static void test_fd_pipe_roundtrip(void) {
	int pipe_fds[2];
	char message[] = "platform-fd-test\n";
	char buffer[64];
	struct timeval timeout;
	ssize_t bytes_written;
	ssize_t bytes_read;

	ASSERT_INT_EQ(spine_process_pipe(pipe_fds), 0);

	bytes_written = spine_fd_write(pipe_fds[1], message, strlen(message));
	ASSERT_INT_EQ((int) bytes_written, (int) strlen(message));

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	ASSERT_INT_EQ(spine_fd_wait_readable(pipe_fds[0], &timeout), 1);

	bytes_read = spine_fd_read(pipe_fds[0], buffer, sizeof(buffer) - 1);
	ASSERT_TRUE(bytes_read > 0);
	if (bytes_read > 0) {
		buffer[bytes_read] = '\0';
		ASSERT_TRUE(strcmp(buffer, message) == 0);
	}

	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[0]), 0);
	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[1]), 0);
}

static void test_fd_timeout_argument_validation(void) {
	int pipe_fds[2];

	ASSERT_INT_EQ(spine_process_pipe(pipe_fds), 0);
	ASSERT_INT_EQ(spine_fd_wait_readable(pipe_fds[0], NULL), -1);
	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[0]), 0);
	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[1]), 0);
}

int main(void) {
	test_fd_pipe_roundtrip();
	test_fd_timeout_argument_validation();
	return finish_tests("platform fd tests");
}
