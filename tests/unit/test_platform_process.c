#include "../../platform.h"
#include "../../platform_process.h"
#include "test_platform_helpers.h"

static void test_platform_misc_helpers(void) {
	ASSERT_TRUE(spine_platform_process_id() > 0);
	ASSERT_TRUE(spine_platform_stdout_is_terminal() == 0 || spine_platform_stdout_is_terminal() == 1);
	ASSERT_TRUE(spine_platform_stderr_is_terminal() == 0 || spine_platform_stderr_is_terminal() == 1);
}

static void test_platform_pipe_helpers(void) {
	int pipe_fds[2];

	ASSERT_INT_EQ(spine_process_pipe(pipe_fds), 0);
	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[0]), 0);
	ASSERT_INT_EQ(spine_process_close_fd(pipe_fds[1]), 0);
}

static void test_platform_spawn_and_wait(void) {
	spine_pid_t pid;
	int status;
#ifdef _WIN32
	char cmd_path[] = "C:\\Windows\\System32\\cmd.exe";
	char cmd_flag[] = "/c";
	char cmd_body[] = "exit 0";
	char *argv[] = { cmd_path, cmd_flag, cmd_body, NULL };
#else
	char shell_path[] = "/bin/sh";
	char shell_flag[] = "-c";
	char shell_body[] = "exit 0";
	char *argv[] = { shell_path, shell_flag, shell_body, NULL };
#endif

	ASSERT_INT_EQ(spine_process_spawn_retry(&pid, argv[0], NULL, argv, NULL, 1, 1000), 0);
	ASSERT_INT_EQ(spine_process_wait(pid, &status), 0);
	ASSERT_INT_EQ(status, 0);
}

static void test_platform_spawn_and_terminate(void) {
	spine_pid_t pid;
	int status;
#ifdef _WIN32
	char cmd_path[] = "C:\\Windows\\System32\\cmd.exe";
	char cmd_flag[] = "/c";
	char cmd_body[] = "ping -n 3 127.0.0.1 >NUL";
	char *argv[] = { cmd_path, cmd_flag, cmd_body, NULL };
#else
	char shell_path[] = "/bin/sh";
	char shell_flag[] = "-c";
	char shell_body[] = "sleep 1";
	char *argv[] = { shell_path, shell_flag, shell_body, NULL };
#endif

	ASSERT_INT_EQ(spine_process_spawn_retry(&pid, argv[0], NULL, argv, NULL, 1, 1000), 0);
	ASSERT_INT_EQ(spine_process_terminate(pid), 0);
	ASSERT_INT_EQ(spine_process_wait(pid, &status), 0);
	ASSERT_TRUE(status != 0);
}

int main(void) {
	test_platform_misc_helpers();
	test_platform_pipe_helpers();
	test_platform_spawn_and_wait();
	test_platform_spawn_and_terminate();
	return finish_tests("platform process tests");
}
