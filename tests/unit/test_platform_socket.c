#include "../../platform.h"
#include "../../platform_socket.h"
#include "test_platform_helpers.h"

static void test_socket_open_and_close(void) {
	spine_socket_t socket_fd;
	struct timeval timeout;

	socket_fd = spine_socket_open(AF_INET, SOCK_DGRAM, 0);
	ASSERT_TRUE(spine_socket_is_valid(socket_fd));
	if (!spine_socket_is_valid(socket_fd)) {
		return;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;
	ASSERT_INT_EQ(spine_socket_set_timeout(socket_fd, &timeout), 0);
	ASSERT_INT_EQ(spine_socket_close(socket_fd), 0);
}

static void test_socket_invalid_wait_sets_error(void) {
	struct timeval timeout;
	int error_code;

	timeout.tv_sec = 0;
	timeout.tv_usec = 1000;

	ASSERT_INT_EQ(spine_socket_wait_readable(SPINE_INVALID_SOCKET_HANDLE, &timeout), -1);
	error_code = spine_socket_last_error();
	ASSERT_TRUE(!spine_socket_error_is_conn_refused(error_code));
	ASSERT_TRUE(!spine_socket_error_is_interrupted(error_code));
}

static void test_ping_socket_platform_policy(void) {
#ifdef _WIN32
	ASSERT_INT_EQ(spine_socket_ping_icmp_recv_flags(), 0);
	ASSERT_INT_EQ(spine_socket_ping_tcp_supports_retries(), 1);
	ASSERT_INT_EQ(spine_socket_raw_icmp_needs_privileged_open(), 0);
#elif defined(__CYGWIN__)
	ASSERT_INT_EQ(spine_socket_ping_icmp_recv_flags(), MSG_PEEK);
	ASSERT_INT_EQ(spine_socket_ping_tcp_supports_retries(), 0);
#if defined(SOLAR_PRIV)
	ASSERT_INT_EQ(spine_socket_raw_icmp_needs_privileged_open(), 1);
#else
	ASSERT_INT_EQ(spine_socket_raw_icmp_needs_privileged_open(), 0);
#endif
#else
	ASSERT_INT_EQ(spine_socket_ping_icmp_recv_flags(), MSG_WAITALL);
	ASSERT_INT_EQ(spine_socket_ping_tcp_supports_retries(), 1);
	ASSERT_INT_EQ(spine_socket_raw_icmp_needs_privileged_open(), 1);
#endif
}

int main(void) {
	ASSERT_INT_EQ(spine_platform_init(), 0);
	test_socket_open_and_close();
	test_socket_invalid_wait_sets_error();
	test_ping_socket_platform_policy();
	spine_platform_cleanup();
	return finish_tests("platform socket tests");
}
