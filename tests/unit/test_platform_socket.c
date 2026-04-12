#include <errno.h>
#include <string.h>

#include "../../platform.h"
#include "../../platform_socket.h"
#include "test_platform_helpers.h"

static int bind_loopback_ipv4(spine_socket_t socket_fd, struct sockaddr_in *address, socklen_t *address_len) {
	memset(address, 0, sizeof(*address));
	address->sin_family = AF_INET;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	address->sin_len = (uint8_t) sizeof(*address);
#endif
	address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address->sin_port = 0;

	if (bind(socket_fd, (struct sockaddr *) address, sizeof(*address)) != 0) {
		return -1;
	}

	*address_len = (socklen_t) sizeof(*address);
	return getsockname(socket_fd, (struct sockaddr *) address, address_len);
}

static int bind_loopback_ipv6(spine_socket_t socket_fd, struct sockaddr_in6 *address, socklen_t *address_len) {
	memset(address, 0, sizeof(*address));
	address->sin6_family = AF_INET6;
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
	address->sin6_len = (uint8_t) sizeof(*address);
#endif
	address->sin6_addr = in6addr_loopback;
	address->sin6_port = 0;

	if (bind(socket_fd, (struct sockaddr *) address, sizeof(*address)) != 0) {
		return -1;
	}

	*address_len = (socklen_t) sizeof(*address);
	return getsockname(socket_fd, (struct sockaddr *) address, address_len);
}

static void test_socket_ipv4_loopback_tcp(void) {
	spine_socket_t listener_fd;
	spine_socket_t client_fd;
	spine_socket_t accepted_fd;
	struct sockaddr_in listener_addr;
	struct sockaddr_in accepted_addr;
	struct timeval timeout;
	socklen_t listener_len;
	socklen_t accepted_len;
	char message[] = "ipv4-tcp";
	char buffer[32];
	int result;

	listener_fd = spine_socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_TRUE(spine_socket_is_valid(listener_fd));
	if (!spine_socket_is_valid(listener_fd)) {
		return;
	}

	result = bind_loopback_ipv4(listener_fd, &listener_addr, &listener_len);
	if (result != 0) {
		fprintf(stderr, "skipping ipv4 loopback tcp test: bind() failed on this host\n");
		spine_socket_close(listener_fd);
		return;
	}

	result = listen(listener_fd, 1);
	ASSERT_INT_EQ(result, 0);
	if (result != 0) {
		spine_socket_close(listener_fd);
		return;
	}

	client_fd = spine_socket_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_TRUE(spine_socket_is_valid(client_fd));
	if (!spine_socket_is_valid(client_fd)) {
		spine_socket_close(listener_fd);
		return;
	}

	result = spine_socket_connect(client_fd, (struct sockaddr *) &listener_addr, listener_len);
	ASSERT_INT_EQ(result, 0);
	if (result != 0) {
		spine_socket_close(client_fd);
		spine_socket_close(listener_fd);
		return;
	}

	accepted_len = (socklen_t) sizeof(accepted_addr);
	accepted_fd = accept(listener_fd, (struct sockaddr *) &accepted_addr, &accepted_len);
	ASSERT_TRUE(spine_socket_is_valid(accepted_fd));
	if (!spine_socket_is_valid(accepted_fd)) {
		spine_socket_close(client_fd);
		spine_socket_close(listener_fd);
		return;
	}

	ASSERT_INT_EQ(spine_socket_send(client_fd, message, strlen(message), 0), (int) strlen(message));
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	ASSERT_INT_EQ(spine_socket_wait_readable(accepted_fd, &timeout), 1);
	memset(buffer, 0, sizeof(buffer));
	result = spine_socket_recv(accepted_fd, buffer, sizeof(buffer) - 1, 0);
	ASSERT_INT_EQ(result, (int) strlen(message));
	if (result > 0) {
		buffer[result] = '\0';
		ASSERT_TRUE(strcmp(buffer, message) == 0);
	}

	ASSERT_INT_EQ(spine_socket_close(accepted_fd), 0);
	ASSERT_INT_EQ(spine_socket_close(client_fd), 0);
	ASSERT_INT_EQ(spine_socket_close(listener_fd), 0);
}

static void test_socket_ipv6_loopback_tcp(void) {
	spine_socket_t listener_fd;
	spine_socket_t client_fd;
	spine_socket_t accepted_fd;
	struct sockaddr_in6 listener_addr;
	struct sockaddr_in6 accepted_addr;
	struct timeval timeout;
	socklen_t listener_len;
	socklen_t accepted_len;
	char message[] = "ipv6-tcp";
	char buffer[32];
	int result;

	listener_fd = spine_socket_open(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_TRUE(spine_socket_is_valid(listener_fd));
	if (!spine_socket_is_valid(listener_fd)) {
		return;
	}

	result = bind_loopback_ipv6(listener_fd, &listener_addr, &listener_len);
	if (result != 0) {
		fprintf(stderr, "skipping ipv6 loopback socket test: bind() failed on this host\n");
		spine_socket_close(listener_fd);
		return;
	}

	result = listen(listener_fd, 1);
	ASSERT_INT_EQ(result, 0);
	if (result != 0) {
		spine_socket_close(listener_fd);
		return;
	}

	client_fd = spine_socket_open(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	ASSERT_TRUE(spine_socket_is_valid(client_fd));
	if (!spine_socket_is_valid(client_fd)) {
		spine_socket_close(listener_fd);
		return;
	}

	result = spine_socket_connect(client_fd, (struct sockaddr *) &listener_addr, listener_len);
	ASSERT_INT_EQ(result, 0);
	if (result != 0) {
		spine_socket_close(client_fd);
		spine_socket_close(listener_fd);
		return;
	}

	accepted_len = (socklen_t) sizeof(accepted_addr);
	accepted_fd = accept(listener_fd, (struct sockaddr *) &accepted_addr, &accepted_len);
	ASSERT_TRUE(spine_socket_is_valid(accepted_fd));

	if (spine_socket_is_valid(accepted_fd)) {
		ASSERT_INT_EQ(spine_socket_send(client_fd, message, strlen(message), 0), (int) strlen(message));
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		ASSERT_INT_EQ(spine_socket_wait_readable(accepted_fd, &timeout), 1);
		memset(buffer, 0, sizeof(buffer));
		result = spine_socket_recv(accepted_fd, buffer, sizeof(buffer) - 1, 0);
		ASSERT_INT_EQ(result, (int) strlen(message));
		if (result > 0) {
			buffer[result] = '\0';
			ASSERT_TRUE(strcmp(buffer, message) == 0);
		}
		ASSERT_INT_EQ(spine_socket_close(accepted_fd), 0);
	}
	ASSERT_INT_EQ(spine_socket_close(client_fd), 0);
	ASSERT_INT_EQ(spine_socket_close(listener_fd), 0);
}

static void test_socket_ipv4_loopback_udp(void) {
	spine_socket_t server_fd;
	spine_socket_t client_fd;
	struct sockaddr_in server_addr;
	struct sockaddr_in peer_addr;
	struct timeval timeout;
	socklen_t server_len;
	socklen_t peer_len;
	char message[] = "ipv4-udp";
	char buffer[32];
	int result;

	server_fd = spine_socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_TRUE(spine_socket_is_valid(server_fd));
	if (!spine_socket_is_valid(server_fd)) {
		return;
	}

	result = bind_loopback_ipv4(server_fd, &server_addr, &server_len);
	if (result != 0) {
		fprintf(stderr, "skipping ipv4 loopback udp test: bind() failed on this host\n");
		spine_socket_close(server_fd);
		return;
	}

	client_fd = spine_socket_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_TRUE(spine_socket_is_valid(client_fd));
	if (!spine_socket_is_valid(client_fd)) {
		spine_socket_close(server_fd);
		return;
	}

	ASSERT_INT_EQ(spine_socket_sendto(client_fd, message, strlen(message), 0, (struct sockaddr *) &server_addr, server_len), (int) strlen(message));
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	ASSERT_INT_EQ(spine_socket_wait_readable(server_fd, &timeout), 1);
	memset(buffer, 0, sizeof(buffer));
	peer_len = (socklen_t) sizeof(peer_addr);
	result = spine_socket_recvfrom(server_fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *) &peer_addr, &peer_len);
	ASSERT_INT_EQ(result, (int) strlen(message));
	if (result > 0) {
		buffer[result] = '\0';
		ASSERT_TRUE(strcmp(buffer, message) == 0);
	}

	ASSERT_INT_EQ(spine_socket_close(client_fd), 0);
	ASSERT_INT_EQ(spine_socket_close(server_fd), 0);
}

static void test_socket_ipv6_loopback_udp(void) {
	spine_socket_t server_fd;
	spine_socket_t client_fd;
	struct sockaddr_in6 server_addr;
	struct sockaddr_in6 peer_addr;
	struct timeval timeout;
	socklen_t server_len;
	socklen_t peer_len;
	char message[] = "ipv6-udp";
	char buffer[32];
	int result;

	server_fd = spine_socket_open(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_TRUE(spine_socket_is_valid(server_fd));
	if (!spine_socket_is_valid(server_fd)) {
		return;
	}

	result = bind_loopback_ipv6(server_fd, &server_addr, &server_len);
	if (result != 0) {
		fprintf(stderr, "skipping ipv6 udp loopback socket test: bind() failed on this host\n");
		spine_socket_close(server_fd);
		return;
	}

	client_fd = spine_socket_open(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	ASSERT_TRUE(spine_socket_is_valid(client_fd));
	if (!spine_socket_is_valid(client_fd)) {
		spine_socket_close(server_fd);
		return;
	}

	ASSERT_INT_EQ(spine_socket_sendto(client_fd, message, strlen(message), 0, (struct sockaddr *) &server_addr, server_len), (int) strlen(message));
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	ASSERT_INT_EQ(spine_socket_wait_readable(server_fd, &timeout), 1);
	memset(buffer, 0, sizeof(buffer));
	peer_len = (socklen_t) sizeof(peer_addr);
	result = spine_socket_recvfrom(server_fd, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *) &peer_addr, &peer_len);
	ASSERT_INT_EQ(result, (int) strlen(message));
	if (result > 0) {
		buffer[result] = '\0';
		ASSERT_TRUE(strcmp(buffer, message) == 0);
	}

	ASSERT_INT_EQ(spine_socket_close(client_fd), 0);
	ASSERT_INT_EQ(spine_socket_close(server_fd), 0);
}

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
	ASSERT_TRUE(spine_socket_error_is_host_unreachable(WSAEHOSTUNREACH));
	ASSERT_TRUE(spine_socket_error_is_host_unreachable(WSAENETUNREACH));
#else
	ASSERT_INT_EQ(spine_socket_ping_icmp_recv_flags(), MSG_WAITALL);
	ASSERT_INT_EQ(spine_socket_ping_tcp_supports_retries(), 1);
	ASSERT_INT_EQ(spine_socket_raw_icmp_needs_privileged_open(), 1);
	ASSERT_TRUE(spine_socket_error_is_host_unreachable(EHOSTUNREACH));
#ifdef ENETUNREACH
	ASSERT_TRUE(spine_socket_error_is_host_unreachable(ENETUNREACH));
#endif
#ifdef EHOSTDOWN
	ASSERT_TRUE(spine_socket_error_is_host_unreachable(EHOSTDOWN));
#endif
#endif
}

int main(void) {
	ASSERT_INT_EQ(spine_platform_init(), 0);
	test_socket_open_and_close();
	test_socket_ipv4_loopback_tcp();
	test_socket_ipv6_loopback_tcp();
	test_socket_ipv4_loopback_udp();
	test_socket_ipv6_loopback_udp();
	test_socket_invalid_wait_sets_error();
	test_ping_socket_platform_policy();
	spine_platform_cleanup();
	return finish_tests("platform socket tests");
}
