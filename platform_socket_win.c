#include "platform_socket.h"

#ifdef _WIN32

spine_socket_t spine_socket_open(int domain, int type, int protocol) {
	return socket(domain, type, protocol);
}

int spine_socket_close(spine_socket_t socket_fd) {
	return closesocket(socket_fd);
}

int spine_socket_connect(spine_socket_t socket_fd, const struct sockaddr *address, socklen_t address_len) {
	return connect(socket_fd, address, address_len);
}

int spine_socket_send(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags) {
	return send(socket_fd, (const char *) buffer, (int) buffer_len, flags);
}

int spine_socket_sendto(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags, const struct sockaddr *address, socklen_t address_len) {
	return sendto(socket_fd, (const char *) buffer, (int) buffer_len, flags, address, address_len);
}

int spine_socket_recv(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags) {
	return recv(socket_fd, (char *) buffer, (int) buffer_len, flags);
}

int spine_socket_recvfrom(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags, struct sockaddr *address, socklen_t *address_len) {
	int actual_len;
	int recv_result;

	actual_len = (int) *address_len;
	recv_result = recvfrom(socket_fd, (char *) buffer, (int) buffer_len, flags, address, &actual_len);
	*address_len = (socklen_t) actual_len;

	return recv_result;
}

int spine_socket_set_timeout(spine_socket_t socket_fd, const struct timeval *timeout) {
	DWORD timeout_ms;

	timeout_ms = (DWORD) (timeout->tv_sec * 1000U + timeout->tv_usec / 1000U);

	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *) &timeout_ms, sizeof(timeout_ms)) != 0) {
		return -1;
	}

	if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *) &timeout_ms, sizeof(timeout_ms)) != 0) {
		return -1;
	}

	return 0;
}

int spine_socket_wait_readable(spine_socket_t socket_fd, struct timeval *timeout) {
	fd_set socket_fds;

	if (socket_fd == INVALID_SOCKET) {
		WSASetLastError(WSAENOTSOCK);
		return -1;
	}

	FD_ZERO(&socket_fds);
	FD_SET(socket_fd, &socket_fds);

	return select(0, &socket_fds, NULL, NULL, timeout);
}

int spine_socket_last_error(void) {
	return WSAGetLastError();
}

int spine_socket_is_valid(spine_socket_t socket_fd) {
	return socket_fd != SPINE_INVALID_SOCKET_HANDLE;
}

int spine_socket_error_is_interrupted(int error_code) {
	return error_code == WSAEINTR;
}

int spine_socket_error_is_conn_refused(int error_code) {
	return error_code == WSAECONNREFUSED;
}

int spine_socket_error_is_conn_reset(int error_code) {
	return error_code == WSAECONNRESET;
}

int spine_socket_error_is_host_unreachable(int error_code) {
	return error_code == WSAEHOSTUNREACH;
}

int spine_socket_ping_icmp_recv_flags(void) {
	return 0;
}

int spine_socket_ping_tcp_supports_retries(void) {
	return 1;
}

int spine_socket_raw_icmp_needs_privileged_open(void) {
	return 0;
}

#endif
