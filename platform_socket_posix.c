#include "platform_socket.h"

#ifndef _WIN32

#include <errno.h>

spine_socket_t spine_socket_open(int domain, int type, int protocol) {
	return socket(domain, type, protocol);
}

int spine_socket_close(spine_socket_t socket_fd) {
	return close(socket_fd);
}

int spine_socket_connect(spine_socket_t socket_fd, const struct sockaddr *address, socklen_t address_len) {
	return connect(socket_fd, address, address_len);
}

int spine_socket_send(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags) {
	return (int) send(socket_fd, buffer, buffer_len, flags);
}

int spine_socket_sendto(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags, const struct sockaddr *address, socklen_t address_len) {
	return (int) sendto(socket_fd, buffer, buffer_len, flags, address, address_len);
}

int spine_socket_recv(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags) {
	return (int) recv(socket_fd, buffer, buffer_len, flags);
}

int spine_socket_recvfrom(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags, struct sockaddr *address, socklen_t *address_len) {
	return (int) recvfrom(socket_fd, buffer, buffer_len, flags, address, address_len);
}

int spine_socket_set_timeout(spine_socket_t socket_fd, const struct timeval *timeout) {
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const void *) timeout, sizeof(*timeout)) != 0) {
		return -1;
	}

	if (setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const void *) timeout, sizeof(*timeout)) != 0) {
		return -1;
	}

	return 0;
}

int spine_socket_wait_readable(spine_socket_t socket_fd, struct timeval *timeout) {
	fd_set socket_fds;

	if (socket_fd < 0 || socket_fd >= FD_SETSIZE) {
		errno = EINVAL;
		return -1;
	}

	FD_ZERO(&socket_fds);
	FD_SET(socket_fd, &socket_fds);

	return select(socket_fd + 1, &socket_fds, NULL, NULL, timeout);
}

int spine_socket_last_error(void) {
	return errno;
}

int spine_socket_is_valid(spine_socket_t socket_fd) {
	return socket_fd != SPINE_INVALID_SOCKET_HANDLE;
}

int spine_socket_error_is_interrupted(int error_code) {
	return error_code == EINTR;
}

int spine_socket_error_is_conn_refused(int error_code) {
	return error_code == ECONNREFUSED;
}

int spine_socket_error_is_conn_reset(int error_code) {
	return error_code == ECONNRESET;
}

int spine_socket_error_is_host_unreachable(int error_code) {
	return error_code == EHOSTUNREACH;
}

int spine_socket_ping_icmp_recv_flags(void) {
	return MSG_WAITALL;
}

int spine_socket_ping_tcp_supports_retries(void) {
	return 1;
}

int spine_socket_raw_icmp_needs_privileged_open(void) {
	return 1;
}

#endif
