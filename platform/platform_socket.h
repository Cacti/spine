#ifndef SPINE_PLATFORM_SOCKET_H
#define SPINE_PLATFORM_SOCKET_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET spine_socket_t;
#define SPINE_INVALID_SOCKET_HANDLE INVALID_SOCKET
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int spine_socket_t;
#define SPINE_INVALID_SOCKET_HANDLE (-1)
#endif

spine_socket_t spine_socket_open(int domain, int type, int protocol);
int spine_socket_close(spine_socket_t socket_fd);
int spine_socket_connect(spine_socket_t socket_fd, const struct sockaddr *address, socklen_t address_len);
/* send/recv wrappers return -1 on error and set errno (POSIX) or WSAGetLastError (Windows). */
int spine_socket_send(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags);
int spine_socket_sendto(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags, const struct sockaddr *address, socklen_t address_len);
int spine_socket_recv(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags);
int spine_socket_recvfrom(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags, struct sockaddr *address, socklen_t *address_len);
/* timeout pointer must be non-NULL and normalized: tv_sec >= 0 and 0 <= tv_usec < 1000000. */
int spine_socket_set_timeout(spine_socket_t socket_fd, const struct timeval *timeout);
int spine_socket_wait_readable(spine_socket_t socket_fd, struct timeval *timeout);
int spine_socket_last_error(void);
int spine_socket_is_valid(spine_socket_t socket_fd);
int spine_socket_error_is_interrupted(int error_code);
int spine_socket_error_is_conn_refused(int error_code);
int spine_socket_error_is_conn_reset(int error_code);
int spine_socket_error_is_host_unreachable(int error_code);
int spine_socket_ping_icmp_recv_flags(void);
int spine_socket_ping_tcp_supports_retries(void);
int spine_socket_raw_icmp_needs_privileged_open(void);

#endif
