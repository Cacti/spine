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
int spine_socket_send(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags);
int spine_socket_sendto(spine_socket_t socket_fd, const void *buffer, size_t buffer_len, int flags, const struct sockaddr *address, socklen_t address_len);
int spine_socket_recv(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags);
int spine_socket_recvfrom(spine_socket_t socket_fd, void *buffer, size_t buffer_len, int flags, struct sockaddr *address, socklen_t *address_len);
int spine_socket_set_timeout(spine_socket_t socket_fd, const struct timeval *timeout);
int spine_socket_wait_readable(spine_socket_t socket_fd, struct timeval *timeout);
int spine_socket_last_error(void);
int spine_socket_is_valid(spine_socket_t socket_fd);
int spine_socket_error_is_interrupted(int error_code);
int spine_socket_error_is_conn_refused(int error_code);
int spine_socket_error_is_conn_reset(int error_code);
int spine_socket_error_is_host_unreachable(int error_code);

#endif
