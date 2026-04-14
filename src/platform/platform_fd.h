#ifndef SPINE_PLATFORM_FD_H
#define SPINE_PLATFORM_FD_H

#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>

ssize_t spine_fd_read(int fd, void *buffer, size_t buffer_len);
ssize_t spine_fd_write(int fd, const void *buffer, size_t buffer_len);
/* timeout must be non-NULL and normalized: tv_sec >= 0 and 0 <= tv_usec < 1000000. */
int spine_fd_wait_readable(int fd, struct timeval *timeout);
int spine_fd_last_error(void);
int spine_fd_error_is_interrupted(int error_code);
int spine_fd_error_is_badf(int error_code);
int spine_fd_error_is_invalid(int error_code);
int spine_fd_error_is_nomem(int error_code);

#endif
