#include "platform_fd.h"

#ifndef _WIN32

#include <errno.h>
#include <sys/select.h>
#include <unistd.h>

ssize_t spine_fd_read(int fd, void *buffer, size_t buffer_len) {
	return read(fd, buffer, buffer_len);
}

ssize_t spine_fd_write(int fd, const void *buffer, size_t buffer_len) {
	return write(fd, buffer, buffer_len);
}

int spine_fd_wait_readable(int fd, struct timeval *timeout) {
	fd_set read_fds;

	if (fd < 0 || fd >= FD_SETSIZE) {
		errno = EINVAL;
		return -1;
	}

	FD_ZERO(&read_fds);
	FD_SET(fd, &read_fds);

	return select(fd + 1, &read_fds, NULL, NULL, timeout);
}

int spine_fd_last_error(void) {
	return errno;
}

int spine_fd_error_is_interrupted(int error_code) {
	return error_code == EINTR;
}

int spine_fd_error_is_badf(int error_code) {
	return error_code == EBADF;
}

int spine_fd_error_is_invalid(int error_code) {
	return error_code == EINVAL;
}

int spine_fd_error_is_nomem(int error_code) {
	return error_code == ENOMEM;
}

#endif
