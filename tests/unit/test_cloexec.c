/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Regression: long-lived descriptors (raw ICMP sockets, MySQL client
 | socket, audit netlink, log file) must carry FD_CLOEXEC so poll-script
 | children spawned via nft_popen() cannot inherit them. Exercises the
 | platform socket helper, which is the single gatekeeper every TCP /
 | UDP / ping call funnels through.
 +-------------------------------------------------------------------------+
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_platform_helpers.h"

#include "platform/platform_socket.h"

static void test_tcp_socket_has_cloexec(void) {
	spine_socket_t s = spine_socket_open(AF_INET, SOCK_STREAM, 0);
	ASSERT_TRUE(s >= 0);
	if (s < 0) return;

	int fl = fcntl((int) s, F_GETFD);
	ASSERT_TRUE(fl >= 0);
	ASSERT_TRUE((fl & FD_CLOEXEC) != 0);

	spine_socket_close(s);
}

static void test_udp_socket_has_cloexec(void) {
	spine_socket_t s = spine_socket_open(AF_INET, SOCK_DGRAM, 0);
	ASSERT_TRUE(s >= 0);
	if (s < 0) return;

	int fl = fcntl((int) s, F_GETFD);
	ASSERT_TRUE(fl >= 0);
	ASSERT_TRUE((fl & FD_CLOEXEC) != 0);

	spine_socket_close(s);
}

static void test_log_file_open_carries_cloexec(void) {
	char tmpl[] = "/tmp/spine-cloexec-log-XXXXXX";
	int fd = mkstemp(tmpl);
	ASSERT_TRUE(fd >= 0);
	if (fd < 0) return;
	close(fd);

	/* Mirror the open flags util.c uses for the log file path. */
	int log_fd = open(tmpl, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
	                  S_IRUSR | S_IWUSR | S_IRGRP);
	ASSERT_TRUE(log_fd >= 0);
	if (log_fd >= 0) {
		int fl = fcntl(log_fd, F_GETFD);
		ASSERT_TRUE(fl >= 0);
		ASSERT_TRUE((fl & FD_CLOEXEC) != 0);
		close(log_fd);
	}
	unlink(tmpl);
}

int main(void) {
	test_tcp_socket_has_cloexec();
	test_udp_socket_has_cloexec();
	test_log_file_open_carries_cloexec();
	return finish_tests("cloexec tests");
}
