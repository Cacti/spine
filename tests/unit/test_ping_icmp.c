/* ping_icmp() resource ownership.
 *
 * This is the least-tested and highest-consequence change in the branch: the
 * function runs in a SUID-root binary, and its five exits were collapsed onto
 * one cleanup label while the seteuid(0)/LOCK_SETEUID wrapper around close()
 * was removed. Nothing covered it.
 *
 * The live ICMP cases skip without raw-socket privilege. The ownership cases
 * use controlled socket and allocation sinks, so they run everywhere.
 *
 * The FD_SETSIZE case is the one that mattered: that exit closed the socket and
 * returned without freeing the packet (#593). A controlled descriptor reaches
 * that guard deterministically and lets the test observe the exact free.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include "common.h"
#include "spine.h"
#include "ping.h"

extern int *debug_devices;

static int pi_debug_table[100];
static int use_controlled_socket;
static int controlled_socket_fd;
static int controlled_socket_closed;
static int socket_failures_remaining;
static int socket_calls;
static int track_packet;
static size_t packet_size;
static void *packet_allocation;
static int packet_released;
static int controlled_pair[2] = {-1, -1};
static int resolver_mode;
static int resolver_calls;
static int freeaddrinfo_calls;
static int controlled_reply;
static uint16_t sent_icmp_id;
static uint16_t sent_icmp_seq;

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static void *intercepted_malloc(size_t size);
static void intercepted_free(void *ptr);
static int test_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res);
static void test_freeaddrinfo(struct addrinfo *res);
static ssize_t test_sendto(int fd, const void *buffer, size_t length, int flags,
	const struct sockaddr *address, socklen_t address_len);
static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout);
static ssize_t test_recvfrom(int fd, void *buffer, size_t length, int flags,
	struct sockaddr *address, socklen_t *address_len);

/* Compile the shipped implementation into this test translation unit so its
 * resource sinks can be observed without root or Linux-only linker wrapping. */
#define socket test_socket
#define close test_close
#define malloc intercepted_malloc
#define free intercepted_free
#define getaddrinfo test_getaddrinfo
#define freeaddrinfo test_freeaddrinfo
#define sendto test_sendto
#define select test_select
#define recvfrom test_recvfrom
#include "../../ping.c"
#undef socket
#undef close
#undef malloc
#undef free
#undef getaddrinfo
#undef freeaddrinfo
#undef sendto
#undef select
#undef recvfrom

static int test_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **res) {
	resolver_calls++;
	if (resolver_mode == 1) {
		*res = (struct addrinfo *)(uintptr_t) 1;
		return EAI_NONAME;
	}
	if (resolver_mode == 2) {
		*res = (struct addrinfo *)(uintptr_t) 1;
		return EAI_AGAIN;
	}

	return getaddrinfo(node, service, hints, res);
}

static void test_freeaddrinfo(struct addrinfo *res) {
	freeaddrinfo_calls++;
	freeaddrinfo(res);
}

static ssize_t test_sendto(int fd, const void *buffer, size_t length, int flags,
		const struct sockaddr *address, socklen_t address_len) {
	const struct icmp *request = buffer;

	if (!controlled_reply) {
		return sendto(fd, buffer, length, flags, address, address_len);
	}
	sent_icmp_id = request->icmp_id;
	sent_icmp_seq = request->icmp_seq;
	return (ssize_t) length;
}

static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	if (controlled_reply) {
		return 1;
	}
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

static ssize_t test_recvfrom(int fd, void *buffer, size_t length, int flags,
		struct sockaddr *address, socklen_t *address_len) {
	struct ip *ip_reply;
	struct icmp *icmp_reply;
	struct sockaddr_in *source;
	size_t reply_length = sizeof(struct ip) + sizeof(struct icmp);

	if (!controlled_reply) {
		return recvfrom(fd, buffer, length, flags, address, address_len);
	}
	assert_true(length >= reply_length);
	memset(buffer, 0, reply_length);
	ip_reply = buffer;
	ip_reply->ip_hl = sizeof(struct ip) >> 2;
	icmp_reply = (struct icmp *)((unsigned char *) buffer + sizeof(struct ip));
	icmp_reply->icmp_type = ICMP_ECHOREPLY;
	icmp_reply->icmp_id = sent_icmp_id;
	icmp_reply->icmp_seq = sent_icmp_seq;
	if (address != NULL && address_len != NULL && *address_len >= sizeof(*source)) {
		source = (struct sockaddr_in *) address;
		memset(source, 0, sizeof(*source));
		source->sin_family = AF_INET;
		source->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		*address_len = sizeof(*source);
	}
	return (ssize_t) reply_length;
}

static int test_socket(int domain, int type, int protocol) {
	socket_calls++;
	if (socket_failures_remaining > 0) {
		socket_failures_remaining--;
		errno = EPERM;
		return -1;
	}

	if (use_controlled_socket) {
		(void) domain;
		(void) type;
		(void) protocol;
		return controlled_socket_fd;
	}

	return socket(domain, type, protocol);
}

static int test_close(int fd) {
	if (use_controlled_socket && fd == controlled_socket_fd) {
		controlled_socket_closed++;
		return 0;
	}

	return close(fd);
}

static void *intercepted_malloc(size_t size) {
	void *ptr = malloc(size);

	if (track_packet && size == packet_size && packet_allocation == NULL) {
		packet_allocation = ptr;
	}

	return ptr;
}

static void intercepted_free(void *ptr) {
	if (track_packet && ptr != NULL && ptr == packet_allocation) {
		packet_released++;
	}

	free(ptr);
}

static void make_host(host_t *host, const char *addr) {
	memset(host, 0, sizeof(*host));
	host->id = 1;
	snprintf(host->hostname, sizeof(host->hostname), "%s", addr);
	host->ping_timeout = 400;
	host->ping_retries = 1;
	host->ping_port    = 33439;
	host->availability_method = AVAIL_PING;
	host->ping_method  = PING_ICMP;
}

static int ping_reset(void **state) {
	(void) state;
	config_defaults();
	/* ping_icmp() takes LOCK_SETEUID; pthread_once makes this idempotent */
	init_mutexes();
	/* is_debug_device() walks this global unguarded and ping_icmp() calls it */
	memset(pi_debug_table, 0, sizeof(pi_debug_table));
	debug_devices = pi_debug_table;
	set.ping_timeout = 400;
	set.ping_retries = 1;
	use_controlled_socket = 0;
	controlled_socket_fd = -1;
	controlled_socket_closed = 0;
	socket_failures_remaining = 0;
	socket_calls = 0;
	track_packet = 0;
	packet_size = ICMP_HDR_SIZE + strlen("cacti-monitoring-system");
	packet_allocation = NULL;
	packet_released = 0;
	set.icmp_uses_caps = FALSE;
	controlled_pair[0] = -1;
	controlled_pair[1] = -1;
	resolver_mode = 0;
	resolver_calls = 0;
	freeaddrinfo_calls = 0;
	controlled_reply = 0;
	sent_icmp_id = 0;
	sent_icmp_seq = 0;
	return 0;
}

static int ping_teardown(void **state) {
	(void) state;
	if (controlled_pair[0] != -1) {
		close(controlled_pair[0]);
	}
	if (controlled_pair[1] != -1) {
		close(controlled_pair[1]);
	}
	return 0;
}

static void use_owned_controlled_socket(void) {
	assert_int_equal(socketpair(AF_UNIX, SOCK_DGRAM, 0, controlled_pair), 0);
	use_controlled_socket = 1;
	controlled_socket_fd = controlled_pair[0];
}

/* The exit that leaked. A controlled socket result reaches the guard without
   requiring root or consuming the runner's descriptor table. Tracking the
   packet free makes this fail against the unfixed implementation. */
static void test_fd_setsize_guard_releases_the_packet(void **state) {
	host_t host;
	ping_t ping;
	int rc;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	track_packet = 1;

	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	rc = ping_icmp(&host, &ping);

	assert_int_equal(rc, HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "FD_SETSIZE"));
	assert_non_null(packet_allocation);
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_empty_address_releases_packet_and_socket(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = 42;
	track_packet = 1;
	make_host(&host, "");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "not specified"));
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_invalid_address_releases_packet_and_socket(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	track_packet = 1;
	resolver_mode = 1;
	make_host(&host, "invalid.invalid");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "hostname invalid"));
	assert_int_equal(resolver_calls, 1);
	assert_int_equal(freeaddrinfo_calls, 0);
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_timeout_releases_packet_and_socket(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	track_packet = 1;
	make_host(&host, "127.0.0.1");
	host.ping_timeout = 1;
	host.ping_retries = 0;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "timed out"));
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_temporary_resolver_failure_retries_four_times(void **state) {
	struct sockaddr_in address;

	(void) state;
	resolver_mode = 2;
	memset(&address, 0, sizeof(address));
	assert_false(init_sockaddr(&address, "ignored.example", 7));
	assert_int_equal(resolver_calls, 4);
	assert_int_equal(freeaddrinfo_calls, 0);
}

static void test_matching_reply_releases_resources(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	track_packet = 1;
	controlled_reply = 1;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_non_null(strstr(ping.ping_response, "Alive"));
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
	assert_int_equal(thread_mutex_trylock(LOCK_SETEUID), 0);
	thread_mutex_unlock(LOCK_SETEUID);
}

static void test_cached_capability_path_releases_resources(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	set.icmp_uses_caps = TRUE;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(geteuid(), getuid());
	assert_int_equal(thread_mutex_trylock(LOCK_SETEUID), 0);
	thread_mutex_unlock(LOCK_SETEUID);
}

static void test_socket_retry_can_succeed_after_one_failure(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	socket_failures_remaining = 1;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(socket_calls, 2);
	assert_int_equal(geteuid(), getuid());
	assert_int_equal(controlled_socket_closed, 1);
	assert_int_equal(thread_mutex_trylock(LOCK_SETEUID), 0);
	thread_mutex_unlock(LOCK_SETEUID);
}

/* The socket() retry used to sleep and loop back with LOCK_SETEUID still held,
   so attempt two relocked a non-recursive process-global mutex from its own
   owner. That wedges the thread at euid 0 and every other thread behind it.

   This runs exactly where the tests above skip: with no privilege, socket()
   fails with EPERM and the retry loop is what executes. An alarm turns the
   deadlock into a named failure instead of a CI job that hangs until the
   runner's own timeout kills it with nothing to read. */
static sigjmp_buf ping_deadlock_env;

static void ping_alarm(int sig) {
	(void) sig;
	siglongjmp(ping_deadlock_env, 1);
}

static void test_socket_retry_does_not_deadlock_on_seteuid(void **state) {
	struct sigaction sa, prev;
	host_t host;
	ping_t ping;
	int rc;

	(void) state;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = ping_alarm;
	sigemptyset(&sa.sa_mask);
	assert_int_equal(sigaction(SIGALRM, &sa, &prev), 0);

	if (sigsetjmp(ping_deadlock_env, 1) != 0) {
		alarm(0);
		sigaction(SIGALRM, &prev, NULL);
		fail_msg("ping_icmp() blocked in the socket() retry; LOCK_SETEUID was held across the sleep");
	}

	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));
	socket_failures_remaining = 5;

	/* five attempts at 500ms is about 2s; 15 leaves room on a loaded runner */
	alarm(15);
	rc = ping_icmp(&host, &ping);
	alarm(0);
	sigaction(SIGALRM, &prev, NULL);

	/* it gave up rather than hanging, and said why */
	assert_int_equal(rc, HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "ICMP Socket"));

	/* Keep the alarm armed for the probe, and never block on a leaked lock. */
	assert_int_equal(thread_mutex_trylock(LOCK_SETEUID), 0);
	thread_mutex_unlock(LOCK_SETEUID);

}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_fd_setsize_guard_releases_the_packet, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_empty_address_releases_packet_and_socket, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_invalid_address_releases_packet_and_socket, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_timeout_releases_packet_and_socket, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_temporary_resolver_failure_retries_four_times, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_matching_reply_releases_resources, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_cached_capability_path_releases_resources, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_socket_retry_can_succeed_after_one_failure, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_socket_retry_does_not_deadlock_on_seteuid, ping_reset, ping_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
