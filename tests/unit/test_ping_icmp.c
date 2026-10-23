/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* ping_icmp() resource ownership and the shared raw socket.
 *
 * The function runs in a SUID-root binary, and its five exits were collapsed
 * onto one cleanup label while the seteuid(0) wrapper around close() was
 * removed. Root is now dropped at startup and a setuid install without
 * capabilities pings through raw sockets opened before the drop, which every
 * poller thread shares.
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
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>

#include "internal/common.h"
#include "app/spine.h"
#include "ping/ping.h"
#include "tests/support/child_run.h"

extern int *debug_devices;

static int pi_debug_table[100];
static int use_controlled_socket;
static int controlled_socket_fd;
static int controlled_socket_type;
static int controlled_socket_closed;
static int controlled_socket_cloexec;
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
static int reply_seq_override;
static uint16_t reply_queue[8];
static int reply_queue_len;
static int reply_queue_pos;
static uint16_t reply_seq;
static int recvfrom_calls;
static int recvfrom_eintr_once;
static int controlled_reply_v6;
static int wrong_v6_source_octet;
static int socket_cloexec_einval;
static int fcntl_fails;
static size_t reply_v6_count;
static int check_wrong_peer;
static int select_eintr_once;
static int select_times_out;
static int fail_packet_allocation;
static int reply_defect;
static int sendto_fails_once;
static int getifaddrs_mode;
static struct addrinfo *fake_hostinfo;

enum {
	DEFECT_NONE,
	DEFECT_WRONG_SEQUENCE,
	DEFECT_NOT_AN_ECHO_REPLY,
	DEFECT_OTHER_PEER
};

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static int test_fcntl(int fd, int command, int argument);
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
static int test_getifaddrs(struct ifaddrs **list);
static void test_freeifaddrs(struct ifaddrs *list);

/* Compile the shipped implementation into this test translation unit so its
 * resource sinks can be observed without root or Linux-only linker wrapping. */
#define socket test_socket
#define close test_close
#define fcntl test_fcntl
#define malloc intercepted_malloc
#define free intercepted_free
#define getaddrinfo test_getaddrinfo
#define freeaddrinfo test_freeaddrinfo
#define sendto test_sendto
#define select test_select
#define recvfrom test_recvfrom
#define getifaddrs test_getifaddrs
#define freeifaddrs test_freeifaddrs
#include "../../src/poller/availability.c"
#include "../../src/ping/icmp_shared.c"
#include "../../src/ping/icmp4.c"
#include "../../src/ping/icmp6.c"
#include "../../src/ping/udp.c"
#include "../../src/ping/tcp.c"
#include "../../src/ping/address.c"

#undef socket
#undef close
#undef fcntl
#undef malloc
#undef free
#undef getaddrinfo
#undef freeaddrinfo
#undef sendto
#undef select
#undef recvfrom
#undef getifaddrs
#undef freeifaddrs

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
	/* resolution succeeds but yields nothing */
	if (resolver_mode == 3) {
		*res = NULL;
		return 0;
	}
	/* resolution succeeds with a caller-supplied list */
	if (resolver_mode == 4) {
		*res = fake_hostinfo;
		return 0;
	}

	return getaddrinfo(node, service, hints, res);
}

static void test_freeaddrinfo(struct addrinfo *res) {
	freeaddrinfo_calls++;
	if (resolver_mode == 4 && res == fake_hostinfo) return;
	freeaddrinfo(res);
}

/* An interface list of the shapes apply_ipv6_scope_id() has to skip, ending in
 * a usable one. The names are looked up for real by if_nametoindex(). */
static struct ifaddrs fake_interfaces[5];
static struct sockaddr_in fake_ipv4_address;
static struct sockaddr_in6 fake_ipv6_address;

static int test_getifaddrs(struct ifaddrs **list) {
	if (getifaddrs_mode == 0) return getifaddrs(list);
	if (getifaddrs_mode == 1) {
		errno = ENOMEM;
		return -1;
	}
	memset(fake_interfaces, 0, sizeof(fake_interfaces));
	fake_ipv4_address.sin_family = AF_INET;
	fake_ipv6_address.sin6_family = AF_INET6;
	fake_interfaces[0].ifa_name = (char *) "lo";
	fake_interfaces[0].ifa_next = &fake_interfaces[1];
	fake_interfaces[1].ifa_name = (char *) "lo";
	fake_interfaces[1].ifa_addr = (struct sockaddr *) &fake_ipv4_address;
	fake_interfaces[1].ifa_next = &fake_interfaces[2];
	fake_interfaces[2].ifa_name = (char *) "lo";
	fake_interfaces[2].ifa_addr = (struct sockaddr *) &fake_ipv6_address;
	fake_interfaces[2].ifa_flags = IFF_LOOPBACK;
	fake_interfaces[2].ifa_next = &fake_interfaces[3];
	fake_interfaces[3].ifa_name = (char *) "spine-no-such-if";
	fake_interfaces[3].ifa_addr = (struct sockaddr *) &fake_ipv6_address;
	fake_interfaces[3].ifa_next = &fake_interfaces[4];
	fake_interfaces[4].ifa_name = (char *) "lo";
	fake_interfaces[4].ifa_addr = (struct sockaddr *) &fake_ipv6_address;
	*list = &fake_interfaces[0];
	return 0;
}

static void test_freeifaddrs(struct ifaddrs *list) {
	if (getifaddrs_mode == 2) return;
	freeifaddrs(list);
}

static ssize_t test_sendto(int fd, const void *buffer, size_t length, int flags,
		const struct sockaddr *address, socklen_t address_len) {
	const struct icmp *request = buffer;

	if (!controlled_reply) {
		return sendto(fd, buffer, length, flags, address, address_len);
	}
	if (sendto_fails_once) {
		sendto_fails_once = 0;
		errno = EIO;
		return -1;
	}
#ifdef SPINE_HAVE_ICMPV6
	if (controlled_reply_v6) {
		const struct icmp6_hdr *request6 = buffer;
		sent_icmp_id = request6->icmp6_id;
		sent_icmp_seq = request6->icmp6_seq;
	} else
#endif
	{
		sent_icmp_id = request->icmp_id;
		sent_icmp_seq = request->icmp_seq;
	}
	return (ssize_t) length;
}

static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	if (controlled_reply) {
		if (select_eintr_once) {
			select_eintr_once = 0;
			errno = EINTR;
			return -1;
		}
		return select_times_out ? 0 : 1;
	}
	return select(nfds, readfds, writefds, exceptfds, timeout);
}

static ssize_t test_recvfrom(int fd, void *buffer, size_t length, int flags,
		struct sockaddr *address, socklen_t *address_len) {
	struct ip *ip_reply;
	struct icmp *icmp_reply;
	struct sockaddr_in *source;
	size_t ip_length = controlled_socket_type == SOCK_DGRAM ? 0 : sizeof(struct ip);
	size_t reply_length = ip_length + sizeof(struct icmp);

	if (!controlled_reply) {
		return recvfrom(fd, buffer, length, flags, address, address_len);
	}
	recvfrom_calls++;
	if (recvfrom_eintr_once) {
		recvfrom_eintr_once = 0;
		errno = EINTR;
		return -1;
	}
#ifdef SPINE_HAVE_ICMPV6
	if (controlled_reply_v6) {
		const char payload[] = "cacti-monitoring-system";
		struct icmp6_hdr *reply6 = buffer;
		struct sockaddr_in6 *source6 = (struct sockaddr_in6 *) address;
		size_t response_length = sizeof(*reply6) + sizeof(payload) - 1;

		assert_true(length >= response_length);
		assert_non_null(address);
		assert_non_null(address_len);
		assert_true(*address_len >= sizeof(*source6));
		if (check_wrong_peer) assert_true(reply_v6_count <= sizeof(source6->sin6_addr.s6_addr));
		memset(buffer, 0, response_length);
		reply6->icmp6_type = ICMP6_ECHO_REPLY;
		reply6->icmp6_id = check_wrong_peer && controlled_socket_type == SOCK_DGRAM ? sent_icmp_id ^ htons(0x100) : sent_icmp_id;
		reply6->icmp6_seq = sent_icmp_seq;
		if (reply_defect == DEFECT_WRONG_SEQUENCE) {
			reply_defect = DEFECT_NONE;
			reply6->icmp6_seq ^= htons(0x100);
		}
		memcpy((unsigned char *) buffer + sizeof(*reply6), payload, sizeof(payload) - 1);
		memset(source6, 0, sizeof(*source6));
		source6->sin6_family = AF_INET6;
		source6->sin6_addr = in6addr_loopback;
		if (wrong_v6_source_octet >= 0 && (size_t) wrong_v6_source_octet < sizeof(source6->sin6_addr.s6_addr)) {
			source6->sin6_addr.s6_addr[wrong_v6_source_octet++] ^= 0x80;
		}
		/* Queue one wrong source for every address octet, then the real peer. */
		if (check_wrong_peer && reply_v6_count < sizeof(source6->sin6_addr.s6_addr)) {
			source6->sin6_addr.s6_addr[reply_v6_count] ^= 0x80;
		}
		reply_v6_count++;
		*address_len = sizeof(*source6);
		return (ssize_t) response_length;
	}
#endif
	/* A finite queue ends the way a drained non-blocking socket does. */
	if (reply_queue_len > 0 && reply_queue_pos >= reply_queue_len) {
		errno = EAGAIN;
		return -1;
	}
	assert_true(length >= reply_length);
	memset(buffer, 0, reply_length);
	if (ip_length != 0) {
		ip_reply = buffer;
		ip_reply->ip_v = 4;
		ip_reply->ip_hl = sizeof(struct ip) >> 2;
		ip_reply->ip_p = IPPROTO_ICMP;
	}
	icmp_reply = (struct icmp *)((unsigned char *) buffer + ip_length);
	icmp_reply->icmp_type = ICMP_ECHOREPLY;
	icmp_reply->icmp_id = sent_icmp_id;
	if (reply_queue_len > 0) {
		icmp_reply->icmp_seq = reply_queue[reply_queue_pos++];
	} else {
		icmp_reply->icmp_seq = reply_seq_override ? reply_seq : sent_icmp_seq;
	}
	if (address != NULL && address_len != NULL && *address_len >= sizeof(*source)) {
		source = (struct sockaddr_in *) address;
		memset(source, 0, sizeof(*source));
		source->sin_family = AF_INET;
		source->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		*address_len = sizeof(*source);
		if (reply_defect == DEFECT_OTHER_PEER) {
			reply_defect = DEFECT_NONE;
			source->sin_addr.s_addr = htonl(INADDR_LOOPBACK + 1);
		}
	}
	if (reply_defect == DEFECT_WRONG_SEQUENCE) {
		reply_defect = DEFECT_NONE;
		icmp_reply->icmp_seq = (uint16_t) (icmp_reply->icmp_seq + 1000);
	} else if (reply_defect == DEFECT_NOT_AN_ECHO_REPLY) {
		reply_defect = DEFECT_NONE;
		/* destination unreachable; the wire value is not portable by name */
		icmp_reply->icmp_type = 3;
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
		(void) protocol;
		#ifdef SOCK_CLOEXEC
		/* A kernel too old for SOCK_CLOEXEC rejects the flag. */
		if ((type & SOCK_CLOEXEC) && socket_cloexec_einval) {
			errno = EINVAL;
			return -1;
		}
		if (type & SOCK_CLOEXEC) {
			controlled_socket_cloexec = 1;
			type &= ~SOCK_CLOEXEC;
		}
		#endif
		controlled_socket_type = type;
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

static int test_fcntl(int fd, int command, int argument) {
	if (use_controlled_socket && fd == controlled_socket_fd) {
		if (fcntl_fails) {
			errno = EBADF;
			return -1;
		}
		if (command == F_SETFD && (argument & FD_CLOEXEC)) {
			controlled_socket_cloexec = 1;
		}
		return 0;
	}

	return fcntl(fd, command, argument);
}

static void *intercepted_malloc(size_t size) {
	void *ptr;

	if (fail_packet_allocation && size == packet_size) {
		fail_packet_allocation = 0;
		return NULL;
	}
	ptr = malloc(size);

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
	host->availability.timeout = 400;
	host->availability.retries = 1;
	host->availability.port    = 33439;
	host->availability.method = AVAIL_PING;
	host->availability.ping_method  = PING_ICMP;
}

static int ping_reset(void **state) {
	(void) state;
	config_defaults();
	/* ping_icmp() takes LOCK_SETEUID; pthread_once makes this idempotent */
	init_mutexes();
	/* is_debug_device() walks this global unguarded and ping_icmp() calls it */
	memset(pi_debug_table, 0, sizeof(pi_debug_table));
	debug_devices = pi_debug_table;
	set.availability.ping_timeout = 400;
	set.availability.ping_retries = 1;
	use_controlled_socket = 0;
	controlled_socket_fd = -1;
	controlled_socket_type = 0;
	controlled_socket_closed = 0;
	controlled_socket_cloexec = 0;
	socket_failures_remaining = 0;
	socket_calls = 0;
	track_packet = 0;
	packet_size = ICMP_HDR_SIZE + strlen("cacti-monitoring-system");
	packet_allocation = NULL;
	packet_released = 0;
	set.availability.icmp_uses_caps = FALSE;
	controlled_pair[0] = -1;
	controlled_pair[1] = -1;
	resolver_mode = 0;
	resolver_calls = 0;
	freeaddrinfo_calls = 0;
	controlled_reply = 0;
	sent_icmp_id = 0;
	sent_icmp_seq = 0;
	reply_seq_override = 0;
	reply_queue_len = 0;
	reply_queue_pos = 0;
	reply_seq = 0;
	recvfrom_calls = 0;
	icmp_shared.fd = -1;
	icmp_shared.reading = FALSE;
	icmp6_shared.fd = -1;
	icmp6_shared.reading = FALSE;
	recvfrom_eintr_once = 0;
	controlled_reply_v6 = 0;
	wrong_v6_source_octet = -1;
	socket_cloexec_einval = 0;
	fcntl_fails = 0;
	icmp_waiters = NULL;
	reply_v6_count = 0;
	check_wrong_peer = 0;
	select_eintr_once = 0;
	select_times_out = 0;
	fail_packet_allocation = 0;
	reply_defect = DEFECT_NONE;
	sendto_fails_once = 0;
	getifaddrs_mode = 0;
	fake_hostinfo = NULL;
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
	host.availability.timeout = 1;
	host.availability.retries = 0;
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
	assert_int_equal(thread_mutex_trylock(LOCK_ICMP), 0);
	thread_mutex_unlock(LOCK_ICMP);
}

static void test_cached_capability_path_releases_resources(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	set.availability.icmp_uses_caps = TRUE;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(geteuid(), getuid());
	assert_int_equal(thread_mutex_trylock(LOCK_ICMP), 0);
	thread_mutex_unlock(LOCK_ICMP);
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
	assert_int_equal(thread_mutex_trylock(LOCK_ICMP), 0);
	thread_mutex_unlock(LOCK_ICMP);
}

/* The socket() retry used to sleep and loop back with the seteuid lock still
   held, so attempt two relocked a non-recursive process-global mutex from its
   own owner. That wedged the thread at euid 0 and every other thread behind it.
   The elevation is gone; the retry must still give up rather than hang.

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
		fail_msg("ping_icmp() blocked in the socket() retry");
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
	assert_int_equal(thread_mutex_trylock(LOCK_ICMP), 0);
	thread_mutex_unlock(LOCK_ICMP);

}

/* A setuid install without capabilities pings through the socket opened before
   root was dropped. It must not try for a raw socket of its own, which would
   fail, and must leave the shared socket open for the next caller. */
static void test_shared_socket_answers_without_a_socket_of_its_own(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	use_controlled_socket = 0;
	socket_failures_remaining = 1;
	controlled_reply = 1;
	track_packet = 1;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_true(ping_icmp_shared_available());
	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_non_null(strstr(ping.ping_response, "Alive"));
	assert_int_equal(socket_calls, 1);
	assert_int_equal(controlled_socket_closed, 0);
	assert_int_equal(packet_released, 1);
	assert_null(icmp_waiters);
	assert_int_equal(geteuid(), getuid());
	assert_int_equal(thread_mutex_trylock(LOCK_ICMP), 0);
	thread_mutex_unlock(LOCK_ICMP);
}

static void test_shared_socket_timeout_unregisters(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	use_controlled_socket = 0;
	socket_failures_remaining = 1;
	make_host(&host, "127.0.0.1");
	host.availability.timeout = 50;
	host.availability.retries = 1;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "timed out"));
	assert_int_equal(controlled_socket_closed, 0);
	assert_null(icmp_waiters);
}

static void make_waiter(icmp_waiter_t *waiter, uint16_t seq) {
	memset(waiter, 0, sizeof(*waiter));
	waiter->shared      = &icmp_shared;
	waiter->family      = AF_INET;
	waiter->id          = (uint16_t) (getpid() & 0xFFFF);
	waiter->seq         = seq;
	waiter->peer.s_addr = htonl(INADDR_LOOPBACK);
}

/* One raw socket queues each reply once. Whoever reads a reply that answers
   another thread's request must hand it over, or that device goes down. */
static void test_shared_reply_for_another_waiter_is_handed_over(void **state) {
	icmp_waiter_t mine;
	icmp_waiter_t theirs;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	controlled_reply = 1;
	reply_seq_override = 1;
	reply_seq = 77;
	sent_icmp_id = (uint16_t) (getpid() & 0xFFFF);
	make_waiter(&mine, 5);
	make_waiter(&theirs, 77);
	icmp_shared_register(&theirs);
	icmp_shared_register(&mine);

	assert_false(icmp_shared_await(&mine, get_time_as_double() + 0.05));
	assert_true(theirs.answered);
	assert_false(mine.answered);
	assert_true(recvfrom_calls > 0);

	icmp_shared_unregister(&mine);
	icmp_shared_unregister(&theirs);
	assert_null(icmp_waiters);
	assert_false(icmp_shared.reading);
}

static void *answer_waiter(void *argument) {
	icmp_waiter_t *waiter = argument;

	usleep(20000);
	thread_mutex_lock(LOCK_ICMP);
	waiter->answered = TRUE;
	pthread_cond_signal(&waiter->wake);
	thread_mutex_unlock(LOCK_ICMP);
	return NULL;
}

/* While another thread reads, a waiter sleeps on the condition variable and
   never touches the socket; the reader's hand-over wakes it. */
static void test_shared_waiter_does_not_read_while_another_thread_does(void **state) {
	icmp_waiter_t mine;
	pthread_t reader;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	controlled_reply = 1;
	make_waiter(&mine, 9);
	icmp_shared_register(&mine);
	icmp_shared.reading = TRUE;

	assert_int_equal(pthread_create(&reader, NULL, answer_waiter, &mine), 0);
	assert_true(icmp_shared_await(&mine, get_time_as_double() + 2.0));
	assert_int_equal(pthread_join(reader, NULL), 0);
	assert_int_equal(recvfrom_calls, 0);

	icmp_shared.reading = FALSE;
	icmp_shared_unregister(&mine);
}

/* Under a flood one reply per lock cycle falls behind the queue. A reader must
   empty everything that is waiting and answer every waiter it finds. */
static void test_shared_reader_drains_the_queue(void **state) {
	icmp_waiter_t mine;
	icmp_waiter_t others[3];

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	controlled_reply = 1;
	sent_icmp_id = (uint16_t) (getpid() & 0xFFFF);
	for (int i = 0; i < 3; i++) {
		make_waiter(&others[i], (uint16_t) (100 + i));
		icmp_shared_register(&others[i]);
		reply_queue[i] = (uint16_t) (100 + i);
	}
	reply_queue[3] = 9;
	reply_queue_len = 4;
	make_waiter(&mine, 9);
	icmp_shared_register(&mine);

	assert_true(icmp_shared_await(&mine, get_time_as_double() + 1.0));
	for (int i = 0; i < 3; i++) {
		assert_true(others[i].answered);
		icmp_shared_unregister(&others[i]);
	}
	/* one pass: four replies, then the empty queue */
	assert_int_equal(recvfrom_calls, 5);
	icmp_shared_unregister(&mine);
	assert_null(icmp_waiters);
}

static void *release_reader(void *argument) {
	icmp_shared_t *shared = argument;

	usleep(20000);
	thread_mutex_lock(LOCK_ICMP);
	shared->reading = FALSE;
	icmp_shared_handoff(shared);
	thread_mutex_unlock(LOCK_ICMP);
	return NULL;
}

/* With per-waiter wakeups, a reader that leaves must hand the socket to a
   sleeping waiter, or that waiter sleeps through its own reply. */
static void test_shared_reader_hands_over_on_leaving(void **state) {
	icmp_waiter_t mine;
	pthread_t reader;
	double begin;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	controlled_reply = 1;
	sent_icmp_id = (uint16_t) (getpid() & 0xFFFF);
	reply_queue[0] = 11;
	reply_queue_len = 1;
	make_waiter(&mine, 11);
	icmp_shared_register(&mine);
	icmp_shared.reading = TRUE;

	begin = get_time_as_double();
	assert_int_equal(pthread_create(&reader, NULL, release_reader, &icmp_shared), 0);
	assert_true(icmp_shared_await(&mine, begin + 5.0));
	assert_int_equal(pthread_join(reader, NULL), 0);
	assert_true(get_time_as_double() - begin < 2.0);
	assert_false(icmp_shared.reading);
	icmp_shared_unregister(&mine);
}

/* Poller threads spawn scripts while others ping, so a per-ping socket must
   be close-on-exec from the start or a script can inherit raw ICMP access. */
static void test_per_ping_sockets_are_close_on_exec(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	make_host(&host, "127.0.0.1");
	host.availability.timeout = 1;
	host.availability.retries = 0;

	/* datagram socket */
	memset(&ping, 0, sizeof(ping));
	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(controlled_socket_type, SOCK_DGRAM);
	assert_int_equal(controlled_socket_cloexec, 1);

	/* raw socket after the datagram one is refused */
	controlled_socket_cloexec = 0;
	socket_failures_remaining = 1;
	memset(&ping, 0, sizeof(ping));
	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(controlled_socket_type, SOCK_RAW);
	assert_int_equal(controlled_socket_cloexec, 1);
}

static void test_icmp6_reply_matching(void **state) {
	unsigned char reply[sizeof(struct icmp6_hdr) + sizeof(icmp6_payload)];
	struct icmp6_hdr *header = (struct icmp6_hdr *) reply;
	ssize_t length = (ssize_t) (sizeof(*header) + sizeof(icmp6_payload) - 1);

	(void) state;
	memset(reply, 0, sizeof(reply));
	header->icmp6_type = ICMP6_ECHO_REPLY;
	header->icmp6_id = htons(7);
	header->icmp6_seq = htons(9);
	memcpy(reply + sizeof(*header), icmp6_payload, sizeof(icmp6_payload) - 1);

	assert_true(icmp6_reply_matches(reply, length, htons(7), htons(9), TRUE));
	assert_false(icmp6_reply_matches(reply, -1, htons(7), htons(9), TRUE));
	assert_false(icmp6_reply_matches(reply, length - 1, htons(7), htons(9), TRUE));
	assert_false(icmp6_reply_matches(reply, length, htons(7), htons(8), TRUE));
	/* a datagram socket rewrites the id, so only the raw path checks it */
	assert_false(icmp6_reply_matches(reply, length, htons(6), htons(9), TRUE));
	assert_true(icmp6_reply_matches(reply, length, htons(6), htons(9), FALSE));
	header->icmp6_type = ICMP6_ECHO_REQUEST;
	assert_false(icmp6_reply_matches(reply, length, htons(7), htons(9), TRUE));
	header->icmp6_type = ICMP6_ECHO_REPLY;
	reply[sizeof(*header)] ^= 1;
	assert_false(icmp6_reply_matches(reply, length, htons(7), htons(9), TRUE));
}

/* Where SOCK_CLOEXEC is missing or refused, fcntl() sets the flag, and a
   socket whose flag cannot be set is closed rather than handed out. */
static void test_open_socket_fcntl_fallback(void **state) {
	(void) state;
	use_owned_controlled_socket();
	socket_cloexec_einval = 1;

	assert_int_equal(icmp_open_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), controlled_socket_fd);
	assert_int_equal(controlled_socket_cloexec, 1);
	assert_int_equal(controlled_socket_closed, 0);

	fcntl_fails = 1;
	assert_int_equal(icmp_open_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), -1);
	assert_int_equal(controlled_socket_closed, 1);
}

/* drop_privileges() calls this once, as root, before anything else runs. */
static void test_open_shared_sockets(void **state) {
	(void) state;
	use_owned_controlled_socket();
	assert_false(ping_icmp_shared_available());
	assert_true(ping_icmp_open_shared());
	assert_true(ping_icmp_shared_available());
	assert_int_equal(icmp_shared.fd, controlled_socket_fd);
	assert_int_equal(icmp6_shared.fd, controlled_socket_fd);
	assert_int_equal(controlled_socket_type, SOCK_RAW);
	assert_int_equal(controlled_socket_cloexec, 1);
	/* opening twice keeps the sockets already open */
	socket_calls = 0;
	assert_true(ping_icmp_open_shared());
	assert_int_equal(socket_calls, 0);
	assert_int_equal(controlled_socket_closed, 0);
}

static void test_open_shared_sockets_failures(void **state) {
	(void) state;
	socket_failures_remaining = 2;
	assert_false(ping_icmp_open_shared());
	assert_int_equal(icmp6_shared.fd, -1);

	/* select() cannot watch a descriptor this high, so it is not kept */
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	assert_false(ping_icmp_open_shared());
	assert_int_equal(controlled_socket_closed, 2);
	assert_int_equal(icmp_shared.fd, -1);
}

static void test_shared_dispatch_ipv6(void **state) {
	icmp_waiter_t waiter;
	unsigned char reply[sizeof(struct icmp6_hdr) + sizeof(icmp6_payload)];
	struct icmp6_hdr *header = (struct icmp6_hdr *) reply;
	struct sockaddr_storage from;
	struct sockaddr_in6 *source = (struct sockaddr_in6 *) &from;
	ssize_t length = (ssize_t) (sizeof(*header) + sizeof(icmp6_payload) - 1);

	(void) state;
	memset(&waiter, 0, sizeof(waiter));
	waiter.shared = &icmp6_shared;
	waiter.family = AF_INET6;
	waiter.id     = htons(3);
	waiter.seq    = htons(4);
	waiter.peer6  = in6addr_loopback;
	icmp_shared_register(&waiter);

	memset(reply, 0, sizeof(reply));
	header->icmp6_type = ICMP6_ECHO_REPLY;
	header->icmp6_id = htons(3);
	header->icmp6_seq = htons(4);
	memcpy(reply + sizeof(*header), icmp6_payload, sizeof(icmp6_payload) - 1);
	memset(&from, 0, sizeof(from));
	source->sin6_family = AF_INET6;

	/* right message, wrong source */
	thread_mutex_lock(LOCK_ICMP);
	icmp_shared_dispatch(AF_INET6, reply, length, &from);
	assert_false(waiter.answered);
	/* an IPv4 reply never answers an IPv6 request */
	icmp_shared_dispatch(AF_INET, reply, length, &from);
	assert_false(waiter.answered);
	source->sin6_addr = in6addr_loopback;
	header->icmp6_seq = htons(5);
	icmp_shared_dispatch(AF_INET6, reply, length, &from);
	assert_false(waiter.answered);
	header->icmp6_seq = htons(4);
	/* Every address octet participates in peer identity; struct padding does not. */
	for (size_t octet = 0; octet < sizeof(source->sin6_addr.s6_addr); octet++) {
		source->sin6_addr.s6_addr[octet] ^= 0x80;
		icmp_shared_dispatch(AF_INET6, reply, length, &from);
		assert_false(waiter.answered);
		source->sin6_addr.s6_addr[octet] ^= 0x80;
	}
	icmp_shared_dispatch(AF_INET6, reply, length, &from);
	assert_true(waiter.answered);
	thread_mutex_unlock(LOCK_ICMP);

	icmp_shared_unregister(&waiter);
}

/* A signal during the drain must not end it or lose the reply behind it. */
static void test_shared_drain_retries_after_eintr(void **state) {
	icmp_waiter_t mine;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	controlled_reply = 1;
	recvfrom_eintr_once = 1;
	sent_icmp_id = (uint16_t) (getpid() & 0xFFFF);
	reply_queue[0] = 21;
	reply_queue_len = 1;
	make_waiter(&mine, 21);
	icmp_shared_register(&mine);

	assert_true(icmp_shared_await(&mine, get_time_as_double() + 1.0));
	/* interrupted, the reply, then the empty queue */
	assert_int_equal(recvfrom_calls, 3);
	icmp_shared_unregister(&mine);
}

static void test_shared_socket_debug_device(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	icmp_shared.fd = controlled_pair[0];
	use_controlled_socket = 0;
	socket_failures_remaining = 1;
	controlled_reply = 1;
	make_host(&host, "127.0.0.1");
	pi_debug_table[0] = host.id;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_null(icmp_waiters);
}

static void make_host6(host_t *host) {
	make_host(host, "::1");
}

/* A setuid install pings IPv6 devices through the shared ICMPv6 socket. */
static void test_ipv6_shared_socket_answers(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	icmp6_shared.fd = controlled_pair[0];
	use_controlled_socket = 0;
	socket_failures_remaining = 1;
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	track_packet = 1;
	packet_size = sizeof(struct icmp6_hdr) + sizeof(icmp6_payload) - 1;
	make_host6(&host);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
	assert_int_equal(socket_calls, 1);
	assert_int_equal(controlled_socket_closed, 0);
	assert_int_equal(packet_released, 1);
	assert_null(icmp_waiters);

	/* and as a debug device */
	pi_debug_table[0] = host.id;
	socket_failures_remaining = 1;
	memset(&ping, 0, sizeof(ping));
	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
}

static void test_ipv6_shared_socket_timeout(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	icmp6_shared.fd = controlled_pair[0];
	use_controlled_socket = 0;
	socket_failures_remaining = 1;
	make_host6(&host);
	host.availability.timeout = 50;
	host.availability.retries = 1;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	assert_string_equal(ping.ping_response, "ICMPv6: Ping timed out");
	assert_null(icmp_waiters);
}

/* The datagram path matches on sequence and payload, not the rewritten id. */
static void test_ipv6_datagram_socket_answers(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	make_host6(&host);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(controlled_socket_type, SOCK_DGRAM);
	assert_int_equal(controlled_socket_cloexec, 1);
	assert_int_equal(controlled_socket_closed, 1);
}
#ifdef SPINE_HAVE_ICMPV6
static void check_ipv6_peer_matching(int socket_type) {
	host_t host;
	ping_t ping;

	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	check_wrong_peer = 1;
	socket_failures_remaining = socket_type == SOCK_RAW ? 1 : 0;
	set.availability.icmp_uses_caps = TRUE;
	track_packet = 1;
	packet_size = sizeof(struct icmp6_hdr) + strlen("cacti-monitoring-system");
	make_host(&host, "::1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(controlled_socket_type, socket_type);
	assert_int_equal(reply_v6_count, sizeof(in6addr_loopback.s6_addr) + 1);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_ipv6_datagram_rejects_every_wrong_source_octet(void **state) {
	(void) state;
	check_ipv6_peer_matching(SOCK_DGRAM);
}

static void test_ipv6_raw_rejects_every_wrong_source_octet(void **state) {
	(void) state;
	check_ipv6_peer_matching(SOCK_RAW);
}
#endif

static void test_ipv6_datagram_rejects_wrong_peer_addresses(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	wrong_v6_source_octet = 0;
	make_host6(&host);
	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(recvfrom_calls, sizeof(in6addr_loopback.s6_addr) + 1);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_ipv6_invalid_input_releases_resources(void **state) {
	(void) state;
	for (int mode = 0; mode <= 2; mode++) {
		host_t host;
		ping_t ping = {0};

		assert_int_equal(ping_reset(NULL), 0);
		use_owned_controlled_socket();
		track_packet = 1;
		packet_size = sizeof(struct icmp6_hdr) + sizeof(icmp6_payload) - 1;
		resolver_mode = mode;
		make_host(&host, mode == 0 ? "" : "::1");
		pi_debug_table[0] = host.id;
		assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
		assert_string_equal(ping.ping_response, mode == 0 ? "ICMPv6: Destination address not specified" : "ICMPv6: Destination hostname invalid");
		assert_string_equal(ping.ping_status, "down");
		assert_int_equal(resolver_calls, mode == 0 ? 0 : mode == 1 ? 1
																   : 4);
		assert_int_equal(freeaddrinfo_calls, 0);
		assert_int_equal(packet_released, 1);
		assert_int_equal(controlled_socket_closed, 1);
		assert_int_equal(ping_teardown(NULL), 0);
		controlled_pair[0] = controlled_pair[1] = -1;
	}
}

static void test_ipv6_fd_boundary_releases_resources(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	track_packet = 1;
	packet_size = sizeof(struct icmp6_hdr) + sizeof(icmp6_payload) - 1;
	make_host6(&host);
	pi_debug_table[0] = host.id;
	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "FD_SETSIZE"));
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_ipv6_socket_failure_budget_is_bounded(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	/* The datagram attempt and all five raw attempts fail deterministically. */
	socket_failures_remaining = 6;
	set.logging.log_level = POLLER_VERBOSITY_DEBUG;
	make_host6(&host);
	pi_debug_table[0] = host.id;
	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "unable to create ICMPv6 Socket"));
	assert_int_equal(socket_calls, 6);
	assert_int_equal(controlled_socket_closed, 0);
	assert_null(packet_allocation);
}

static void set_debug_device(const host_t *host, int enabled) {
	pi_debug_table[0] = enabled ? host->id : 0;
}

static void test_address_type_of_an_unresolvable_host_is_unknown(void **state) {
	host_t host;

	(void) state;
	make_host(&host, "unresolvable.invalid");
	resolver_mode = 1;

	assert_int_equal(get_address_type(&host), SPINE_NONE);
	assert_int_equal(resolver_calls, 1);
}

static void test_address_type_follows_the_families_the_resolver_returns(void **state) {
	struct sockaddr_in6 v6_address;
	struct sockaddr unix_address;
	struct addrinfo entries[2];
	host_t host;

	(void) state;
	make_host(&host, "dual.example");
	memset(&v6_address, 0, sizeof(v6_address));
	memset(&unix_address, 0, sizeof(unix_address));
	memset(entries, 0, sizeof(entries));
	v6_address.sin6_family = AF_INET6;
	v6_address.sin6_addr = in6addr_loopback;
	entries[0].ai_family = AF_UNIX;
	entries[0].ai_addr = &unix_address;
	entries[0].ai_next = &entries[1];
	entries[1].ai_family = AF_INET6;
	entries[1].ai_addr = (struct sockaddr *) &v6_address;
	entries[1].ai_canonname = (char *) "dual.example";
	fake_hostinfo = &entries[0];
	resolver_mode = 4;

	/* an unknown family is skipped, and an IPv6-only answer is IPv6 */
	assert_int_equal(get_address_type(&host), SPINE_IPV6);

	entries[0].ai_next = NULL;
	assert_int_equal(get_address_type(&host), SPINE_NONE);
}

static void test_resolution_that_yields_no_address_is_a_failure(void **state) {
	struct sockaddr_in name;

	(void) state;
	resolver_mode = 3;
	assert_false(init_sockaddr(&name, "empty.example", 7));
}

static void test_address_extraction_respects_the_buffer_size(void **state) {
	char buffer[8];

	(void) state;
	memset(buffer, 'x', sizeof(buffer));
	assert_ptr_equal(ping_address("example.com", buffer, 0), buffer);
	assert_int_equal(buffer[0], 'x');

	assert_ptr_equal(ping_address("example.com", buffer, 4), buffer);
	assert_string_equal(buffer, "exa");
}

static void test_interrupted_select_resumes_the_wait(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	select_eintr_once = 1;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_int_equal(select_eintr_once, 0);
	assert_int_equal(recvfrom_calls, 1);
}

static void test_interrupted_receive_is_retried(void **state) {
	int debug;

	(void) state;
	for (debug = 0; debug <= 1; debug++) {
		host_t host;
		ping_t ping;

		assert_int_equal(ping_reset(NULL), 0);
		use_owned_controlled_socket();
		controlled_reply = 1;
		recvfrom_eintr_once = 1;
		make_host(&host, "127.0.0.1");
		set_debug_device(&host, debug);
		memset(&ping, 0, sizeof(ping));

		assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
		assert_int_equal(recvfrom_calls, 2);
		assert_int_equal(ping_teardown(NULL), 0);
		controlled_pair[0] = controlled_pair[1] = -1;
	}
}

/* A reply that is not ours, is not an echo reply, or comes from another host
 * is dropped and the wait continues until the real answer arrives. Raw and
 * datagram sockets classify it differently. */
static void test_stray_replies_do_not_end_the_wait(void **state) {
	const int defects[] = {DEFECT_WRONG_SEQUENCE, DEFECT_NOT_AN_ECHO_REPLY, DEFECT_OTHER_PEER};
	size_t index;
	int raw;

	(void) state;
	for (raw = 0; raw <= 1; raw++) {
		for (index = 0; index < sizeof(defects) / sizeof(defects[0]); index++) {
			host_t host;
			ping_t ping;

			assert_int_equal(ping_reset(NULL), 0);
			use_owned_controlled_socket();
			controlled_reply = 1;
			socket_failures_remaining = raw;
			reply_defect = defects[index];
			make_host(&host, "127.0.0.1");
			memset(&ping, 0, sizeof(ping));
			print_message("raw=%d defect=%d\n", raw, defects[index]);

			assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
			assert_int_equal(controlled_socket_type, raw ? SOCK_RAW : SOCK_DGRAM);
			assert_int_equal(recvfrom_calls, 2);
			assert_string_equal(ping.ping_response, "ICMP: Device is Alive");
			assert_int_equal(ping_teardown(NULL), 0);
			controlled_pair[0] = controlled_pair[1] = -1;
		}
	}
}

static void test_debug_device_reports_a_live_host_and_a_timeout(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	make_host(&host, "127.0.0.1");
	set_debug_device(&host, TRUE);
	memset(&ping, 0, sizeof(ping));
	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);

	assert_int_equal(ping_reset(NULL), 0);
	assert_int_equal(ping_teardown(NULL), 0);
	controlled_pair[0] = controlled_pair[1] = -1;
	use_owned_controlled_socket();
	make_host(&host, "127.0.0.1");
	host.availability.timeout = 1;
	host.availability.retries = 0;
	set_debug_device(&host, TRUE);
	memset(&ping, 0, sizeof(ping));
	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "timed out"));
}

static void ping_without_packet_memory(void) {
	host_t host;
	ping_t ping = {0};

	use_controlled_socket = 1;
	controlled_socket_fd = 42;
	packet_size = ICMP_HDR_SIZE + strlen("cacti-monitoring-system");
	fail_packet_allocation = 1;
	make_host(&host, "127.0.0.1");
	(void) ping_icmp(&host, &ping);
}

static void test_packet_allocation_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(ping_without_packet_memory), EXIT_FAILURE);
}

#ifdef SPINE_HAVE_ICMPV6
static void test_ipv6_resolution_failures_are_reported(void **state) {
	struct sockaddr_in6 name;
	struct addrinfo wrong_family;
	struct sockaddr_in v4_address;

	(void) state;
	resolver_mode = 3;
	assert_false(init_sockaddr6(&name, "empty.example"));

	memset(&wrong_family, 0, sizeof(wrong_family));
	memset(&v4_address, 0, sizeof(v4_address));
	wrong_family.ai_family = AF_INET;
	wrong_family.ai_addr = (struct sockaddr *) &v4_address;
	wrong_family.ai_addrlen = sizeof(v4_address);
	fake_hostinfo = &wrong_family;
	resolver_mode = 4;
	freeaddrinfo_calls = 0;
	assert_false(init_sockaddr6(&name, "v4only.example"));
	assert_int_equal(freeaddrinfo_calls, 1);
}

#if defined(HAVE_IFADDRS_H) && defined(HAVE_NET_IF_H) && defined(HAVE_GETIFADDRS) && defined(HAVE_IF_NAMETOINDEX)
static void test_link_local_scope_comes_from_the_first_usable_interface(void **state) {
	struct sockaddr_in6 name;
	unsigned int expected = if_nametoindex("lo");

	(void) state;
	if (expected == 0) skip();

	memset(&name, 0, sizeof(name));
	getifaddrs_mode = 1;
	apply_ipv6_scope_id(&name);
	assert_int_equal(name.sin6_scope_id, 0);

	/* null address, wrong family, loopback and unknown interface are skipped */
	getifaddrs_mode = 2;
	apply_ipv6_scope_id(&name);
	assert_int_equal(name.sin6_scope_id, expected);
}

static void test_link_local_destination_gets_a_scope_before_sending(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	getifaddrs_mode = 2;
	make_host(&host, "fe80::1");
	host.availability.timeout = 50;
	host.availability.retries = 0;
	memset(&ping, 0, sizeof(ping));

	/* the controlled reply comes from ::1, not the link-local peer */
	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	assert_string_equal(ping.ping_response, "ICMPv6: Ping timed out");
}
#endif

static void test_ipv6_send_failure_is_retried(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	sendto_fails_once = 1;
	make_host6(&host);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(sendto_fails_once, 0);
}

static void test_ipv6_interrupted_select_resumes_the_wait(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	select_eintr_once = 1;
	make_host6(&host);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(select_eintr_once, 0);
}

static void test_ipv6_interrupted_receive_is_retried(void **state) {
	int debug;

	(void) state;
	for (debug = 0; debug <= 1; debug++) {
		host_t host;
		ping_t ping;

		assert_int_equal(ping_reset(NULL), 0);
		use_owned_controlled_socket();
		controlled_reply = 1;
		controlled_reply_v6 = 1;
		recvfrom_eintr_once = 1;
		make_host6(&host);
		set_debug_device(&host, debug);
		memset(&ping, 0, sizeof(ping));

		assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
		assert_int_equal(ping_teardown(NULL), 0);
		controlled_pair[0] = controlled_pair[1] = -1;
	}
}

static void test_ipv6_reply_for_another_probe_is_dropped(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	reply_defect = DEFECT_WRONG_SEQUENCE;
	make_host6(&host);
	set_debug_device(&host, TRUE);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(reply_defect, DEFECT_NONE);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
}

static void test_ipv6_debug_device_reports_a_timeout(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	select_times_out = 1;
	make_host6(&host);
	host.availability.timeout = 1;
	host.availability.retries = 0;
	set_debug_device(&host, TRUE);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	assert_string_equal(ping.ping_response, "ICMPv6: Ping timed out");
}

static void ping_ipv6_without_packet_memory(void) {
	host_t host;
	ping_t ping = {0};

	use_controlled_socket = 1;
	controlled_socket_fd = 42;
	packet_size = sizeof(struct icmp6_hdr) + sizeof(icmp6_payload) - 1;
	fail_packet_allocation = 1;
	make_host6(&host);
	(void) ping_icmp_ipv6(&host, &ping);
}

static void test_ipv6_packet_allocation_failure_is_fatal(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(ping_ipv6_without_packet_memory), EXIT_FAILURE);
}
#endif

static struct addrinfo fake_entry;
static struct sockaddr_in fake_entry_v4;
static struct sockaddr_in6 fake_entry_v6;

/* Pin the resolver to one loopback address so the family decision does not
 * depend on which interfaces the test host has. */
static void resolve_everything_to(int family) {
	memset(&fake_entry, 0, sizeof(fake_entry));
	memset(&fake_entry_v4, 0, sizeof(fake_entry_v4));
	memset(&fake_entry_v6, 0, sizeof(fake_entry_v6));
	fake_entry.ai_family = family;
	fake_entry.ai_canonname = (char *) "fake.example";
	if (family == AF_INET6) {
		fake_entry_v6.sin6_family = AF_INET6;
		fake_entry_v6.sin6_addr = in6addr_loopback;
		fake_entry.ai_addr = (struct sockaddr *) &fake_entry_v6;
		fake_entry.ai_addrlen = sizeof(fake_entry_v6);
	} else {
		fake_entry_v4.sin_family = AF_INET;
		fake_entry_v4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		fake_entry.ai_addr = (struct sockaddr *) &fake_entry_v4;
		fake_entry.ai_addrlen = sizeof(fake_entry_v4);
	}
	fake_hostinfo = &fake_entry;
	resolver_mode = 4;
}

static void test_icmp_without_privilege_falls_back_to_udp(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	make_host(&host, "localhost");
	set.availability.icmp_avail = FALSE;

	assert_int_equal(ping_network(&host, &ping), HOST_UP);
	assert_int_equal(host.availability.ping_method, PING_UDP);
	assert_string_equal(ping.ping_response, "PING: Device does not require ping.");
}

static void test_unresolvable_device_is_reported_as_unknown(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	make_host(&host, "unresolvable.invalid");
	set.availability.icmp_avail = TRUE;
	resolver_mode = 1;

	assert_int_equal(ping_network(&host, &ping), HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "Unknown or is IPV6"));

	/* an SNMP-only method keeps the ping fields untouched */
	memset(&ping, 0, sizeof(ping));
	host.availability.method = AVAIL_SNMP_AND_PING;
	assert_int_equal(ping_network(&host, &ping), HOST_DOWN);
	assert_string_equal(ping.ping_response, "");
}

static void test_network_ping_dispatches_on_the_configured_method(void **state) {
	static const int methods[] = {PING_ICMP, PING_UDP, PING_TCP, PING_TCP_CLOSED, 99};
	static const char *const prefixes[] = {"ICMP:", "UDP:", "TCP:", "TCP:", ""};
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(methods) / sizeof(methods[0]); index++) {
		host_t host;
		ping_t ping = {0};
		int result;

		assert_int_equal(ping_reset(NULL), 0);
		set.availability.icmp_avail = TRUE;
		resolve_everything_to(AF_INET);
		if (methods[index] == PING_ICMP) {
			use_owned_controlled_socket();
			controlled_reply = 1;
		}
		make_host(&host, "fake.example");
		host.availability.ping_method = methods[index];
		host.availability.timeout = 100;
		host.availability.retries = 0;
		print_message("method=%d\n", methods[index]);

		result = ping_network(&host, &ping);
		if (methods[index] == PING_ICMP) assert_int_equal(result, HOST_UP);
		if (methods[index] == 99) assert_int_equal(result, HOST_DOWN);
		assert_int_equal(strncmp(ping.ping_response, prefixes[index], strlen(prefixes[index])), 0);
		assert_int_equal(ping_teardown(NULL), 0);
		controlled_pair[0] = controlled_pair[1] = -1;
	}
}

#ifdef SPINE_HAVE_ICMPV6
static void test_ipv6_device_is_pinged_with_icmpv6(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	set.availability.icmp_avail = TRUE;
	resolve_everything_to(AF_INET6);
	use_owned_controlled_socket();
	controlled_reply = 1;
	controlled_reply_v6 = 1;
	make_host(&host, "fake.example");

	assert_int_equal(ping_network(&host, &ping), HOST_UP);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
}
#endif

static void test_snmp_ping_of_a_device_without_a_community_is_skipped(void **state) {
	host_t host;
	ping_t ping = {0};

	(void) state;
	make_host(&host, "127.0.0.1");
	host.snmp.session = (void *) (uintptr_t) 1;
	host.snmp.profile.version = 2;
	host.snmp.profile.community[0] = '\0';

	assert_int_equal(ping_snmp(&host, &ping), HOST_UP);
	assert_string_equal(ping.snmp_response, "Device does not require SNMP");
	assert_string_equal(ping.snmp_status, "0.00");
}

static void test_snmp_ping_reports_a_device_that_does_not_answer(void **state) {
	const int statuses[] = {STAT_TIMEOUT, STAT_ERROR};
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(statuses) / sizeof(statuses[0]); index++) {
		host_t host;
		ping_t ping = {0};

		make_host(&host, "127.0.0.1");
		host.snmp.session = (void *) (uintptr_t) 1;
		host.snmp.profile.version = 2;
		snprintf(host.snmp.profile.community, sizeof(host.snmp.profile.community), "public");
		/* an ignored host is not queried, so the recorded status stands */
		host.ignore_host = TRUE;
		host.snmp.status = statuses[index];

		assert_int_equal(ping_snmp(&host, &ping), HOST_DOWN);
		assert_string_equal(ping.snmp_response, "Device did not respond to SNMP");
	}
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
		cmocka_unit_test_setup_teardown(test_shared_socket_answers_without_a_socket_of_its_own, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_socket_timeout_unregisters, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_reply_for_another_waiter_is_handed_over, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_waiter_does_not_read_while_another_thread_does, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_reader_drains_the_queue, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_reader_hands_over_on_leaving, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_per_ping_sockets_are_close_on_exec, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_icmp6_reply_matching, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_open_socket_fcntl_fallback, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_open_shared_sockets, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_open_shared_sockets_failures, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_dispatch_ipv6, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_drain_retries_after_eintr, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_shared_socket_debug_device, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_shared_socket_answers, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_shared_socket_timeout, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_datagram_socket_answers, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_datagram_rejects_wrong_peer_addresses, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_invalid_input_releases_resources, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_fd_boundary_releases_resources, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_socket_failure_budget_is_bounded, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_address_type_of_an_unresolvable_host_is_unknown, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_address_type_follows_the_families_the_resolver_returns, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_resolution_that_yields_no_address_is_a_failure, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_address_extraction_respects_the_buffer_size, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_interrupted_select_resumes_the_wait, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_interrupted_receive_is_retried, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_stray_replies_do_not_end_the_wait, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_debug_device_reports_a_live_host_and_a_timeout, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_packet_allocation_failure_is_fatal, ping_reset, ping_teardown),
#ifdef SPINE_HAVE_ICMPV6
		cmocka_unit_test_setup_teardown(test_ipv6_resolution_failures_are_reported, ping_reset, ping_teardown),
#if defined(HAVE_IFADDRS_H) && defined(HAVE_NET_IF_H) && defined(HAVE_GETIFADDRS) && defined(HAVE_IF_NAMETOINDEX)
		cmocka_unit_test_setup_teardown(test_link_local_scope_comes_from_the_first_usable_interface, ping_reset, ping_teardown),
#endif
#if defined(HAVE_IFADDRS_H) && defined(HAVE_NET_IF_H) && defined(HAVE_GETIFADDRS) && defined(HAVE_IF_NAMETOINDEX)
		cmocka_unit_test_setup_teardown(test_link_local_destination_gets_a_scope_before_sending, ping_reset, ping_teardown),
#endif
		cmocka_unit_test_setup_teardown(test_ipv6_send_failure_is_retried, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_interrupted_select_resumes_the_wait, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_interrupted_receive_is_retried, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_reply_for_another_probe_is_dropped, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_debug_device_reports_a_timeout, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_packet_allocation_failure_is_fatal, ping_reset, ping_teardown),
#endif
		cmocka_unit_test_setup_teardown(test_icmp_without_privilege_falls_back_to_udp, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_unresolvable_device_is_reported_as_unknown, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_network_ping_dispatches_on_the_configured_method, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_snmp_ping_of_a_device_without_a_community_is_skipped, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_snmp_ping_reports_a_device_that_does_not_answer, ping_reset, ping_teardown),
#ifdef SPINE_HAVE_ICMPV6
		cmocka_unit_test_setup_teardown(test_ipv6_device_is_pinged_with_icmpv6, ping_reset, ping_teardown),
#endif
#ifdef SPINE_HAVE_ICMPV6
		cmocka_unit_test_setup_teardown(test_ipv6_datagram_rejects_every_wrong_source_octet, ping_reset, ping_teardown),
		cmocka_unit_test_setup_teardown(test_ipv6_raw_rejects_every_wrong_source_octet, ping_reset, ping_teardown),
#endif
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
