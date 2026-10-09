/* Reachability verdicts and timing in ping.c.
 *
 * Each case drives the shipped probe through controlled socket calls, so a
 * lost packet, a late reply or an ICMP error arrives exactly when the case
 * needs it.  Nothing here needs root, raw sockets or a route off the host.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "internal/common.h"
#include "app/spine.h"
#include "ping/ping.h"

extern int *debug_devices;

static int pt_debug_table[100];
static int controlled_pair[2] = {-1, -1};
static int use_controlled_socket;
static int icmp6_mode;
static int sends;
static int drop_sends;
static int fake_select_timeouts;
static struct timeval first_select_timeout;
static int select_calls;
static unsigned char last_request[64];
static size_t last_request_length;
static int recv_errno;
static int recv_calls;

static int test_socket(int domain, int type, int protocol);
static ssize_t test_sendto(int fd, const void *buffer, size_t length, int flags,
	const struct sockaddr *address, socklen_t address_len);
static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
	fd_set *exceptfds, struct timeval *timeout);
static ssize_t test_recvfrom(int fd, void *buffer, size_t length, int flags,
	struct sockaddr *address, socklen_t *address_len);
static ssize_t test_recv(int fd, void *buffer, size_t length, int flags);

#define socket test_socket
#define sendto test_sendto
#define select test_select
#define recvfrom test_recvfrom
#define recv test_recv
#include "../../src/poller/availability.c"
#include "../../src/ping/icmp_shared.c"
#include "../../src/ping/icmp4.c"
#include "../../src/ping/icmp6.c"
#include "../../src/ping/udp.c"
#include "../../src/ping/tcp.c"
#include "../../src/ping/address.c"

#undef socket
#undef sendto
#undef select
#undef recvfrom
#undef recv

static int test_socket(int domain, int type, int protocol) {
	if (use_controlled_socket && type != SOCK_STREAM && protocol != IPPROTO_UDP) {
		return controlled_pair[0];
	}
	return socket(domain, type, protocol);
}

static ssize_t test_sendto(int fd, const void *buffer, size_t length, int flags,
		const struct sockaddr *address, socklen_t address_len) {
	if (!use_controlled_socket || fd != controlled_pair[0]) {
		return sendto(fd, buffer, length, flags, address, address_len);
	}
	assert_true(length <= sizeof(last_request));
	memcpy(last_request, buffer, length);
	last_request_length = length;
	sends++;
	return (ssize_t) length;
}

/* The first drop_sends probes are lost: their wait runs the real select()
 * on a quiet socket, so the clock moves exactly as it would on the wire.
 * Later probes are answered at once. */
static int test_select(int nfds, fd_set *readfds, fd_set *writefds,
		fd_set *exceptfds, struct timeval *timeout) {
	if (!use_controlled_socket) {
		return select(nfds, readfds, writefds, exceptfds, timeout);
	}
	if (select_calls++ == 0 && timeout != NULL) {
		first_select_timeout = *timeout;
	}
	if (fake_select_timeouts) {
		return 0;
	}
	if (sends <= drop_sends) {
		return select(nfds, readfds, writefds, exceptfds, timeout);
	}
	return 1;
}

static ssize_t test_recvfrom(int fd, void *buffer, size_t length, int flags,
		struct sockaddr *address, socklen_t *address_len) {
	unsigned char *reply = buffer;

	if (!use_controlled_socket || fd != controlled_pair[0]) {
		return recvfrom(fd, buffer, length, flags, address, address_len);
	}
	if (sends <= drop_sends || fake_select_timeouts) {
		errno = EAGAIN;
		return -1;
	}

	/* Echo the probe back as the reply a datagram ICMP socket delivers. */
	assert_true(length >= last_request_length);
	memcpy(reply, last_request, last_request_length);
	reply[0] = icmp6_mode ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY;

	if (icmp6_mode) {
		struct sockaddr_in6 *source = (struct sockaddr_in6 *) address;
		assert_true(*address_len >= sizeof(*source));
		memset(source, 0, sizeof(*source));
		source->sin6_family = AF_INET6;
		source->sin6_addr = in6addr_loopback;
		*address_len = sizeof(*source);
	} else {
		struct sockaddr_in *source = (struct sockaddr_in *) address;
		assert_true(*address_len >= sizeof(*source));
		memset(source, 0, sizeof(*source));
		source->sin_family = AF_INET;
		source->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		*address_len = sizeof(*source);
	}
	return (ssize_t) last_request_length;
}

/* Real recv(), then the errno a connected UDP socket would report if the
 * matching ICMP error had arrived instead of the datagram. */
static ssize_t test_recv(int fd, void *buffer, size_t length, int flags) {
	ssize_t received = recv(fd, buffer, length, flags);

	recv_calls++;
	if (received >= 0 && recv_errno != 0) {
		errno = recv_errno;
		return -1;
	}
	return received;
}

static void make_host(host_t *host, const char *address, int method) {
	memset(host, 0, sizeof(*host));
	host->id = 1;
	snprintf(host->hostname, sizeof(host->hostname), "%s", address);
	host->availability.timeout     = 300;
	host->availability.retries     = 1;
	host->availability.method      = AVAIL_PING;
	host->availability.ping_method = method;
}

static int timing_setup(void **state) {
	(void) state;
	config_defaults();
	init_mutexes();
	memset(pt_debug_table, 0, sizeof(pt_debug_table));
	debug_devices = pt_debug_table;
	set.availability.icmp_uses_caps = TRUE;
	use_controlled_socket = 0;
	icmp6_mode = 0;
	sends = 0;
	drop_sends = 0;
	fake_select_timeouts = 0;
	select_calls = 0;
	memset(&first_select_timeout, 0, sizeof(first_select_timeout));
	last_request_length = 0;
	recv_errno = 0;
	recv_calls = 0;
	return 0;
}

static int timing_teardown(void **state) {
	(void) state;
	if (controlled_pair[0] != -1) close(controlled_pair[0]);
	if (controlled_pair[1] != -1) close(controlled_pair[1]);
	controlled_pair[0] = -1;
	controlled_pair[1] = -1;
	return 0;
}

static void use_controlled_icmp_socket(void) {
	assert_int_equal(socketpair(AF_UNIX, SOCK_DGRAM, 0, controlled_pair), 0);
	use_controlled_socket = 1;
}

/* --- G4: one lost probe must not use up the retry budget ------------------ */

static void test_icmp_retry_after_one_lost_probe_is_alive(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_icmp_socket();
	drop_sends = 1;
	make_host(&host, "127.0.0.1", PING_ICMP);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_int_equal(sends, 2);
	assert_string_equal(ping.ping_response, "ICMP: Device is Alive");
	/* the reported time is the round trip of the answered probe, not the
	 * time since the first one was lost */
	assert_true(atof(ping.ping_status) < host.availability.timeout);
}

#ifdef SPINE_HAVE_ICMPV6
static void test_icmpv6_retry_after_one_lost_probe_is_alive(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_icmp_socket();
	icmp6_mode = 1;
	drop_sends = 1;
	make_host(&host, "::1", PING_ICMP);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
	assert_int_equal(sends, 2);
	assert_string_equal(ping.ping_response, "ICMPv6: Device is Alive");
	assert_true(atof(ping.ping_status) < host.availability.timeout);
}
#endif

/* --- G8: a 1500 ms timeout waits 1500 ms, not 2500 ------------------------ */

static long timeval_usec(const struct timeval *tv) {
	return (long) tv->tv_sec * 1000000L + (long) tv->tv_usec;
}

static void test_wait_left_converts_without_rounding_up(void **state) {
	static const double offsets[] = {0.25, 0.5, 0.75, 1.4, 1.5, 1.6, 9.999};
	struct timeval tv;
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
		long expected = (long) (offsets[i] * 1000000.0);

		ping_wait_left(spine_monotonic_time() + offsets[i], &tv);
		assert_true(tv.tv_usec >= 0 && tv.tv_usec < 1000000);
		assert_true(timeval_usec(&tv) <= expected);
		assert_true(timeval_usec(&tv) > expected - 50000L);
	}

	/* a deadline already behind us polls instead of waiting */
	ping_wait_left(spine_monotonic_time() - 1.0, &tv);
	assert_int_equal(timeval_usec(&tv), 0);
}

static void test_icmp_wait_matches_the_device_timeout(void **state) {
	host_t host;
	ping_t ping;
	long waited;

	(void) state;
	use_controlled_icmp_socket();
	fake_select_timeouts = 1;
	make_host(&host, "127.0.0.1", PING_ICMP);
	host.availability.timeout = 1500;
	host.availability.retries = 0;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	waited = timeval_usec(&first_select_timeout);
	assert_true(waited <= 1500000L);
	assert_true(waited > 1400000L);
}

#ifdef SPINE_HAVE_ICMPV6
static void test_icmpv6_wait_matches_the_device_timeout(void **state) {
	host_t host;
	ping_t ping;
	long waited;

	(void) state;
	use_controlled_icmp_socket();
	icmp6_mode = 1;
	fake_select_timeouts = 1;
	make_host(&host, "::1", PING_ICMP);
	host.availability.timeout = 1500;
	host.availability.retries = 0;
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_DOWN);
	waited = timeval_usec(&first_select_timeout);
	assert_true(waited <= 1500000L);
	assert_true(waited > 1400000L);
}
#endif

/* --- G6: what a UDP probe may take as proof of life ----------------------- */

typedef struct {
	int fd;
	int reply;
} udp_peer_t;

/* Answers one probe, which is what makes the client socket readable.  The
 * injected errno then decides what that readability meant. */
static void *udp_peer(void *argument) {
	udp_peer_t *peer = argument;
	struct sockaddr_storage client;
	socklen_t length = sizeof(client);
	char buffer[64];
	ssize_t received;

	received = recvfrom(peer->fd, buffer, sizeof(buffer), 0, (struct sockaddr *) &client, &length);
	if (received > 0 && peer->reply) {
		sendto(peer->fd, "pong", 4, 0, (struct sockaddr *) &client, length);
	}
	return NULL;
}

static int run_udp_probe(int injected_errno, int reply, ping_t *ping) {
	struct sockaddr_in address;
	socklen_t length = sizeof(address);
	udp_peer_t peer;
	pthread_t thread;
	host_t host;
	int rc;

	peer.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert_true(peer.fd >= 0);
	peer.reply = reply;
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert_int_equal(bind(peer.fd, (struct sockaddr *) &address, sizeof(address)), 0);
	assert_int_equal(getsockname(peer.fd, (struct sockaddr *) &address, &length), 0);
	assert_int_equal(pthread_create(&thread, NULL, udp_peer, &peer), 0);

	make_host(&host, "127.0.0.1", PING_UDP);
	host.availability.port    = ntohs(address.sin_port);
	host.availability.retries = 0;
	host.availability.timeout = 500;
	recv_errno = injected_errno;
	memset(ping, 0, sizeof(*ping));

	rc = ping_udp(&host, ping);

	/* a peer still parked in recvfrom() would hang the join */
	shutdown(peer.fd, SHUT_RDWR);
	assert_int_equal(pthread_join(thread, NULL), 0);
	close(peer.fd);
	return rc;
}

/* Linux reports EHOSTUNREACH on a connected UDP socket only for host or
 * admin prohibited, which a device's own firewall sends; cmd.php reads it as
 * alive and spine has to agree. */
static void test_udp_host_prohibited_is_alive(void **state) {
	ping_t ping;

	(void) state;
	assert_int_equal(run_udp_probe(EHOSTUNREACH, 1, &ping), HOST_UP);
	assert_true(recv_calls >= 1);
	assert_string_equal(ping.ping_response, "UDP: Device is Alive");
}

static void test_udp_network_unreachable_is_down(void **state) {
	ping_t ping;

	(void) state;
	assert_int_equal(run_udp_probe(ENETUNREACH, 1, &ping), HOST_DOWN);
	assert_true(recv_calls >= 1);
}

#ifdef EHOSTDOWN
static void test_udp_host_down_is_down(void **state) {
	ping_t ping;

	(void) state;
	assert_int_equal(run_udp_probe(EHOSTDOWN, 1, &ping), HOST_DOWN);
	assert_true(recv_calls >= 1);
}
#endif

static void test_udp_port_unreachable_is_alive(void **state) {
	ping_t ping;

	(void) state;
	assert_int_equal(run_udp_probe(ECONNREFUSED, 1, &ping), HOST_UP);
	assert_string_equal(ping.ping_response, "UDP: Device is Alive");
}

static void test_udp_data_reply_is_alive(void **state) {
	ping_t ping;

	(void) state;
	assert_int_equal(run_udp_probe(0, 1, &ping), HOST_UP);
	assert_string_equal(ping.ping_response, "UDP: Device is Alive");
}

/* --- G9: transport-qualified and bracketed IPv6 device names -------------- */

static void test_namebyhost_table(void **state) {
	static const struct {
		const char *input;
		const char *hostname;
		int method;
		int port;
	} cases[] = {
		{"router.example",          "router.example",          0, 0},
		{"router.example:161",      "router.example",          0, 161},
		{"TCP:router.example:443",  "router.example",          1, 443},
		{"udp:router.example:53",   "router.example",          2, 53},
		{"tcp6:router.example:22",  "router.example",          3, 22},
		{"192.0.2.7",               "192.0.2.7",               0, 0},
		{"2001:db8::1",             "2001:db8::1",             0, 0},
		{"fe80::1%eth0",            "fe80::1%eth0",            0, 0},
		{"[2001:db8::1]",           "[2001:db8::1]",           0, 0},
		{"[::1]:161",               "[::1]:161",               0, 161},
		{"udp6:[2001:db8::1]:161",  "udp6:[2001:db8::1]:161",  4, 161},
		{"tcp6:[::1]:22",           "tcp6:[::1]:22",           3, 22},
		{"UDP6:[::1]",              "UDP6:[::1]",              4, 0},
		{"udp6:[::1]:notaport",     "udp6:[::1]:notaport",     4, 0},
	};
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		name_t *name = get_namebyhost(cases[i].input, NULL);

		assert_non_null(name);
		if (strcmp(name->hostname, cases[i].hostname) != 0 ||
			name->method != cases[i].method || name->port != cases[i].port) {
			fail_msg("get_namebyhost(\"%s\") gave {\"%s\", %d, %d}, expected {\"%s\", %d, %d}",
				cases[i].input, name->hostname, name->method, name->port,
				cases[i].hostname, cases[i].method, cases[i].port);
		}
		free(name);
	}
}

#ifdef SPINE_HAVE_ICMPV6
static void test_icmpv6_resolves_transport_qualified_names(void **state) {
	static const char *const names[] = {
		"udp6:[::1]:161", "tcp6:[::1]:22", "[::1]:161", "[::1]", "UDP6:[::1]", "::1"
	};
	struct sockaddr_in6 address;
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		memset(&address, 0, sizeof(address));
		if (!init_sockaddr6(&address, names[i])) {
			fail_msg("init_sockaddr6(\"%s\") failed", names[i]);
		}
		assert_memory_equal(&address.sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));
	}
}

static void test_icmpv6_pings_a_transport_qualified_name(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_icmp_socket();
	icmp6_mode = 1;
	make_host(&host, "udp6:[::1]:161", PING_ICMP);
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp_ipv6(&host, &ping), HOST_UP);
}
#endif

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_icmp_retry_after_one_lost_probe_is_alive, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_wait_left_converts_without_rounding_up, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_icmp_wait_matches_the_device_timeout, timing_setup, timing_teardown),
		#ifdef SPINE_HAVE_ICMPV6
		cmocka_unit_test_setup_teardown(test_icmpv6_retry_after_one_lost_probe_is_alive, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_icmpv6_wait_matches_the_device_timeout, timing_setup, timing_teardown),
		#endif
		cmocka_unit_test_setup_teardown(test_udp_host_prohibited_is_alive, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_udp_network_unreachable_is_down, timing_setup, timing_teardown),
		#ifdef EHOSTDOWN
		cmocka_unit_test_setup_teardown(test_udp_host_down_is_down, timing_setup, timing_teardown),
		#endif
		cmocka_unit_test_setup_teardown(test_udp_port_unreachable_is_alive, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_udp_data_reply_is_alive, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_namebyhost_table, timing_setup, timing_teardown),
		#ifdef SPINE_HAVE_ICMPV6
		cmocka_unit_test_setup_teardown(test_icmpv6_resolves_transport_qualified_names, timing_setup, timing_teardown),
		cmocka_unit_test_setup_teardown(test_icmpv6_pings_a_transport_qualified_name, timing_setup, timing_teardown),
		#endif
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
