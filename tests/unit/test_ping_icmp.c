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
static int track_packet;
static size_t packet_size;
static void *packet_allocation;
static int packet_released;
static int alternate_has_caps;
static int has_caps_calls;

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static void *intercepted_malloc(size_t size);
static void intercepted_free(void *ptr);
static int test_has_caps(void);

/* Compile the shipped implementation into this test translation unit so its
 * resource sinks can be observed without root or Linux-only linker wrapping. */
#define socket test_socket
#define close test_close
#define malloc intercepted_malloc
#define free intercepted_free
#define hasCaps test_has_caps
#include "../../ping.c"
#undef socket
#undef close
#undef malloc
#undef free
#undef hasCaps

static int test_has_caps(void) {
	if (alternate_has_caps) {
		return (has_caps_calls++ == 0) ? FALSE : TRUE;
	}

	return hasCaps();
}

static int test_socket(int domain, int type, int protocol) {
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

	if (track_packet && size == packet_size) {
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

static int have_raw_socket(void) {
	int s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (s < 0) {
		return 0;
	}

	close(s);
	return 1;
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
	track_packet = 0;
	packet_size = ICMP_HDR_SIZE + strlen("cacti-monitoring-system");
	packet_allocation = NULL;
	packet_released = 0;
	alternate_has_caps = 0;
	has_caps_calls = 0;
	return 0;
}

static void test_loopback_answers(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	if (!have_raw_socket()) {
		skip();
	}

	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	assert_true(strlen(ping.ping_response) > 0);
}

/* Repeating the call must not accumulate anything. Under --enable-sanitizers
   the packet leak this branch fixed shows up here as a leak report. */
static void test_repeated_pings_do_not_accumulate(void **state) {
	host_t host;
	ping_t ping;
	int i;

	(void) state;
	if (!have_raw_socket()) {
		skip();
	}

	for (i = 0; i < 20; i++) {
		make_host(&host, "127.0.0.1");
		memset(&ping, 0, sizeof(ping));
		assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	}
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
	use_controlled_socket = 1;
	controlled_socket_fd = 43;
	track_packet = 1;
	make_host(&host, "invalid.invalid");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(packet_released, 1);
	assert_int_equal(controlled_socket_closed, 1);
}

static void test_timeout_releases_packet_and_socket(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = 44;
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

static void test_capability_decision_pairs_lock_and_unlock(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	use_controlled_socket = 1;
	controlled_socket_fd = FD_SETSIZE;
	alternate_has_caps = 1;
	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	assert_int_equal(ping_icmp(&host, &ping), HOST_DOWN);
	assert_int_equal(has_caps_calls, 1);
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

	if (have_raw_socket()) {
		/* socket() would succeed, so the retry loop never runs */
		skip();
	}

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

	/* five attempts at 500ms is about 2s; 15 leaves room on a loaded runner */
	alarm(15);
	rc = ping_icmp(&host, &ping);

	/* it gave up rather than hanging, and said why */
	assert_int_equal(rc, HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "ICMP Socket"));

	/* Keep the alarm armed for the probe, and never block on a leaked lock. */
	assert_int_equal(thread_mutex_trylock(LOCK_SETEUID), 0);
	thread_mutex_unlock(LOCK_SETEUID);

	alarm(0);
	sigaction(SIGALRM, &prev, NULL);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_loopback_answers, ping_reset),
		cmocka_unit_test_setup(test_repeated_pings_do_not_accumulate, ping_reset),
		cmocka_unit_test_setup(test_fd_setsize_guard_releases_the_packet, ping_reset),
		cmocka_unit_test_setup(test_empty_address_releases_packet_and_socket, ping_reset),
		cmocka_unit_test_setup(test_invalid_address_releases_packet_and_socket, ping_reset),
		cmocka_unit_test_setup(test_timeout_releases_packet_and_socket, ping_reset),
		cmocka_unit_test_setup(test_capability_decision_pairs_lock_and_unlock, ping_reset),
		cmocka_unit_test_setup(test_socket_retry_does_not_deadlock_on_seteuid, ping_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
