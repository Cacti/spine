/* ping_icmp() resource ownership.
 *
 * This is the least-tested and highest-consequence change in the branch: the
 * function runs in a SUID-root binary, and its five exits were collapsed onto
 * one cleanup label while the seteuid(0)/LOCK_SETEUID wrapper around close()
 * was removed. Nothing covered it.
 *
 * A raw ICMP socket needs privilege, so these run only where that succeeds and
 * skip otherwise rather than failing for the wrong reason.
 *
 * The FD_SETSIZE case is the one that mattered: that exit closed the socket and
 * returned without freeing the packet (#593). It is reachable by holding enough
 * descriptors open that the next socket lands at or above FD_SETSIZE, which is
 * what this does.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>

#include "common.h"
#include "spine.h"
#include "ping.h"

extern int *debug_devices;

static int pi_debug_table[100];

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
	return 0;
}

static void test_loopback_answers(void **state) {
	host_t host;
	ping_t ping;

	(void) state;
	if (!have_raw_socket()) {
		print_message("no raw ICMP socket here; skipping\n");
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
		print_message("no raw ICMP socket here; skipping\n");
		skip();
	}

	for (i = 0; i < 20; i++) {
		make_host(&host, "127.0.0.1");
		memset(&ping, 0, sizeof(ping));
		assert_int_equal(ping_icmp(&host, &ping), HOST_UP);
	}
}

/* The exit that leaked. Hold descriptors until a new socket would land at or
   above FD_SETSIZE, then ping: the guard fires, and the packet must still be
   released. */
static void test_fd_setsize_guard_releases_the_packet(void **state) {
	host_t host;
	ping_t ping;
	int *held;
	int count = 0;
	int i;
	int rc;

	(void) state;
	if (!have_raw_socket()) {
		print_message("no raw ICMP socket here; skipping\n");
		skip();
	}

	held = calloc(FD_SETSIZE + 16, sizeof(int));
	assert_non_null(held);

	/* consume descriptors up to the limit the guard tests */
	while (count < FD_SETSIZE + 8) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0) {
			break;
		}

		held[count++] = fd;

		if (fd >= FD_SETSIZE) {
			break;
		}
	}

	if (count == 0 || held[count - 1] < FD_SETSIZE) {
		for (i = 0; i < count; i++) close(held[i]);
		free(held);
		print_message("could not reach FD_SETSIZE descriptors here; skipping\n");
		skip();
	}

	make_host(&host, "127.0.0.1");
	memset(&ping, 0, sizeof(ping));

	rc = ping_icmp(&host, &ping);

	for (i = 0; i < count; i++) close(held[i]);
	free(held);

	/* the guard reports the device down and names the reason */
	assert_int_equal(rc, HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "FD_SETSIZE"));
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
	alarm(0);

	sigaction(SIGALRM, &prev, NULL);

	/* it gave up rather than hanging, and said why */
	assert_int_equal(rc, HOST_DOWN);
	assert_non_null(strstr(ping.ping_response, "ICMP Socket"));

	/* the lock is free: a thread that still owned it could not take it again */
	thread_mutex_lock(LOCK_SETEUID);
	thread_mutex_unlock(LOCK_SETEUID);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_loopback_answers, ping_reset),
		cmocka_unit_test_setup(test_repeated_pings_do_not_accumulate, ping_reset),
		cmocka_unit_test_setup(test_fd_setsize_guard_releases_the_packet, ping_reset),
		cmocka_unit_test_setup(test_socket_retry_does_not_deadlock_on_seteuid, ping_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
