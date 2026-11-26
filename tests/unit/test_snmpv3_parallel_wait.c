/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Project contributor history: CONTRIBUTORS.md.
 */

/* SNMPv3 requests on different sessions wait in parallel.
 *
 * LOCK_SNMP guards Net-SNMP's USM globals, so a v3 request holds it while
 * Net-SNMP builds or parses a message. It must not hold it while waiting for
 * the reply: that made every v3 request in the process single-threaded and
 * let one dead device stall all the others for its whole timeout.
 *
 * Each thread here polls its own real Net-SNMP v3 session against a UDP
 * socket that never answers, so every request runs to its timeout. Waiting
 * in parallel takes about one timeout; a serialized wait takes one per
 * thread. Under ThreadSanitizer the same run also checks that the unlocked
 * part of the wait shares no state across sessions.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "internal/common.h"
#include "app/spine.h"

#define WAIT_THREADS 4
#define WAIT_TIMEOUT_MS 400

typedef struct {
	host_t host;
	char *result;
} wait_worker_t;

/*! \fn static int open_blackhole(int *port)
 *  \brief binds a loopback UDP socket that is never read.
 *
 *  \return the socket, with its port stored in port
 */
static int open_blackhole(int *port) {
	struct sockaddr_in address;
	socklen_t length = sizeof(address);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	assert_true(fd >= 0);
	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert_int_equal(bind(fd, (struct sockaddr *) &address, sizeof(address)), 0);
	assert_int_equal(getsockname(fd, (struct sockaddr *) &address, &length), 0);
	*port = ntohs(address.sin_port);
	return fd;
}

/*! \fn static void *open_v3_session(int port)
 *  \brief opens a noAuthNoPriv v3 session whose engine ID is already known.
 *
 *  A known engine ID skips discovery, so the session opens without network
 *  I/O and the only wait is the request the test measures.
 *
 *  \return the Net-SNMP single-session handle
 */
static void *open_v3_session(int port) {
	static unsigned char engine_id[] = {0x80, 0x00, 0x1f, 0x88, 0x04, 's', 'p', 'i', 'n', 'e'};
	static char user[] = "parallel";
	struct snmp_session session;
	char peer[64];
	void *sessp;

	snmp_sess_init(&session);
	snprintf(peer, sizeof(peer), "udp:127.0.0.1:%d", port);
	session.peername = peer;
	session.version = SNMP_VERSION_3;
	session.securityModel = USM_SEC_MODEL_NUMBER;
	session.securityLevel = SNMP_SEC_LEVEL_NOAUTH;
	session.securityName = user;
	session.securityNameLen = strlen(user);
	session.securityEngineID = engine_id;
	session.securityEngineIDLen = sizeof(engine_id);
	session.flags |= SNMP_FLAGS_DONT_PROBE;
	session.retries = 0;
	session.timeout = WAIT_TIMEOUT_MS * 1000L;

	thread_mutex_lock(LOCK_SNMP);
	sessp = snmp_sess_open(&session);
	thread_mutex_unlock(LOCK_SNMP);
	assert_non_null(sessp);
	return sessp;
}

static void *wait_worker(void *argument) {
	wait_worker_t *worker = argument;
	char oid[] = ".1.3.6.1.2.1.1.3.0";

	worker->result = snmp_get(&worker->host, oid);
	return NULL;
}

static void test_v3_waits_do_not_serialize(void **state) {
	wait_worker_t workers[WAIT_THREADS];
	pthread_t threads[WAIT_THREADS];
	double begin;
	double elapsed;
	int port;
	int blackhole;
	int index;

	(void) state;
	blackhole = open_blackhole(&port);
	memset(workers, 0, sizeof(workers));
	for (index = 0; index < WAIT_THREADS; index++) {
		workers[index].host.id = index + 1;
		workers[index].host.snmp.session = open_v3_session(port);
	}

	begin = spine_monotonic_time();
	for (index = 0; index < WAIT_THREADS; index++) {
		assert_int_equal(pthread_create(&threads[index], NULL, wait_worker, &workers[index]), 0);
	}
	for (index = 0; index < WAIT_THREADS; index++) {
		assert_int_equal(pthread_join(threads[index], NULL), 0);
	}
	elapsed = spine_monotonic_time() - begin;

	print_message("%d v3 timeouts of %d ms took %.3f s\n", WAIT_THREADS, WAIT_TIMEOUT_MS, elapsed);
	for (index = 0; index < WAIT_THREADS; index++) {
		assert_non_null(workers[index].result);
		assert_string_equal(workers[index].result, "U");
		assert_int_equal(workers[index].host.snmp.status, STAT_TIMEOUT);
		free(workers[index].result);
		snmp_host_cleanup(workers[index].host.snmp.session);
	}

	/* Serialized waits take WAIT_THREADS timeouts. Allow sanitizer and
	 * scheduler overhead, but stay well below that. */
	assert_true(elapsed < (WAIT_THREADS / 2.0) * WAIT_TIMEOUT_MS / 1000.0);
	assert_true(elapsed >= 0.9 * WAIT_TIMEOUT_MS / 1000.0);

	/* The lock is free again once every request has finished. */
	assert_int_equal(thread_mutex_trylock(LOCK_SNMP), 0);
	thread_mutex_unlock(LOCK_SNMP);
	(void) close(blackhole);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_v3_waits_do_not_serialize),
	};

	config_defaults();
	init_mutexes();
	set.snmp.snmp_retries = 0;
	snmp_spine_init();

	return cmocka_run_group_tests(tests, NULL, NULL);
}
