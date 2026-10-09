/*
 * Copyright (C) 2004-2026 The Cacti Group
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 */

/* setresuid() and setresgid() let a root test reproduce the ids a setuid root
 * exec hands spine: real uid of the caller, effective and saved uid of 0. */
#define _GNU_SOURCE
#include "internal/common.h"
#include "app/spine.h"
#include <sys/resource.h>
#include <grp.h>

#define UNPRIVILEGED_ID 65534

/* Linux keeps all four ids on one line, and the saved id is the one that a
 * seteuid()-only drop leaves at 0. */
static bool status_ids_are(const char *field, unsigned long id) {
#ifdef __linux__
	char line[256];
	char expected[128];
	bool found = FALSE;
	FILE *status = fopen("/proc/self/status", "r");
	assert(status != NULL);
	snprintf(expected, sizeof(expected), "%s\t%lu\t%lu\t%lu\t%lu\n", field, id, id, id, id);
	while (fgets(line, sizeof(line), status) != NULL) {
		if (strncmp(line, field, strlen(field)) == 0) {
			found = strcmp(line, expected) == 0;
			break;
		}
	}
	assert(fclose(status) == 0);
	return found;
#else
	(void) field;
	(void) id;
	return TRUE;
#endif
}

static int run_child(void (*body)(void), char *output, size_t capacity) {
	int descriptors[2];
	assert(pipe(descriptors) == 0);
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(15);
		assert(close(descriptors[0]) == 0);
		assert(dup2(descriptors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(descriptors[1]) == 0);
		body();
		_exit(EXIT_SUCCESS);
	}
	assert(close(descriptors[1]) == 0);
	size_t used = 0;
	for (;;) {
		ssize_t received = read(descriptors[0], output + used, capacity - used - 1);
		if (received < 0 && errno == EINTR) continue;
		assert(received >= 0);
		if (received == 0) break;
		used += (size_t) received;
		assert(used < capacity - 1);
	}
	output[used] = '\0';
	assert(close(descriptors[0]) == 0);
	int status;
	while (waitpid(child, &status, 0) < 0) assert(errno == EINTR);
	assert(WIFEXITED(status));
	return WEXITSTATUS(status);
}

#ifdef __linux__
/* The state execve() leaves behind for a setuid root binary run by a user. */
static void become_setuid_root_caller(void) {
	assert(setgroups(0, NULL) == 0);
	assert(setresgid(UNPRIVILEGED_ID, UNPRIVILEGED_ID, UNPRIVILEGED_ID) == 0);
	assert(setresuid(UNPRIVILEGED_ID, 0, 0) == 0);
	assert(getuid() == UNPRIVILEGED_ID && geteuid() == 0);
	assert(!privileges_dropped(UNPRIVILEGED_ID, UNPRIVILEGED_ID));
}

static void setuid_drop_body(void) {
	become_setuid_root_caller();
	drop_privileges();
	assert(privileges_dropped(UNPRIVILEGED_ID, UNPRIVILEGED_ID));
	assert(status_ids_are("Uid:", UNPRIVILEGED_ID));
	assert(status_ids_are("Gid:", UNPRIVILEGED_ID));
	assert(seteuid(0) == -1 && geteuid() == UNPRIVILEGED_ID);
	assert(setuid(0) == -1 && getuid() == UNPRIVILEGED_ID);
#ifdef HAVE_LCAP
	assert(hasCaps() == TRUE);
#else
	/* Opened as root, and never inherited by PHP or script children. */
	assert(ping_icmp_shared_available());
	int probe = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	assert(probe == -1 && errno == EPERM);
#endif
}

/* When ICMP cannot be had, spine still drops root for good and keeps
 * running; only ICMP availability is lost. */
static void setuid_without_icmp_body(void) {
#ifdef HAVE_LCAP
	cap_value_t net_raw = CAP_NET_RAW;
	cap_t caps;
#else
	struct rlimit none = {0, 0};
#endif
	set.exit.exit_code = EXIT_SUCCESS;
	set.php.php_initialized = FALSE;
	become_setuid_root_caller();
#ifdef HAVE_LCAP
	/* cap_set_proc() cannot keep a capability that is no longer permitted. */
	caps = cap_get_proc();
	assert(caps != NULL);
	assert(cap_set_flag(caps, CAP_PERMITTED, 1, &net_raw, CAP_CLEAR) == 0);
	assert(cap_set_flag(caps, CAP_EFFECTIVE, 1, &net_raw, CAP_CLEAR) == 0);
	assert(cap_set_proc(caps) == 0);
	assert(cap_free(caps) == 0);
#else
	/* With no descriptor to spare, the raw sockets cannot open. */
	assert(setrlimit(RLIMIT_NOFILE, &none) == 0);
#endif
	drop_privileges();
	assert(privileges_dropped(UNPRIVILEGED_ID, UNPRIVILEGED_ID));
	assert(!ping_icmp_shared_available());
	assert(hasCaps() == FALSE);
#ifdef HAVE_LCAP
	/* PR_SET_KEEPCAPS must not have carried root's other capabilities over. */
	caps = cap_get_proc();
	assert(caps != NULL);
	for (cap_value_t value = 0; value < 64; value++) {
		cap_flag_value_t flag;
		assert(cap_get_flag(caps, value, CAP_PERMITTED, &flag) != 0 || flag == CAP_CLEAR);
	}
	assert(cap_free(caps) == 0);
#endif
	fprintf(stderr, "drop_privileges returned\n");
}

#ifdef HAVE_LCAP
/* A real root run of an --enable-lcap build is confined to CAP_NET_RAW.  When
 * that cannot be done it must stop, not carry on with every capability. */
static void real_root_unconfinable_body(void) {
	cap_value_t net_raw = CAP_NET_RAW;
	cap_t caps = cap_get_proc();
	set.exit.exit_code = EXIT_SUCCESS;
	set.php.php_initialized = FALSE;
	assert(caps != NULL);
	assert(cap_set_flag(caps, CAP_PERMITTED, 1, &net_raw, CAP_CLEAR) == 0);
	assert(cap_set_flag(caps, CAP_EFFECTIVE, 1, &net_raw, CAP_CLEAR) == 0);
	assert(cap_set_proc(caps) == 0);
	assert(cap_free(caps) == 0);
	drop_privileges();
	fprintf(stderr, "drop_privileges returned\n");
}

/* All ids non-zero is not enough: a capability kept in the permitted set can
 * be raised again without any uid change. */
static void retained_capabilities_body(void) {
	assert(prctl(PR_SET_KEEPCAPS, 1) == 0);
	assert(setgroups(0, NULL) == 0);
	assert(setresgid(UNPRIVILEGED_ID, UNPRIVILEGED_ID, UNPRIVILEGED_ID) == 0);
	assert(setresuid(UNPRIVILEGED_ID, UNPRIVILEGED_ID, UNPRIVILEGED_ID) == 0);
	assert(seteuid(0) == -1);
	assert(!privileges_dropped(UNPRIVILEGED_ID, UNPRIVILEGED_ID));
}
#endif
#endif

void test_privilege_contracts(void) {
	char output[2048];
	uid_t uid = getuid();
	gid_t gid = getgid();

	assert(!privileges_dropped(0, gid));
	if (geteuid() != 0) {
		/* An unprivileged run has nothing to drop and keeps its ids. */
		drop_privileges();
		assert(getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid);
		assert(privileges_dropped(uid, gid));
		assert(!privileges_dropped(uid + 1, gid));
		assert(!privileges_dropped(uid, gid + 1));
		assert(!ping_icmp_shared_available());
		puts("production unprivileged startup contracts passed");
		return;
	}

#ifdef __linux__
	if (uid == 0) {
		assert(run_child(setuid_drop_body, output, sizeof(output)) == EXIT_SUCCESS);
		assert(run_child(setuid_without_icmp_body, output, sizeof(output)) == EXIT_SUCCESS);
		assert(strstr(output, "refusing to run") == NULL);
		assert(strstr(output, "drop_privileges returned") != NULL);
#ifdef HAVE_LCAP
		assert(run_child(retained_capabilities_body, output, sizeof(output)) == EXIT_SUCCESS);
		assert(run_child(real_root_unconfinable_body, output, sizeof(output)) == EXIT_FAILURE);
		assert(strstr(output, "could not confine itself to CAP_NET_RAW") != NULL);
		assert(strstr(output, "drop_privileges returned") == NULL);
#endif
		puts("production setuid privilege drop contracts passed");
	}
#else
	(void) output;
#endif
}

static void *ping_loopback(void *argument) {
	host_t host = {0};
	ping_t ping = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	host.id = (int) (intptr_t) argument;
	host.availability.timeout = 1000;
	host.availability.retries = 1;
	return (void *) (intptr_t) ping_icmp(&host, &ping);
}

/* Run from a copy of this binary installed setuid root and started by an
 * unprivileged user, with net.ipv4.ping_group_range closed so the shared or
 * capability path is the one that answers. */
void test_setuid_icmp(void) {
	uid_t uid = getuid();
	gid_t gid = getgid();
	pthread_t threads[8];

	assert(uid != 0 && geteuid() == 0);
	drop_privileges();
	assert(privileges_dropped(uid, gid));
	assert(status_ids_are("Uid:", uid));
	init_mutexes();
	checkAsRoot();
	assert(set.availability.icmp_avail);
	for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); i++) {
		assert(pthread_create(&threads[i], NULL, ping_loopback, (void *) (intptr_t) (i + 1)) == 0);
	}
	for (size_t i = 0; i < sizeof(threads) / sizeof(threads[0]); i++) {
		void *result;
		assert(pthread_join(threads[i], &result) == 0);
		assert((intptr_t) result == HOST_UP);
	}
#ifdef SPINE_HAVE_ICMPV6
	/* The IPv6 socket shares the same hand-over.  get_address_type() asks
	 * for AI_ADDRCONFIG, so ::1 only resolves on a host with a configured
	 * IPv6 address; skip it elsewhere. */
	host_t host6 = {0};
	ping_t ping6 = {0};
	STRNCOPY(host6.hostname, "::1");
	host6.availability.method = AVAIL_PING;
	host6.availability.ping_method = PING_ICMP;
	host6.availability.timeout = 1000;
	host6.availability.retries = 1;
	if (get_address_type(&host6) == SPINE_IPV6) {
		assert(ping_host(&host6, &ping6) == HOST_UP);
		assert(strcmp(ping6.ping_response, "ICMPv6: Device is Alive") == 0);
		puts("setuid ICMPv6 loopback answered");
	}
#endif
	assert(privileges_dropped(uid, gid));
	printf("setuid ICMP: uid=%d euid=%d shared=%d caps=%d\n", (int) getuid(), (int) geteuid(),
		ping_icmp_shared_available(), hasCaps());
}

/* One device per thread: two in three are loopback addresses that answer, the
 * rest are TEST-NET-1 addresses that never do.  Timeouts and retries vary so
 * readers come and go while others still wait. */
static void *stress_device(void *argument) {
	int index = (int) (intptr_t) argument;
	int up = (index % 3) != 0;
	host_t host = {0};
	ping_t ping = {0};
	if (up) {
		snprintf(host.hostname, sizeof(host.hostname), "127.0.%d.%d", (index / 200) + 1, (index % 200) + 1);
	} else {
		snprintf(host.hostname, sizeof(host.hostname), "192.0.2.%d", (index % 250) + 1);
	}
	host.id = index;
	host.availability.timeout = up ? 300 + (index % 7) * 100 : 200 + (index % 5) * 150;
	host.availability.retries = index % 3;
	int result = ping_icmp(&host, &ping);
	if (up && result != HOST_UP) return (void *) (intptr_t) 1;
	if (!up && result == HOST_UP) return (void *) (intptr_t) 2;
	return NULL;
}

/* Linux only; run as root.  Reproduces a setuid root start (or, with
 * SPINE_STRESS_REAL_ROOT set, a real root one that opens a socket per ping)
 * and pings SPINE_STRESS_THREADS devices at once, `rounds` times.  Run it
 * with net.ipv4.ping_group_range closed so raw sockets answer, and with an
 * ICMP flood aimed at the host to see how many responsive devices it hides. */
void test_setuid_stress(int rounds) {
#ifdef __linux__
	const char *requested = getenv("SPINE_STRESS_THREADS");
	int count = requested != NULL ? atoi(requested) : 96;
	int falsely_down = 0;
	int falsely_up = 0;
	int expected_up = 0;
	double begin;
	pthread_t *threads;

	assert(getuid() == 0 && count > 0 && count <= 1000 && rounds > 0);
	if (getenv("SPINE_STRESS_REAL_ROOT") == NULL) {
		become_setuid_root_caller();
		drop_privileges();
		assert(privileges_dropped(UNPRIVILEGED_ID, UNPRIVILEGED_ID));
	}
	init_mutexes();
	checkAsRoot();
	assert(set.availability.icmp_avail);
	threads = calloc((size_t) count, sizeof(*threads));
	assert(threads != NULL);
	begin = get_time_as_double();
	for (int round = 0; round < rounds; round++) {
		for (int i = 0; i < count; i++) {
			int index = i + round * count;
			if (index % 3 != 0) expected_up++;
			assert(pthread_create(&threads[i], NULL, stress_device, (void *) (intptr_t) index) == 0);
		}
		for (int i = 0; i < count; i++) {
			void *outcome;
			assert(pthread_join(threads[i], &outcome) == 0);
			if ((intptr_t) outcome == 1) falsely_down++;
			if ((intptr_t) outcome == 2) falsely_up++;
		}
	}
	free(threads);
	printf("stress %s threads=%d rounds=%d falsely-down=%d of %d up, falsely-up=%d, elapsed=%.2fs\n",
		ping_icmp_shared_available() ? "shared" : "per-ping", count, rounds,
		falsely_down, expected_up, falsely_up, get_time_as_double() - begin);
#else
	(void) rounds;
	puts("stress mode needs Linux");
#endif
}
