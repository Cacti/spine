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
#include "common.h"
#include "spine.h"
#include <dirent.h>
#include <spawn.h>
#include <fcntl.h>

/* GNU ld wraps the actual API boundary. No production test-only code is used. */
extern size_t __real_strftime(char *, size_t, const char *, const struct tm *);
extern int __real_mysql_query(MYSQL *, const char *);
extern int __real_mysql_ping(MYSQL *);
extern unsigned int __real_mysql_errno(MYSQL *);
extern int __real_pipe(int [2]);
extern int __real_socketpair(int, int, int, int [2]);
extern int __real_posix_spawn(pid_t *, const char *, const posix_spawn_file_actions_t *,
	const posix_spawnattr_t *, char *const [], char *const []);
extern void *__real_malloc(size_t);
extern char *__real_strdup(const char *);
extern void *__real_snmp_sess_open(netsnmp_session *);
extern int __real_snmp_sess_close(void *);
extern int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern int spine_program_main(int, char **);
extern poller_thread_t **details;

static int format_failures;
static int format_fault_calls;
static MYSQL *query_fault_connection;
static const char *query_fault_statement;
static int query_fault_armed;
static int observed_query_error;
static int query_fault_calls;
static int query_ping_calls;
static MYSQL *interrupted_connection;
static int interrupted_queries;
static int interrupted_query_calls;
static int pipe_failures;
static int socketpair_failures;
static int spawn_failures;
static int spawn_failure_errno;
static int spawn_fault_calls;
static int allocation_failures;
static int copy_failures;
static const char *copy_failure_text;
static bool account_snmp_sessions;
static void *owned_snmp_session;
static int session_opens;
static int session_close_attempts;
static int session_closes;
static bool launch_case_active;
static int launch_error;
static int launch_failures;
static int launch_expected_faults;
static int launch_calls;
static int launch_fault_calls;
static int launch_checkpoints;
static int launch_device_counter;
static spine_permits_t *launch_startup;

int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
	void *(*start)(void *), void *arg) {
	if (!launch_case_active || start != &child) return __real_pthread_create(thread, attributes, start, arg);
	const poller_thread_t *work = arg;
	assert(work != NULL && work->host_id == 902);
	launch_calls++;
	launch_device_counter = work->device_counter;
	launch_startup = work->thread_init_sem;
	if (launch_failures > 0) {
		launch_failures--;
		launch_fault_calls++;
		return launch_error;
	}
	return __real_pthread_create(thread, attributes, start, arg);
}

static void inspect_worker_launch_completion(void) {
	assert(launch_startup != NULL && launch_calls > 0);
	assert(spine_permits_available(&available_threads) == 1);
	assert(spine_permits_available(launch_startup) == 1);
	assert(spine_permits_available(&available_scripts) == MAX_SIMULTANEOUS_SCRIPTS);
	assert(db_pool_local != NULL && db_pool_local[0].free);
	thread_mutex_lock(LOCK_THDET);
	const poller_thread_t *device = details[launch_device_counter];
	assert(device != NULL && device->host_id == 902);
	if (launch_error == EPERM) {
		assert(set.exit.exit_code == EXIT_FAILURE && !device->complete);
		assert(device->threads_complete == 0 && !device->output_failed);
	} else {
		assert(set.exit.exit_code == EXIT_SUCCESS && device->complete);
		assert(device->threads_complete == 1 && !device->output_failed);
	}
	thread_mutex_unlock(LOCK_THDET);
	launch_checkpoints++;
}

static void verify_worker_launch_exit(void) {
	fflush(NULL);
	fprintf(stderr, "worker launch checkpoint: checkpoints=%i calls=%i faults=%i pending=%i exit=%i\n", launch_checkpoints, launch_calls, launch_fault_calls, launch_failures, set.exit.exit_code);
	assert(launch_checkpoints == 1 && launch_failures == 0);
	assert(launch_fault_calls == launch_expected_faults);
	assert(launch_calls == (launch_error == EAGAIN ? 2 : 1));
	puts("production worker launch completion checkpoint passed");
}

void *__wrap_snmp_sess_open(netsnmp_session *session) {
	void *handle = __real_snmp_sess_open(session);
	if (account_snmp_sessions && handle != NULL) {
		assert(owned_snmp_session == NULL);
		owned_snmp_session = handle;
		session_opens++;
	}
	return handle;
}

int __wrap_snmp_sess_close(void *handle) {
	bool owned = account_snmp_sessions && handle == owned_snmp_session && handle != NULL;
	if (owned) session_close_attempts++;
	int result = __real_snmp_sess_close(handle);
	if (owned && result == 1) {
		session_closes++;
		owned_snmp_session = NULL;
	}
	return result;
}

size_t __wrap_strftime(char *output, size_t capacity, const char *format, const struct tm *time) {
	if (format_failures > 0) {
		format_failures--;
		format_fault_calls++;
		return 0; /* strftime documents zero when its destination is insufficient. */
	}
	return __real_strftime(output, capacity, format, time);
}

int __wrap_mysql_query(MYSQL *mysql, const char *query) {
	static const char completion[] = "UPDATE poller_time SET end_time=NOW() WHERE poller_id=";
	/* The interrupted handle is never connected; it must not reach the client library. */
	if (mysql == interrupted_connection) {
		interrupted_query_calls++;
		if (interrupted_queries > 0) {
			interrupted_queries--;
			errno = EINTR;
			return 1;
		}
		return 0;
	}
	if (launch_case_active && strncmp(query, completion, sizeof(completion) - 1) == 0) {
		inspect_worker_launch_completion();
	}
	if (query_fault_armed && mysql == query_fault_connection && strcmp(query, query_fault_statement) == 0) {
		query_fault_armed = 0;
		bool reconnect = FALSE;
		assert(mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect) == 0);
		int result = __real_mysql_query(mysql, query);
		observed_query_error = (int)mysql_errno(mysql);
		assert(result != 0 && (observed_query_error == 2006 || observed_query_error == 2013));
		reconnect = TRUE;
		assert(mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect) == 0);
		assert((int)mysql_errno(mysql) == observed_query_error);
		query_fault_calls++;
		return result;
	}
	return __real_mysql_query(mysql, query);
}

int __wrap_mysql_ping(MYSQL *mysql) {
	if (mysql == query_fault_connection) query_ping_calls++;
	return __real_mysql_ping(mysql);
}

unsigned int __wrap_mysql_errno(MYSQL *mysql) {
	if (mysql == interrupted_connection) return 2013;
	return __real_mysql_errno(mysql);
}

int __wrap_pipe(int descriptors[2]) {
	if (pipe_failures > 0) { pipe_failures--; errno = EMFILE; return -1; }
	return __real_pipe(descriptors);
}

int __wrap_socketpair(int domain, int type, int protocol, int descriptors[2]) {
	if (socketpair_failures > 0) { socketpair_failures--; errno = EMFILE; return -1; }
	return __real_socketpair(domain, type, protocol, descriptors);
}

/* Script children are created with posix_spawn(), which reports failure
 * through its return value rather than errno. */
int __wrap_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *actions,
		const posix_spawnattr_t *attributes, char *const arguments[], char *const environment[]) {
	if (spawn_failures > 0) { spawn_failures--; spawn_fault_calls++; return spawn_failure_errno; }
	return __real_posix_spawn(pid, path, actions, attributes, arguments, environment);
}

void *__wrap_malloc(size_t size) {
	if (allocation_failures > 0) { allocation_failures--; errno = ENOMEM; return NULL; }
	return __real_malloc(size);
}

char *__wrap_strdup(const char *text) {
	if (copy_failures > 0) { copy_failures--; errno = ENOMEM; return NULL; }
	if (copy_failure_text != NULL && strcmp(text, copy_failure_text) == 0) { errno = ENOMEM; return NULL; }
	return __real_strdup(text);
}

/* Identity and ICMP socket faults.  A setuid root start cannot be reproduced
 * by an unprivileged `make check`, so the ids the kernel would report, and the
 * rules it applies to changing them, are modelled here for drop_privileges()
 * and checkAsRoot().  Every case runs in a child so the process-wide state
 * they set (the shared sockets, the setuid flag) cannot leak between cases. */
extern uid_t __real_getuid(void);
extern uid_t __real_geteuid(void);
extern gid_t __real_getgid(void);
extern gid_t __real_getegid(void);
extern int __real_setuid(uid_t);
extern int __real_setgid(gid_t);
extern int __real_seteuid(uid_t);
extern int __real_setegid(gid_t);
extern int __real_socket(int, int, int);

static bool ids_faked;
static uid_t fake_ruid, fake_euid, fake_suid;
static gid_t fake_rgid, fake_egid, fake_sgid;
static bool setuid_refused;
static bool setuid_keeps_saved;
static bool setgid_keeps_saved;
static bool icmp_faked;
static bool raw_icmp_allowed;
static bool dgram_icmp_allowed;

uid_t __wrap_getuid(void) { return ids_faked ? fake_ruid : __real_getuid(); }
uid_t __wrap_geteuid(void) { return ids_faked ? fake_euid : __real_geteuid(); }
gid_t __wrap_getgid(void) { return ids_faked ? fake_rgid : __real_getgid(); }
gid_t __wrap_getegid(void) { return ids_faked ? fake_egid : __real_getegid(); }

/* POSIX: with euid 0 setuid() sets all three ids; otherwise only the
 * effective id may change, and only to the real or saved id. */
int __wrap_setuid(uid_t uid) {
	if (!ids_faked) return __real_setuid(uid);
	if (setuid_refused) { errno = EAGAIN; return -1; }
	if (fake_euid == 0) {
		fake_ruid = fake_euid = uid;
		if (!setuid_keeps_saved) fake_suid = uid;
		return 0;
	}
	if (uid == fake_ruid || uid == fake_suid) { fake_euid = uid; return 0; }
	errno = EPERM;
	return -1;
}

int __wrap_setgid(gid_t gid) {
	if (!ids_faked) return __real_setgid(gid);
	if (fake_euid == 0) {
		fake_rgid = fake_egid = gid;
		if (!setgid_keeps_saved) fake_sgid = gid;
		return 0;
	}
	if (gid == fake_rgid || gid == fake_sgid) { fake_egid = gid; return 0; }
	errno = EPERM;
	return -1;
}

int __wrap_seteuid(uid_t uid) {
	if (!ids_faked) return __real_seteuid(uid);
	if (fake_euid == 0 || uid == fake_ruid || uid == fake_suid) { fake_euid = uid; return 0; }
	errno = EPERM;
	return -1;
}

int __wrap_setegid(gid_t gid) {
	if (!ids_faked) return __real_setegid(gid);
	if (fake_euid == 0 || gid == fake_rgid || gid == fake_sgid) { fake_egid = gid; return 0; }
	errno = EPERM;
	return -1;
}

/* An allowed ICMP socket is stood in for by a local datagram socket. */
int __wrap_socket(int domain, int type, int protocol) {
	int base = type;
	#ifdef SOCK_CLOEXEC
	base &= ~SOCK_CLOEXEC;
	#endif
	if (!icmp_faked || (protocol != IPPROTO_ICMP && protocol != IPPROTO_ICMPV6)) {
		return __real_socket(domain, type, protocol);
	}
	if ((base == SOCK_RAW && raw_icmp_allowed) || (base == SOCK_DGRAM && dgram_icmp_allowed)) {
		return __real_socket(AF_UNIX, SOCK_DGRAM | (type & ~base), 0);
	}
	errno = EPERM;
	return -1;
}


typedef void (*identity_case_t)(void);

/* Runs one case in a child; returns its exit status with its output. */
static int run_identity_case(identity_case_t body, char *output, size_t capacity) {
	int descriptors[2];
	assert(__real_pipe(descriptors) == 0);
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		assert(close(descriptors[0]) == 0);
		assert(dup2(descriptors[1], STDOUT_FILENO) == STDOUT_FILENO);
		assert(dup2(descriptors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(descriptors[1]) == 0);
		set.exit.exit_code = EXIT_SUCCESS;
		set.php.php_initialized = FALSE;
		set.logging.log_level = POLLER_VERBOSITY_DEBUG;
		set.logging.log_destination = LOGDEST_STDOUT;
		body();
		fflush(NULL);
		/* exit(), not _exit(), so the child's coverage counters are kept */
		exit(EXIT_SUCCESS);
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

#ifndef HAVE_LCAP
static void fake_setuid_root_start(uid_t uid, gid_t gid) {
	ids_faked = TRUE;
	fake_ruid = uid;
	fake_euid = fake_suid = 0;
	fake_rgid = fake_egid = fake_sgid = gid;
	icmp_faked = TRUE;
}

static void setuid_start_with_raw_icmp(void) {
	fake_setuid_root_start(1000, 1000);
	raw_icmp_allowed = TRUE;
	drop_privileges();
	assert(fake_ruid == 1000 && fake_euid == 1000 && fake_suid == 1000);
	assert(fake_rgid == 1000 && fake_egid == 1000 && fake_sgid == 1000);
	assert(ping_icmp_shared_available());
	/* nothing can open another raw socket now, and none is needed */
	raw_icmp_allowed = FALSE;
	checkAsRoot();
	assert(set.availability.icmp_avail);
}

static void setuid_start_without_icmp(void) {
	fake_setuid_root_start(1000, 1000);
	drop_privileges();
	assert(fake_euid == 1000 && fake_suid == 1000);
	assert(!ping_icmp_shared_available());
	checkAsRoot();
	assert(!set.availability.icmp_avail);
}

static void setuid_start_with_datagram_icmp(void) {
	fake_setuid_root_start(1000, 1000);
	drop_privileges();
	dgram_icmp_allowed = TRUE;
	checkAsRoot();
	assert(set.availability.icmp_avail);
}

static void setuid_start_setuid_refused(void) {
	fake_setuid_root_start(1000, 1000);
	raw_icmp_allowed = TRUE;
	setuid_refused = TRUE;
	drop_privileges();
}

static void setuid_start_saved_uid_kept(void) {
	fake_setuid_root_start(1000, 1000);
	setuid_keeps_saved = TRUE;
	drop_privileges();
}

/* A setuid and setgid root install starts with an effective gid of 0. */
static void setuid_start_saved_gid_kept(void) {
	fake_setuid_root_start(1000, 1000);
	fake_egid = fake_sgid = 0;
	setgid_keeps_saved = TRUE;
	drop_privileges();
}

static void real_root_start(void) {
	ids_faked = TRUE;
	icmp_faked = TRUE;
	drop_privileges();
	assert(fake_ruid == 0 && fake_euid == 0 && fake_suid == 0);
	checkAsRoot();
	assert(set.availability.icmp_avail);
}

#endif

static void unprivileged_start(void) {
	ids_faked = TRUE;
	fake_ruid = fake_euid = fake_suid = 1000;
	fake_rgid = fake_egid = fake_sgid = 1000;
	icmp_faked = TRUE;
	drop_privileges();
	assert(!ping_icmp_shared_available());
	/* a file capability */
	raw_icmp_allowed = TRUE;
	checkAsRoot();
	assert(set.availability.icmp_avail);
	/* net.ipv4.ping_group_range */
	raw_icmp_allowed = FALSE;
	dgram_icmp_allowed = TRUE;
	checkAsRoot();
	assert(set.availability.icmp_avail);
	/* neither */
	dgram_icmp_allowed = FALSE;
	checkAsRoot();
	assert(!set.availability.icmp_avail);
}

static void test_privilege_drop_faults(void) {
	char output[8192];
	#ifndef HAVE_LCAP
	/* With libcap the drop goes through prctl(), setgroups() and the cap_*
	 * calls, which these fakes do not model; regressions.yml runs it for real. */
	assert(run_identity_case(setuid_start_with_raw_icmp, output, sizeof(output)) == EXIT_SUCCESS);
	assert(strstr(output, "raw ICMP sockets it opened before dropping root") != NULL);
	assert(run_identity_case(setuid_start_without_icmp, output, sizeof(output)) == EXIT_SUCCESS);
	assert(strstr(output, "WARNING: Spine is setuid root but could not get raw ICMP access") != NULL);
	assert(run_identity_case(setuid_start_with_datagram_icmp, output, sizeof(output)) == EXIT_SUCCESS);
	assert(strstr(output, "may use unprivileged ICMP sockets") != NULL);
	assert(run_identity_case(setuid_start_setuid_refused, output, sizeof(output)) == EXIT_FAILURE);
	assert(strstr(output, "could not drop to uid 1000/gid 1000; refusing to run") != NULL);
	assert(run_identity_case(setuid_start_saved_uid_kept, output, sizeof(output)) == EXIT_FAILURE);
	assert(strstr(output, "could not drop root permanently; refusing to run") != NULL);
	assert(run_identity_case(setuid_start_saved_gid_kept, output, sizeof(output)) == EXIT_FAILURE);
	assert(strstr(output, "could not drop root permanently; refusing to run") != NULL);
	assert(run_identity_case(real_root_start, output, sizeof(output)) == EXIT_SUCCESS);
	assert(strstr(output, "Spine is running as root") != NULL);
	#endif
	assert(run_identity_case(unprivileged_start, output, sizeof(output)) == EXIT_SUCCESS);
	assert(strstr(output, "may open raw ICMP sockets") != NULL);
	assert(strstr(output, "Spine has no ICMP access") != NULL);
	assert(strstr(output, "WARNING: Spine is setuid root") == NULL);
	puts("production privilege drop faults passed");
}

static void test_logger_format_failure(void) {
	config_t previous = set;
	char filename[] = "spine-log-fault-XXXXXX";
	int log = mkstemp(filename);
	assert(log >= 0 && close(log) == 0);
	set.logging.log_destination = LOGDEST_FILE;
	set.logging.log_level = POLLER_VERBOSITY_LOW;
	set.logging.logfile_processed = TRUE;
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = FALSE;
	STRNCOPY(set.logging.path_logfile, filename);
	#ifdef DISABLE_STDERR
	const int diagnostic = STDOUT_FILENO;
	set.console.stdout_notty = FALSE;
	#else
	const int diagnostic = STDERR_FILENO;
	#endif
	int saved = dup(diagnostic);
	int capture[2];
	assert(saved >= 0 && pipe(capture) == 0);
	fflush(NULL);
	assert(dup2(capture[1], diagnostic) == diagnostic && close(capture[1]) == 0);
	format_failures = 1;
	format_fault_calls = 0;
	/* Date formatting failure reports a warning and preserves sink delivery. */
	assert(spine_log("regression date fallback") == TRUE);
	assert(format_failures == 0 && format_fault_calls == 1);
	fflush(NULL);
	assert(dup2(saved, diagnostic) == diagnostic && close(saved) == 0);
	char response[LOGSIZE * 2];
	ssize_t received = read(capture[0], response, sizeof(response) - 1);
	assert(received > 0 && (size_t)received < sizeof(response) && close(capture[0]) == 0);
	response[received] = '\0';
	assert(strstr(response, "ERROR: Could not get string from strftime()") != NULL);
	assert(strstr(response, "regression date fallback") != NULL);

	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	saved = dup(diagnostic);
	assert(saved >= 0 && pipe(capture) == 0);
	assert(dup2(capture[1], diagnostic) == diagnostic && close(capture[1]) == 0);
	format_failures = 1;
	assert(spine_log("regression quiet date fallback") == TRUE);
	fflush(NULL);
	assert(dup2(saved, diagnostic) == diagnostic && close(saved) == 0);
	assert(read(capture[0], response, sizeof(response)) == 0 && close(capture[0]) == 0);
	assert(format_failures == 0 && format_fault_calls == 2);
	FILE *file = fopen(filename, "r");
	assert(file != NULL);
	size_t bytes = fread(response, 1, sizeof(response) - 1, file);
	assert(bytes > 0 && bytes < sizeof(response) && !ferror(file) && fclose(file) == 0);
	response[bytes] = '\0';
	assert(strstr(response, "regression date fallback") != NULL);
	assert(strstr(response, "regression quiet date fallback") != NULL);
	assert(strncmp(response, "SPINE: Poller[", strlen("SPINE: Poller[")) == 0);
	assert(unlink(filename) == 0);
	set = previous;
	puts("production logger date-format failure regressions passed");
}

static unsigned int open_descriptor_count(void) {
	DIR *directory = opendir("/proc/self/fd");
	assert(directory != NULL);
	unsigned int count = 0;
	const struct dirent *entry;
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) count++;
	}
	assert(closedir(directory) == 0);
	return count;
}

static void assert_cancel_state(int expected) {
	int previous;
	assert(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
	assert(previous == expected);
	assert(pthread_setcancelstate(previous, NULL) == 0);
}

static void test_child_setup_failures(unsigned int expected_descriptors) {
	/* Redirection and exec now happen inside posix_spawn(), out of reach of
	 * the dup2()/execve() wrappers, so drive the failure through the shell:
	 * a command that cannot execute must still be reaped with 127 and must not
	 * leak a descriptor in either pipe mode. */
	for (int index = 0; index < 2; index++) {
		int descriptor = nft_popen("/spine-regression/nonexistent-command 2>/dev/null", index == 1 ? "r+" : "r");
		assert(descriptor >= 0);
		char bytes[3];
		assert(read(descriptor, bytes, sizeof(bytes)) == 0);
		int status = nft_pclose(descriptor);
		assert(status == -1 || (WIFEXITED(status) && WEXITSTATUS(status) == 127));
		assert(open_descriptor_count() == expected_descriptors);
	}
}

static void test_process_creation_failures(void) {
	unsigned int descriptors = open_descriptor_count();
	int unrelated[2];
	assert(pipe(unrelated) == 0);
	unsigned int with_unrelated = open_descriptor_count();
	assert(with_unrelated == descriptors + 2);
	pipe_failures = 1;
	assert(nft_popen("printf unused", "r") == -1 && errno == EMFILE);
	assert(pipe_failures == 0 && open_descriptor_count() == with_unrelated);
	socketpair_failures = 1;
	assert(nft_popen("printf unused", "r+") == -1 && errno == EMFILE);
	assert(socketpair_failures == 0 && open_descriptor_count() == with_unrelated);
	allocation_failures = 1;
	assert(nft_popen("printf unused", "r") == -1 && errno == ENOMEM);
	assert(allocation_failures == 0 && open_descriptor_count() == with_unrelated);
	assert_cancel_state(PTHREAD_CANCEL_ENABLE);
	copy_failures = 1;
	assert(nft_popen("printf unused", "r") == -1 && errno == ENOMEM);
	assert(copy_failures == 0 && open_descriptor_count() == with_unrelated);
	assert_cancel_state(PTHREAD_CANCEL_ENABLE);
	spawn_failures = 4;
	spawn_failure_errno = EAGAIN;
	spawn_fault_calls = 0;
	assert(nft_popen("printf unused", "r") == -1 && errno == EAGAIN);
	assert(spawn_failures == 0 && spawn_fault_calls == 4 && open_descriptor_count() == with_unrelated);
	assert_cancel_state(PTHREAD_CANCEL_ENABLE);
	spawn_failures = 1;
	spawn_failure_errno = EPERM;
	spawn_fault_calls = 0;
	assert(nft_popen("printf unused", "r") == -1 && errno == EPERM);
	assert(spawn_failures == 0 && spawn_fault_calls == 1 && open_descriptor_count() == with_unrelated);
	spawn_failures = 2;
	spawn_failure_errno = EAGAIN;
	spawn_fault_calls = 0;
	int descriptor = nft_popen("printf ok", "r");
	assert(descriptor >= 0 && spawn_failures == 0 && spawn_fault_calls == 2);
	char bytes[3] = {0};
	assert(read(descriptor, bytes, 2) == 2 && strcmp(bytes, "ok") == 0);
	int status = nft_pclose(descriptor);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	assert(open_descriptor_count() == with_unrelated);
	test_child_setup_failures(with_unrelated);
	assert(write(unrelated[1], "x", 1) == 1 && read(unrelated[0], bytes, 1) == 1 && bytes[0] == 'x');
	assert(close(unrelated[0]) == 0 && close(unrelated[1]) == 0);
	assert(open_descriptor_count() == descriptors);
	puts("production process creation failure regressions passed");
}

static void kill_owned_connection(MYSQL *administrator, MYSQL *victim) {
	char query[100];
	spine_snprintf(query, sizeof(query), "KILL CONNECTION %lu", mysql_thread_id(victim));
	assert(mysql_query(administrator, query) == 0);
}

static void arm_lost_connection(MYSQL *mysql, const char *statement) {
	query_fault_connection = mysql;
	query_fault_statement = statement;
	query_fault_armed = 1;
	query_fault_calls = 0;
	query_ping_calls = 0;
	observed_query_error = 0;
}

/* A lost-connection error raised while a signal interrupted the call is
 * retried in place: db_insert() must neither give up nor ping for a reconnect. */
static void test_interrupted_insert_retry(void) {
	MYSQL offline;
	assert(mysql_init(&offline) == &offline);
	set.poller.SQL_readonly = FALSE;
	interrupted_connection = &offline;
	interrupted_queries = 1;
	interrupted_query_calls = 0;
	query_fault_connection = &offline;
	query_ping_calls = 0;
	assert(db_insert(&offline, LOCAL, "INSERT INTO interrupted(value) VALUES(1)"));
	assert(interrupted_queries == 0 && interrupted_query_calls == 2 && query_ping_calls == 0);
	interrupted_connection = NULL;
	query_fault_connection = NULL;
	mysql_close(&offline);
	puts("production interrupted insert retry regressions passed");
}

/* die() ends the process, so the copy failure runs in a child. The
 * authentication copy has already succeeded and must be released first. */
static void test_snmpv3_privacy_copy_failure(void) {
	int output[2];
	assert(pipe(output) == 0);
	fflush(stdout);
	fflush(stderr);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		if (dup2(output[1], STDERR_FILENO) != STDERR_FILENO) _exit(3);
		close(output[0]);
		close(output[1]);
		snmp_spine_init();
		copy_failure_text = "fault-privacy-passphrase";
		snmp_connection_t options = {
			.host_id = 47, .hostname = "127.0.0.1", .snmp_version = 3,
			.snmp_community = "", .snmp_username = "fault-v3-user",
			.snmp_password = "fault-auth-passphrase", .snmp_auth_protocol = "SHA",
			.snmp_priv_passphrase = "fault-privacy-passphrase", .snmp_priv_protocol = "AES",
			.snmp_context = "", .snmp_engine_id = "", .snmp_port = 1162,
			.snmp_timeout = 500
		};
		snmp_host_init(&options);
		_exit(4);
	}
	assert(close(output[1]) == 0);
	char message[BUFSIZE] = {0};
	size_t used = 0;
	ssize_t count;
	while (used < sizeof(message) - 1 && (count = read(output[0], message + used, sizeof(message) - 1 - used)) > 0) {
		used += (size_t)count;
	}
	assert(close(output[0]) == 0);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
	assert(strstr(message, "ERROR: Fatal malloc error: SNMP privacy passphrase") != NULL);
	assert(strstr(message, "fault-auth-passphrase") == NULL);
	puts("production SNMPv3 privacy copy failure regressions passed");
}

static void test_real_database_retry(void) {
	const char *hostname = getenv("SPINE_TEST_DB_HOST");
	assert(hostname != NULL && hostname[0] != '\0');
	config_defaults();
	strncopy(set.database.host, hostname, sizeof(set.database.host));
	STRNCOPY(set.database.user, "root");
	STRNCOPY(set.database.database, "spine_regressions");
	set.database.password[0] = '\0';
	set.database.port = 3306;
	set.poller.SQL_readonly = FALSE;
	set.logging.log_destination = 0;
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	MYSQL administrator;
	MYSQL victim;
	db_connect(LOCAL, &administrator);
	db_connect(LOCAL, &victim);
	unsigned long original = mysql_thread_id(&victim);
	kill_owned_connection(&administrator, &victim);
	const char *read_statement = "SELECT 123 AS recovered_value";
	arm_lost_connection(&victim, read_statement);
	MYSQL_RES *result = db_query(&victim, LOCAL, read_statement);
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "123") == 0);
	db_free_result(result);
	assert(query_fault_calls == 1 && query_ping_calls == 1 && !query_fault_armed && observed_query_error != 0);
	assert(mysql_thread_id(&victim) != original);
	char table[100];
	spine_snprintf(table, sizeof(table), "spine_fault_%ld", (long)getpid());
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "CREATE TABLE %s (value INT NOT NULL) ENGINE=InnoDB", table);
	assert(db_insert(&administrator, LOCAL, query));
	original = mysql_thread_id(&victim);
	kill_owned_connection(&administrator, &victim);
	spine_snprintf(query, sizeof(query), "INSERT INTO %s(value) VALUES(456)", table);
	arm_lost_connection(&victim, query);
	assert(db_insert(&victim, LOCAL, query));
	assert(query_fault_calls == 1 && query_ping_calls == 1 && !query_fault_armed && observed_query_error != 0);
	assert(mysql_thread_id(&victim) != original);
	spine_snprintf(query, sizeof(query), "SELECT value FROM %s", table);
	result = db_query(&administrator, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "456") == 0);
	db_free_result(result);
	spine_snprintf(query, sizeof(query), "DROP TABLE %s", table);
	assert(db_insert(&administrator, LOCAL, query));
	db_disconnect(&victim);
	db_disconnect(&administrator);
	query_fault_connection = NULL;
	query_fault_statement = NULL;
	puts("production real lost-connection retry regressions passed");
}

static unsigned long long fault_database_count(MYSQL *mysql, const char *query) {
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	unsigned long long count = strtoull(row[0], NULL, 10);
	db_free_result(result);
	return count;
}

static void *run_ping_only_worker(void *argument) {
	assert(mysql_thread_init() == 0);
	int errors = -1;
	poll_host(argument, &errors);
	assert(errors == -1); /* Early ping-only return preserves this output. */
	return NULL;
}

static void test_ping_only_session_lifetime(void) {
	extern int *debug_devices;
	const char *agent = getenv("SPINE_TEST_SNMP_HOST");
	assert(agent != NULL && agent[0] != '\0');
	config_t previous = set;
	int *previous_debug_devices = debug_devices;
	int debug_fixture[100] = {0};
	debug_devices = debug_fixture;
	pool_t *previous_pool = db_pool_local;
	set.poller.threads = 1;
	set.poller.poller_id = 1;
	set.poller.mode = REMOTE_OFFLINE;
	set.availability.ping_only = TRUE;
	set.snmp.snmp_retries = 0;
	set.snmp.mibs = 0;
	MYSQL administrator;
	db_connect(LOCAL, &administrator);
	/* Refuse to replace pre-existing records, even in the isolated fixture. */
	assert(fault_database_count(&administrator, "SELECT COUNT(*) FROM host WHERE id=900") == 0);
	assert(fault_database_count(&administrator, "SELECT COUNT(*) FROM poller_item WHERE host_id=900") == 0);
	unsigned long long outputs = fault_database_count(&administrator, "SELECT COUNT(*) FROM poller_output");
	unsigned long long boosted = fault_database_count(&administrator, "SELECT COUNT(*) FROM poller_output_boost");
	db_pool_local = calloc(1, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_pool_local[0].free = TRUE;
	db_connect(LOCAL, &db_pool_local[0].mysql);
	assert(spine_permits_init(&available_threads, 2) == 0);
	assert(spine_permits_init(&available_scripts, 3) == 0);
	char escaped_agent[BUFSIZE];
	db_escape(&administrator, escaped_agent, sizeof(escaped_agent), agent);
	snmp_spine_init();
	for (int with_session = 1; with_session >= 0; with_session--) {
		char query[LRG_BUFSIZE];
		spine_snprintf(query, sizeof(query), "INSERT INTO host(id,hostname,snmp_version,snmp_community,snmp_port,snmp_timeout,availability_method,status,total_polls,failed_polls,status_fail_date,status_rec_date,snmp_sysLocation) VALUES(900,'%s',2,'%s',1161,500,%i,%i,0,0,'2026-10-06 00:00:00','2026-10-06 00:00:00','ping-only-metadata')", escaped_agent, with_session ? "regression" : "", AVAIL_SNMP, HOST_UP);
		assert(db_insert(&administrator, LOCAL, query));
		poller_thread_t work = {0};
		work.host_id = 900;
		work.host_thread = 1;
		work.host_threads = 1;
		work.host_time_double = get_time_as_double();
		STRNCOPY(work.host_time, "1791244800");
		owned_snmp_session = NULL;
		session_opens = 0;
		session_close_attempts = 0;
		session_closes = 0;
		account_snmp_sessions = TRUE;
		pthread_t worker;
		assert(pthread_create(&worker, NULL, run_ping_only_worker, &work) == 0);
		assert(pthread_join(worker, NULL) == 0);
		account_snmp_sessions = FALSE;
		int observed_opens = session_opens;
		int observed_attempts = session_close_attempts;
		int observed_closes = session_closes;
		/* Preserve an old-code failure without leaking the task-owned fixture
		 * handle: this real cleanup is excluded from production close counts. */
		if (owned_snmp_session != NULL) {
			assert(__real_snmp_sess_close(owned_snmp_session) == 1);
			owned_snmp_session = NULL;
		}
		assert(db_pool_local[0].free);
		assert(spine_permits_available(&available_threads) == 2);
		assert(spine_permits_available(&available_scripts) == 3);
		spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM host WHERE id=900 AND status=%i AND total_polls=1 AND failed_polls=0 AND snmp_sysLocation='ping-only-metadata'", HOST_UP);
		assert(fault_database_count(&administrator, query) == 1);
		assert(fault_database_count(&administrator, "SELECT COUNT(*) FROM poller_output") == outputs);
		assert(fault_database_count(&administrator, "SELECT COUNT(*) FROM poller_output_boost") == boosted);
		assert(db_insert(&administrator, LOCAL, "DELETE FROM host WHERE id=900"));
		fprintf(stderr, "ping-only owned session accounting: session=%d opens=%d attempts=%d closes=%d\n", with_session, observed_opens, observed_attempts, observed_closes);
		assert(observed_opens == with_session);
		assert(observed_attempts == with_session && observed_closes == with_session);
	}
	snmp_spine_close();
	assert(spine_permits_destroy(&available_scripts) == 0);
	assert(spine_permits_destroy(&available_threads) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	db_disconnect(&administrator);
	debug_devices = previous_debug_devices;
	set = previous;
	puts("production ping-only SNMP session ownership regressions passed");
}

static int execute_worker_launch_case(const char *scenario, char *config) {
	assert(strcmp(scenario, "admitted") == 0 || strcmp(scenario, "rejected") == 0 || strcmp(scenario, "retry") == 0);
	launch_case_active = TRUE;
	if (strcmp(scenario, "rejected") == 0) launch_error = EPERM;
	else if (strcmp(scenario, "retry") == 0) launch_error = EAGAIN;
	launch_expected_faults = launch_error == 0 ? 0 : 1;
	launch_failures = launch_expected_faults;
	assert(atexit(verify_worker_launch_exit) == 0);
	alarm(15);
	char interval[] = "poller_interval:5";
	char profiles[] = "active_profiles:2";
	char boost[] = "boost_rrd_update_enable:0";
	char redirect[] = "boost_redirect:0";
	char *arguments[] = {"spine", "-C", "/nonexistent/spine-fault.conf", "--conf", config,
		"-p", "1", "-t", "1", "-H", "902", "-O", interval, "-O", profiles,
		"-O", boost, "-O", redirect, "-S", "-V", "2", NULL};
	return spine_program_main((int)(sizeof(arguments) / sizeof(arguments[0]) - 1), arguments);
}

static pid_t run_worker_launch_case(const char *scenario, const char *config, int expected) {
	fflush(NULL);
	pid_t process = fork();
	assert(process >= 0);
	if (process == 0) {
		execl("./test_spine_faults", "test_spine_faults", "--worker-launch-case", scenario, config, NULL);
		_exit(127);
	}
	int status;
	assert(waitpid(process, &status, 0) == process);
	fprintf(stderr, "worker launch case=%s expected=%i status=%i\n", scenario, expected, status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
	return process;
}

static void test_worker_launch_failures(void) {
	MYSQL mysql;
	db_connect(LOCAL, &mysql);
	/* Refuse any pre-existing spelling of this fixture identity. Grants are
	 * limited to DML on the isolated fixture; no global administrative rights. */
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM mysql.user WHERE User='spine_owned_launch'") == 0);
	assert(db_insert(&mysql, LOCAL, "CREATE USER 'spine_owned_launch'@'%' IDENTIFIED BY 'regression-only'"));
	assert(db_insert(&mysql, LOCAL, "GRANT SELECT,INSERT,UPDATE,DELETE ON spine_regressions.* TO 'spine_owned_launch'@'%'"));
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'spine_owned_launch',CHAR(39),'@',CHAR(39),'%',CHAR(39))") == 4);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'spine_owned_launch',CHAR(39),'@',CHAR(39),'%',CHAR(39)) AND TABLE_SCHEMA='spine_regressions' AND PRIVILEGE_TYPE IN('SELECT','INSERT','UPDATE','DELETE') AND IS_GRANTABLE='NO'") == 4);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=CONCAT(CHAR(39),'spine_owned_launch',CHAR(39),'@',CHAR(39),'%',CHAR(39)) AND PRIVILEGE_TYPE<>'USAGE'") == 0);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM host WHERE id=902") == 0);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=902 OR local_data_id=942001") == 0);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=942001") == 0);
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=942001") == 0);
	/* Poller1 always includes device0 if present, regardless of hostlist. */
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=0 AND poller_id=1") == 0);
	assert(db_insert(&mysql, LOCAL, "INSERT INTO host(id,hostname,poller_id,disabled,device_threads,availability_method,snmp_version,status_fail_date,status_rec_date) VALUES(902,'127.0.0.1',1,'',1,0,0,'2026-10-06 00:00:00','2026-10-06 00:00:00')"));
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name,snmp_port,rrd_step,rrd_next_step) VALUES(942001,902,1,%i,'/usr/bin/printf 123','owned',161,300,0)", POLLER_ACTION_SCRIPT);
	assert(db_insert(&mysql, LOCAL, query));
	char directory[] = "/tmp/spine-worker-launch-XXXXXX";
	assert(mkdtemp(directory) != NULL);
	struct stat owned;
	assert(lstat(directory, &owned) == 0 && S_ISDIR(owned.st_mode));
	assert(owned.st_uid == geteuid() && (owned.st_mode & 0777) == 0700);
	char config[SMALL_BUFSIZE];
	char log_path[SMALL_BUFSIZE];
	spine_snprintf(config, sizeof(config), "%s/spine.conf", directory);
	spine_snprintf(log_path, sizeof(log_path), "%s/spine.log", directory);
	int descriptor = open(config, O_WRONLY | O_CREAT | O_EXCL, 0600);
	assert(descriptor >= 0);
	assert(fstat(descriptor, &owned) == 0 && S_ISREG(owned.st_mode));
	assert(owned.st_uid == geteuid() && (owned.st_mode & 0777) == 0600);
	FILE *file = fdopen(descriptor, "w");
	assert(file != NULL);
	/* Public fixture-only credentials follow the parser's two-token grammar.
	 * A value-less DB_Pass line retains its configured default. */
	assert(fprintf(file, "DB_Host %s\nDB_Database spine_regressions\nDB_User spine_owned_launch\nDB_Pass regression-only\nDB_Port 3306\nCacti_Log %s\n", set.database.host, log_path) > 0);
	assert(fclose(file) == 0);
	const char *const scenarios[] = {"admitted", "rejected", "retry"};
	for (size_t index = 0; index < sizeof(scenarios) / sizeof(scenarios[0]); index++) {
		assert(db_insert(&mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=942001"));
		assert(db_insert(&mysql, LOCAL, "UPDATE poller_item SET rrd_next_step=0 WHERE host_id=902 AND local_data_id=942001"));
		unsigned long long first_id = fault_database_count(&mysql, "SELECT COALESCE(MAX(id),0) FROM poller_time");
		bool rejected = index == 1;
		pid_t process = run_worker_launch_case(scenarios[index], config, rejected ? EXIT_FAILURE : EXIT_SUCCESS);
		assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=942001 AND output='123'") == (rejected ? 0 : 1));
		spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_item WHERE host_id=902 AND local_data_id=942001 AND rrd_next_step=%i", rejected ? 0 : 295);
		assert(fault_database_count(&mysql, query) == 1);
		assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=942001") == 0);
		spine_snprintf(query, sizeof(query), "DELETE FROM poller_time WHERE poller_id=1 AND pid=%ld AND id>%llu", (long)process, first_id);
		assert(db_insert(&mysql, LOCAL, query));
	}
	assert(db_insert(&mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=942001"));
	assert(db_insert(&mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=902 AND local_data_id=942001"));
	assert(db_insert(&mysql, LOCAL, "DELETE FROM host WHERE id=902"));
	assert(db_insert(&mysql, LOCAL, "DROP USER 'spine_owned_launch'@'%'"));
	assert(fault_database_count(&mysql, "SELECT COUNT(*) FROM mysql.user WHERE User='spine_owned_launch'") == 0);
	assert(unlink(config) == 0);
	if (unlink(log_path) != 0) assert(errno == ENOENT);
	assert(rmdir(directory) == 0);
	db_disconnect(&mysql);
	puts("production actual main worker launch failure and retry regressions passed");
}

int main(int argc, char **argv) {
	/* Fresh exec enters production initialization exactly once, without
	 * reinitializing the ordinary fault harness's inherited mutexes. */
	if (argc == 4 && strcmp(argv[1], "--worker-launch-case") == 0) {
		return execute_worker_launch_case(argv[2], argv[3]);
	}
	config_defaults();
	init_mutexes();
	alarm(20);
	test_logger_format_failure();
	test_process_creation_failures();
	test_interrupted_insert_retry();
	test_snmpv3_privacy_copy_failure();
	test_privilege_drop_faults();
	if (argc == 2 && strcmp(argv[1], "--database") == 0) {
		test_real_database_retry();
		test_ping_only_session_lifetime();
		test_worker_launch_failures();
	}
	else assert(argc == 1);
	alarm(0);
	puts("production linker fault regressions passed");
	return 0;
}
