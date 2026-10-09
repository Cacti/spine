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
#include "internal/common.h"
#include "app/spine.h"
#include <stdint.h>
#include <sys/resource.h>

static void test_keyword_roundtrips(void) {
	typedef struct {
		const char *word;
		int value;
	} keyword_case_t;
	static const keyword_case_t levels[] = {
		{"NONE", POLLER_VERBOSITY_NONE}, {"LOW", POLLER_VERBOSITY_LOW},
		{"MEDIUM", POLLER_VERBOSITY_MEDIUM}, {"HIGH", POLLER_VERBOSITY_HIGH},
		{"DEBUG", POLLER_VERBOSITY_DEBUG}};
	static const keyword_case_t destinations[] = {
		{"FILE", LOGDEST_FILE}, {"SYSLOG", LOGDEST_SYSLOG},
		{"BOTH", LOGDEST_BOTH}, {"STDOUT", LOGDEST_STDOUT}};
	static const keyword_case_t actions[] = {
		{"SNMP", POLLER_ACTION_SNMP}, {"SCRIPT", POLLER_ACTION_SCRIPT},
		{"PHPSCRIPT", POLLER_ACTION_PHP_SCRIPT_SERVER},
		{"SNMP_CT", POLLER_ACTION_SNMP_COUNT}, {"SCRIPT_CT", POLLER_ACTION_SCRIPT_COUNT},
		{"PHPSCRIPT_CT", POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT}};
	for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
		assert(parse_log_level(levels[i].word, -1) == levels[i].value);
		assert(strcmp(printable_log_level(levels[i].value), levels[i].word) == 0);
	}
	for (size_t i = 0; i < sizeof(destinations) / sizeof(destinations[0]); i++) {
		assert(parse_logdest(destinations[i].word, -1) == destinations[i].value);
		assert(strcmp(printable_logdest(destinations[i].value), destinations[i].word) == 0);
	}
	for (size_t i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
		assert(parse_action(actions[i].word, -1) == actions[i].value);
		assert(strcmp(printable_action(actions[i].value), actions[i].word) == 0);
	}
	assert(parse_log_level("dEbUg", -1) == POLLER_VERBOSITY_DEBUG);
	assert(parse_logdest("sYsLoG", -1) == LOGDEST_SYSLOG);
	assert(parse_action("pHpScRiPt_Ct", -1) == POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT);
	assert(parse_log_level("42", -1) == 42);
	assert(parse_logdest("007", -1) == 7);
	assert(parse_action("0", -1) == 0);
	assert(parse_log_level("", 97) == 97);
	assert(parse_log_level("unknown", 97) == 97);
	assert(parse_logdest("-1", 98) == 98);
	assert(parse_action(" 2", 99) == 99);
	assert(parse_action("2x", 99) == 99);
	assert(strcmp(printable_log_level(-1), "-unknown-") == 0);
	assert(strcmp(printable_logdest(-1), "-unknown-") == 0);
	assert(strcmp(printable_action(-1), "-unknown-") == 0);
}

static void *try_busy_lock(void *argument) {
	int lock = *(int *) argument;
	int result = thread_mutex_trylock(lock);
	if (result == 0) thread_mutex_unlock(lock);
	return (void *) (intptr_t) result;
}

static void test_lock_contracts(void) {
	static const int locks[] = {LOCK_SNMP, LOCK_ICMP, LOCK_GHBN, LOCK_POOL, LOCK_PHP,
		LOCK_PHP_PROC_0, LOCK_PHP_PROC_1, LOCK_PHP_PROC_2, LOCK_PHP_PROC_3,
		LOCK_PHP_PROC_4, LOCK_PHP_PROC_5, LOCK_PHP_PROC_6, LOCK_PHP_PROC_7,
		LOCK_PHP_PROC_8, LOCK_PHP_PROC_9, LOCK_PHP_PROC_10, LOCK_PHP_PROC_11,
		LOCK_PHP_PROC_12, LOCK_PHP_PROC_13, LOCK_PHP_PROC_14, LOCK_THDET, LOCK_HOST_TIME};
	static const char *const names[] = {"snmp", "icmp", "ghbn", "pool", "php",
		"php_proc_0", "php_proc_1", "php_proc_2", "php_proc_3", "php_proc_4",
		"php_proc_5", "php_proc_6", "php_proc_7", "php_proc_8", "php_proc_9",
		"php_proc_10", "php_proc_11", "php_proc_12", "php_proc_13", "php_proc_14", "thdet", "host_time"};
	init_mutexes();
	init_mutexes(); /* pthread_once must preserve the already-created locks. */
	for (size_t i = 0; i < sizeof(locks) / sizeof(locks[0]); i++) {
		assert(strcmp(get_name(locks[i]), names[i]) == 0);
		assert(get_lock(locks[i]) != NULL && get_cond(locks[i]) != NULL && get_attr(locks[i]) != NULL);
		assert(get_lock(locks[i]) == get_lock(locks[i]));
		for (size_t j = 0; j < i; j++) {
			assert(get_lock(locks[i]) != get_lock(locks[j]));
			assert(get_cond(locks[i]) != get_cond(locks[j]));
			assert(get_attr(locks[i]) != get_attr(locks[j]));
		}
		assert(thread_mutex_trylock(locks[i]) == 0);
		pthread_t competitor;
		int lock = locks[i];
		assert(pthread_create(&competitor, NULL, try_busy_lock, &lock) == 0);
		void *result;
		assert(pthread_join(competitor, &result) == 0);
		assert((intptr_t) result == EBUSY);
		thread_mutex_unlock(locks[i]);
		assert(thread_mutex_trylock(locks[i]) == 0);
		thread_mutex_unlock(locks[i]);
	}
	assert(strcmp(get_name(-1), "Unknown lock") == 0);
	assert(get_lock(-1) == NULL && get_cond(-1) == NULL && get_attr(-1) == NULL);
	assert(get_lock(1) == NULL && get_cond(1) == NULL && get_attr(1) == NULL);
}

static pthread_mutex_t distribution_mutex = PTHREAD_MUTEX_INITIALIZER;
static int distribution[MAX_PHP_SERVERS];
static void *next_php_process(void *unused) {
	(void) unused;
	for (int i = 0; i < 300; i++) {
		int process = php_get_process();
		assert(process >= 0 && process < 3);
		assert(pthread_mutex_lock(&distribution_mutex) == 0);
		distribution[process]++;
		assert(pthread_mutex_unlock(&distribution_mutex) == 0);
	}
	return NULL;
}

static void test_php_roundrobin(void) {
	int previous_count = set.php.php_servers;
	int previous_current = set.php.php_current_server;
	/* php_get_process() hands out healthy slots, so every slot looks like a
	 * live, ready server here. */
	php_t *previous_processes = php_processes;
	php_t healthy[MAX_PHP_SERVERS];
	php_processes_initialize(healthy, MAX_PHP_SERVERS);
	for (int i = 0; i < MAX_PHP_SERVERS; i++) {
		healthy[i].php_state = PHP_READY;
		healthy[i].php_pid = 2;
		healthy[i].php_read_fd = STDIN_FILENO;
		healthy[i].php_write_fd = STDOUT_FILENO;
	}
	php_processes = healthy;
	set.php.php_servers = MAX_PHP_SERVERS;
	set.php.php_current_server = 0;
	for (int i = 0; i < 2 * MAX_PHP_SERVERS; i++) assert(php_get_process() == i % MAX_PHP_SERVERS);
	set.php.php_servers = 1;
	set.php.php_current_server = MAX_PHP_SERVERS;
	assert(php_get_process() == 0 && php_get_process() == 0);
	set.php.php_servers = 3;
	set.php.php_current_server = 0;
	memset(distribution, 0, sizeof(distribution));
	pthread_t workers[4];
	for (size_t i = 0; i < 4; i++) assert(pthread_create(&workers[i], NULL, next_php_process, NULL) == 0);
	for (size_t i = 0; i < 4; i++) assert(pthread_join(workers[i], NULL) == 0);
	/* The cursor is fair, but a slot busy in another thread hands that caller
	 * the next healthy one, so only the total and coverage are exact. */
	assert(distribution[0] + distribution[1] + distribution[2] == 1200);
	for (int i = 0; i < 3; i++) assert(distribution[i] > 0);
	assert(set.php.php_current_server == 3);
	set.php.php_servers = previous_count;
	set.php.php_current_server = previous_current;
	php_processes = previous_processes;
}

static void test_legacy_ip_predicate(void) {
	/* This unused legacy helper recognizes characters, not IP syntax. */
	assert(is_ipaddress("127.0.0.1"));
	assert(is_ipaddress("::1"));
	assert(is_ipaddress(""));
	assert(is_ipaddress("999.999.999.999"));
	assert(is_ipaddress(".:"));
	assert(!is_ipaddress("example.org"));
	assert(!is_ipaddress("2001:db8::1"));
	assert(!is_ipaddress("127.0.0.1 "));
	assert(!is_ipaddress("127.0.0.1/8"));
}

static void test_multipart_boundaries(void) {
	static const struct {
		const char *input;
		int expected;
	} cases[] = {
		{NULL, FALSE}, {"", FALSE}, {"123", FALSE}, {"hello", FALSE},
		{"a:1", TRUE}, {"a!1", TRUE}, {":", TRUE}, {"!", TRUE},
		{"a:1 b:2", TRUE}, {"a!1 b!2", TRUE}, {"a:1 b!2", TRUE},
		{"a:1  b:2", FALSE}, {" a:1", TRUE}, {"a:1 ", TRUE},
		{" a:1 b:2 ", TRUE}, {"a:1 b:2 c:3", TRUE},
		{"a::1 b:2", FALSE}, {"a::1", TRUE},
		{"a:1\tb:2", TRUE}, {"a:1\nb!2", TRUE},
		{"a:1\t b!2", TRUE}, {"a:1 b:2\n c!3", TRUE},
		{"a:1 \t b:2", FALSE}, {"a  b", FALSE}};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		classified_result_t out;
		assert((classify_result(cases[i].input, &out) == RESULT_MULTIPART) == cases[i].expected);
	}
}

static void test_fatal_signal_contracts(void) {
	static const struct {
		int signal;
		const char *message;
	} cases[] = {
		{SIGINT, "Console Operator"},
		{SIGSEGV, "Segmentation Fault"}, {SIGBUS, "Bus Error"},
		{SIGFPE, "Floating Point Exception"}, {SIGQUIT, "Keyboard Quit"},
		{SIGSYS, "Unhandled Exception"}, {SIGABRT, "Abort Signal"}};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int diagnostic[2];
		assert(pipe(diagnostic) == 0);
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			alarm(5);
			close(diagnostic[0]);
			assert(dup2(diagnostic[1], STDERR_FILENO) == STDERR_FILENO);
			close(diagnostic[1]);
			/* The default action of several cases dumps core. */
			struct rlimit no_core = {0, 0};
			assert(setrlimit(RLIMIT_CORE, &no_core) == 0);
			assert(signal(cases[i].signal, SIG_DFL) != SIG_ERR);
			install_spine_signal_handler();
			assert(raise(cases[i].signal) == 0);
			/* A fatal signal must end the process once it is logged. */
			_exit(0);
		}
		close(diagnostic[1]);
		char message[512] = {0};
		size_t used = 0;
		ssize_t count;
		while ((count = read(diagnostic[0], message + used, sizeof(message) - used - 1)) != 0) {
			if (count < 0 && errno == EINTR) continue;
			assert(count > 0);
			used += (size_t) count;
			assert(used < sizeof(message) - 1);
		}
		close(diagnostic[0]);
		int status;
		assert(waitpid(child, &status, 0) == child);
		fprintf(stderr, "fatal signal %d: raw_status=%d\n", cases[i].signal, status);
		if (cases[i].signal == SIGSEGV) {
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 1);
		} else {
			assert(WIFSIGNALED(status) && WTERMSIG(status) == cases[i].signal);
		}
		assert(strstr(message, cases[i].message) != NULL);
	}
	/* A broken pipe is an ordinary write failure: it must neither terminate
	 * Spine nor be reported as fatal, and the handler stays installed. */
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(5);
		set.exit.exit_code = 0;
		install_spine_signal_handler();
		assert(raise(SIGPIPE) == 0 && raise(SIGPIPE) == 0);
		assert(set.exit.exit_code == 0);
		struct sigaction installed;
		assert(sigaction(SIGPIPE, NULL, &installed) == 0 && installed.sa_handler != SIG_DFL);
		uninstall_spine_signal_handler();
		assert(sigaction(SIGPIPE, NULL, &installed) == 0 && installed.sa_handler == SIG_DFL);
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

void test_additional_contracts(void) {
	test_keyword_roundtrips();
	test_lock_contracts();
	test_php_roundrobin();
	test_legacy_ip_predicate();
	test_multipart_boundaries();
	test_fatal_signal_contracts();
	puts("production additional contracts passed");
}

/* The client library never clears errno, so an EINTR left over from an
 * unrelated call must not stand in for an interrupted query. Run in a child
 * so an unbounded retry shows up as the alarm instead of a hung suite. */
static void assert_stale_interrupt_is_retried(void) {
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(10);
		MYSQL administrator;
		MYSQL victim;
		db_connect(LOCAL, &administrator);
		db_connect(LOCAL, &victim);
		char query[100];
		snprintf(query, sizeof(query), "KILL CONNECTION %lu", mysql_thread_id(&victim));
		if (mysql_query(&administrator, query) != 0) _exit(2);
		errno = EINTR;
		_exit(db_insert(&victim, LOCAL, "SET @spine_regression_interrupt=1") == TRUE ? 0 : 3);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	fprintf(stderr, "stale EINTR retry: raw_status=%d\n", status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/* Query wrappers report failure to the caller; only startup code may turn a
 * database error into a process exit. Port 1 refuses the reconnect quickly
 * and deterministically, which stands in for a server that is down. */
static void assert_database_failures_return(void) {
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(30);
		MYSQL administrator;
		MYSQL victim;
		if (!db_connect(LOCAL, &administrator) || !db_connect(LOCAL, &victim)) _exit(2);
		if (db_query(&administrator, LOCAL, "SELECT spine_regression_missing FROM spine_regression_missing") != NULL) _exit(3);
		if (db_insert(&administrator, LOCAL, "UPDATE spine_regression_missing SET value=1") != FALSE) _exit(4);
		char query[100];
		snprintf(query, sizeof(query), "KILL CONNECTION %lu", mysql_thread_id(&victim));
		if (mysql_query(&administrator, query) != 0) _exit(5);
		unsigned int port = set.database.port;
		set.database.port = 1;
		double begin = spine_monotonic_time();
		if (db_query(&victim, LOCAL, "SELECT 1") != NULL) _exit(6);
		if (db_insert(&victim, LOCAL, "SET @spine_regression_down=1") != FALSE) _exit(7);
		if (db_reconnect(&victim, LOCAL, 2006, "regression_down_server") != -1) _exit(8);
		if (spine_monotonic_time() - begin > 20) _exit(9);
		/* The same handle recovers once the server is reachable again. */
		set.database.port = port;
		MYSQL_RES *result = db_query(&victim, LOCAL, "SELECT 789");
		MYSQL_ROW row = result != NULL ? mysql_fetch_row(result) : NULL;
		if (row == NULL || row[0] == NULL || strcmp(row[0], "789") != 0) _exit(10);
		db_free_result(result);
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	fprintf(stderr, "database failure propagation: raw_status=%d\n", status);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static bool session_mode_contains(MYSQL *mysql, const char *mode) {
	MYSQL_RES *result = db_query(mysql, LOCAL, "SELECT @@SESSION.sql_mode");
	assert(result != NULL);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	bool found = strstr(row[0], mode) != NULL;
	db_free_result(result);
	return found;
}

/* Pooled sessions run with Cacti's relaxed sql_mode. A reconnect opens a new
 * session with the server default, so it must apply the same policy again. */
static void assert_reconnect_restores_session_mode(MYSQL *mysql) {
	MYSQL victim;
	assert(db_connect(LOCAL, &victim));
	/* The fixture server's default mode is strict; otherwise this proves nothing. */
	assert(session_mode_contains(&victim, "STRICT_TRANS_TABLES"));
	char query[100];
	snprintf(query, sizeof(query), "KILL CONNECTION %lu", mysql_thread_id(&victim));
	assert(mysql_query(mysql, query) == 0);
	bool strict = session_mode_contains(&victim, "STRICT_TRANS_TABLES");
	bool zero_date = session_mode_contains(&victim, "NO_ZERO_DATE");
	fprintf(stderr, "reconnected session mode: strict=%d no_zero_date=%d\n", strict, zero_date);
	assert(!strict && !zero_date);
	db_disconnect(&victim);
}

void test_additional_database_contracts(MYSQL *mysql) {
	assert(db_column_exists(mysql, LOCAL, "host", "id") == TRUE);
	assert(db_column_exists(mysql, LOCAL, "host", "regression_missing_column") == FALSE);
	/* Only kill a connection created and owned by this test. */
	MYSQL victim;
	db_connect(LOCAL, &victim);
	unsigned long original = mysql_thread_id(&victim);
	char query[100];
	snprintf(query, sizeof(query), "KILL CONNECTION %lu", original);
	assert(mysql_query(mysql, query) == 0);
	assert(db_reconnect(&victim, LOCAL, 2006, "regression_owned_session") == TRUE);
	assert(mysql_thread_id(&victim) != original);
	assert(mysql_query(&victim, "SELECT 123") == 0);
	MYSQL_RES *result = mysql_store_result(&victim);
	assert(result != NULL);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "123") == 0);
	mysql_free_result(result);
	/* An already-healthy session does not count as a new reconnection. */
	assert(db_reconnect(&victim, LOCAL, 2006, "regression_healthy_session") == FALSE);
	/* Exercise query and mutation callers, not just explicit reconnect. */
	for (int insert = 0; insert < 2; insert++) {
		original = mysql_thread_id(&victim);
		snprintf(query, sizeof(query), "KILL CONNECTION %lu", original);
		assert(mysql_query(mysql, query) == 0);
		errno = 0;
		if (insert) assert(db_insert(&victim, LOCAL, "SET @spine_regression_retry=456"));
		else {
			result = db_query(&victim, LOCAL, "SELECT 456");
			assert(result != NULL);
			row = mysql_fetch_row(result);
			assert(row != NULL && row[0] != NULL && strcmp(row[0], "456") == 0);
			db_free_result(result);
		}
		assert(mysql_thread_id(&victim) != original);
		if (insert) {
			result = db_query(&victim, LOCAL, "SELECT @spine_regression_retry");
			assert(result != NULL);
			row = mysql_fetch_row(result);
			assert(row != NULL && row[0] != NULL && strcmp(row[0], "456") == 0);
			db_free_result(result);
		}
	}
	db_disconnect(&victim);
	assert_stale_interrupt_is_retried();
	assert_database_failures_return();
	assert_reconnect_restores_session_mode(mysql);
}
