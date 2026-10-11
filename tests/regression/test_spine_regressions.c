/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"
#include <fcntl.h>
#include <sys/un.h>
#include <limits.h>

#include "app/runtime.h"
extern void test_output_write_contracts(MYSQL *mysql);
extern void test_database_tls_contracts(void);
extern void run_script_limit_contracts(void);
extern void test_additional_contracts(void);
extern void test_cli_alias_contracts(void);
extern void test_privilege_contracts(void);
extern void test_setuid_icmp(void);
extern void test_setuid_stress(int rounds);
extern int run_script_stream_fixture(const char *scenario);
extern void test_script_stream_contracts(void);
extern void test_additional_database_contracts(MYSQL *mysql);
extern void test_settings_write_contracts(MYSQL *mysql);
extern void test_config_option_boundaries(MYSQL *mysql);
extern void test_additional_reindex_contracts(MYSQL *mysql);
extern void test_reindex_result_contracts(MYSQL *mysql);
extern void test_additional_snmp_session_boundaries(void);
extern void test_snmpv3_agent_contracts(void);

/* Threads that run poll_host() need the stack production workers get. */
void start_test_worker(pthread_t *worker, void *(*start)(void *), void *argument) {
	pthread_attr_t attributes;

	assert(spine_thread_attr_init(&attributes) == 0);
	assert(pthread_create(worker, &attributes, start, argument) == 0);
	assert(pthread_attr_destroy(&attributes) == 0);
}

static void test_copy_bounds(void) {
	struct {
		char text[8];
		unsigned char guard;
	} output;
	memset(&output, 0xa5, sizeof output);
	strncopy(output.text, "12345678", sizeof(output.text));
	assert(strcmp(output.text, "1234567") == 0);
	assert(output.guard == 0xa5);
	strncopy(output.text, "abcdefghijk", sizeof(output.text));
	assert(strcmp(output.text, "abcdefg") == 0);
	assert(output.guard == 0xa5);
	strncopy(output.text, "unchanged", 0);
	assert(strcmp(output.text, "abcdefg") == 0);
	strncopy(output.text, "x", 1);
	assert(output.text[0] == '\0');
	strncopy(output.text, "", sizeof(output.text));
	assert(output.text[0] == '\0');
}

static void test_string_conversions(void) {
	char empty[] = "";
	char one[] = "x";
	char word[] = "abcd";
	assert(strcmp(reverse(empty), "") == 0);
	assert(strcmp(reverse(one), "x") == 0);
	assert(strcmp(reverse(word), "dcba") == 0);
	classified_result_t hex;
	assert(classify_result("\"FF ff\t\"", &hex) == RESULT_HEX_COUNTER && hex.value.counter == 65535);
	assert(classify_result("FF:FF:FF:FF FF-FF-FF-FF", &hex) == RESULT_HEX_COUNTER && hex.value.counter == ULLONG_MAX);
	assert(classify_result("01 00 00 00 00 00 00 00 00", &hex) == RESULT_UNKNOWN && IS_UNDEFINED(hex.text));
	assert(classify_result("not hex", &hex) == RESULT_UNKNOWN);
	char input[BUFSIZE * 2];
	memset(input, '\\', sizeof(input) - 1);
	input[sizeof(input) - 1] = '\0';
	char *escaped = add_slashes(input);
	assert(strlen(escaped) == 2 * (sizeof(input) - 1));
	for (size_t i = 0; escaped[i] != '\0'; i++) assert(escaped[i] == '\\');
	free(escaped);
	escaped = add_slashes("a\\b");
	assert(strcmp(escaped, "a\\\\b") == 0);
	free(escaped);
	escaped = add_slashes("");
	assert(escaped[0] == '\0');
	free(escaped);
	char decorated[] = "text +12.5 Bytes";
	assert(strcmp(strip_alpha(decorated), "12.5") == 0);
	char negative[] = "text -12.5 Bytes";
	assert(strcmp(strip_alpha(negative), "-12.5") == 0);
	char nonnumeric[] = "no sample";
	assert(strcmp(strip_alpha(nonnumeric), "") == 0);
}

static void test_result_count_range(void) {
	assert(spine_count_to_int(0) == 0);
	assert(spine_count_to_int(INT_MAX) == INT_MAX);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		spine_count_to_int((unsigned long long) INT_MAX + 1);
		_exit(99);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
}

static void test_cli_case(const char *flag, const char *input, int expected, const char *error) {
	int errors[2];
	assert(pipe(errors) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		assert(close(errors[0]) == 0);
		assert(dup2(errors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(errors[1]) == 0);
		char program[] = "spine";
		char option[32];
		strncopy(option, flag, sizeof(option));
		char version[] = "--version";
		char value[64];
		strncopy(value, input, sizeof(value));
		char *args[] = {program, option, value, version, NULL};
		spine_run(4, args);
		_exit(99);
	}
	assert(close(errors[1]) == 0);
	char message[512];
	ssize_t received = read(errors[0], message, sizeof(message) - 1);
	if (received < 0 || received >= (ssize_t) sizeof(message)) abort();
	message[received] = '\0';
	assert(close(errors[0]) == 0);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
	if (expected == EXIT_FAILURE || error != NULL) assert(strstr(message, error) != NULL);
	else assert(message[0] == '\0');
}

static void test_cli_option_shape(void) {
	test_cli_case("--option", "missing-colon", EXIT_FAILURE, "ERROR: -O requires setting:value");
	test_cli_case("--option", ":value", EXIT_FAILURE, "ERROR: -O requires setting:value");
	test_cli_case("--option", "regression:", EXIT_SUCCESS, NULL);
	test_cli_case("--option", "regression:value:colon", EXIT_SUCCESS, NULL);
	test_cli_case("--mode", "online", EXIT_SUCCESS, NULL);
	test_cli_case("--mode", "offline", EXIT_SUCCESS, NULL);
	test_cli_case("--mode", "recovery", EXIT_SUCCESS, NULL);
	test_cli_case("--mode", "invalid", EXIT_FAILURE, "ERROR: invalid polling mode 'invalid' specified");
	static const char *const bad_threads[] = {"0", "-1", "abc", "5x", " 5", "+5", "", "99999999999999999999"};
	for (size_t index = 0; index < sizeof(bad_threads) / sizeof(bad_threads[0]); index++) {
		test_cli_case("--threads", bad_threads[index], EXIT_FAILURE, "is an invalid thread count, use 1 to 100");
		test_cli_case("-t", bad_threads[index], EXIT_FAILURE, "is an invalid thread count, use 1 to 100");
	}
	test_cli_case("--threads", "1", EXIT_SUCCESS, NULL);
	test_cli_case("-t", "100", EXIT_SUCCESS, NULL);
	/* above the cap still runs, as it did with atoi(), but says so */
	test_cli_case("-t", "101", EXIT_SUCCESS, "WARNING: '-t=101' exceeds the maximum thread count, using 100");
	test_cli_case("--threads", "150", EXIT_SUCCESS, "WARNING: '--threads=150' exceeds the maximum thread count, using 100");
	static const char *const bad_ids[] = {"abc", "1x", "-1", "+1", " 1", "", "2147483648", "99999999999999999999"};
	for (size_t index = 0; index < sizeof(bad_ids) / sizeof(bad_ids[0]); index++) {
		test_cli_case("--first", bad_ids[index], EXIT_FAILURE, "is invalid first-host ID");
		test_cli_case("-l", bad_ids[index], EXIT_FAILURE, "is invalid last-host ID");
	}
	test_cli_case("-f", "0", EXIT_SUCCESS, NULL);
	test_cli_case("--last", "2147483647", EXIT_SUCCESS, NULL);
	/* the positional "first last" form poller.php uses */
	test_cli_case("7", "99999999999999999999", EXIT_FAILURE, "is invalid last-host ID");
	test_cli_case("99999999999999999999", "7", EXIT_FAILURE, "is invalid first-host ID");
	test_cli_case("7", "9", EXIT_SUCCESS, NULL);
	int errors[2];
	assert(pipe(errors) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		assert(close(errors[0]) == 0);
		assert(dup2(errors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(errors[1]) == 0);
		set.exit.exit_code = EXIT_SUCCESS;
		for (int i = 0; i < 257; i++) set_option("regression", "value");
		_exit(99);
	}
	assert(close(errors[1]) == 0);
	char message[512];
	ssize_t received = read(errors[0], message, sizeof(message) - 1);
	if (received < 0 || received >= (ssize_t) sizeof(message)) abort();
	message[received] = '\0';
	assert(close(errors[0]) == 0);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
	assert(strstr(message, "Invalid or excessive command-line setting overrides") != NULL);
}

static spine_permits_t test_permits;
static pthread_mutex_t permit_test_mutex = PTHREAD_MUTEX_INITIALIZER;
static int active_permit_workers;

static void *exercise_permit(void *unused) {
	(void) unused;
	for (int iteration = 0; iteration < 100; iteration++) {
		int status;
		while ((status = spine_permits_try_acquire(&test_permits)) == EAGAIN) spine_sleep_usec(100);
		assert(status == 0);
		assert(pthread_mutex_lock(&permit_test_mutex) == 0);
		assert(active_permit_workers == 0);
		active_permit_workers++;
		assert(pthread_mutex_unlock(&permit_test_mutex) == 0);
		spine_sleep_usec(100);
		assert(pthread_mutex_lock(&permit_test_mutex) == 0);
		assert(active_permit_workers == 1);
		active_permit_workers--;
		assert(pthread_mutex_unlock(&permit_test_mutex) == 0);
		assert(spine_permits_release(&test_permits) == 0);
	}
	return NULL;
}

static void test_concurrent_permits(void) {
	assert(spine_permits_init(&test_permits, -1) == EINVAL);
	assert(spine_permits_init(&test_permits, INT_MAX) == 0);
	assert(spine_permits_release(&test_permits) == EOVERFLOW);
	assert(spine_permits_available(&test_permits) == INT_MAX);
	assert(spine_permits_destroy(&test_permits) == 0);
	assert(spine_permits_init(&test_permits, 1) == 0);
	assert(spine_permits_try_acquire(&test_permits) == 0);
	assert(spine_permits_try_acquire(&test_permits) == EAGAIN);
	assert(spine_permits_available(&test_permits) == 0);
	assert(spine_permits_release(&test_permits) == 0);
	pthread_t workers[4];
	for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); i++) {
		assert(pthread_create(&workers[i], NULL, exercise_permit, NULL) == 0);
	}
	for (size_t i = 0; i < sizeof(workers) / sizeof(workers[0]); i++) assert(pthread_join(workers[i], NULL) == 0);
	assert(spine_permits_available(&test_permits) == 1 && active_permit_workers == 0);
	assert(spine_permits_destroy(&test_permits) == 0);
}

static void test_database_escape(void) {
	MYSQL *mysql = mysql_init(NULL);
	assert(mysql != NULL);
	char input[RESULTS_BUFFER];
	char output[RESULTS_BUFFER * 2 + 1];
	memset(input, 'x', sizeof(input) - 1);
	input[sizeof(input) - 1] = '\0';
	db_escape(mysql, output, sizeof(output), input);
	assert(strcmp(output, input) == 0);
	memset(input, '\'', sizeof(input) - 1);
	db_escape(mysql, output, sizeof(output), input);
	assert(strlen(output) == 2 * (sizeof(input) - 1));
	for (size_t i = 0; i < sizeof(input) - 1; i++) {
		assert(output[2 * i] == '\\' && output[2 * i + 1] == '\'');
	}
	unsigned char guarded[13];
	memset(guarded, 0xa5, sizeof(guarded));
	db_escape(mysql, (char *) guarded + 1, 11, input);
	assert(guarded[0] == 0xa5 && guarded[12] == 0xa5);
	assert(strlen((char *) guarded + 1) == 10);
	char tiny[] = "abc";
	db_escape(mysql, tiny, 0, input);
	assert(strcmp(tiny, "abc") == 0);
	db_escape(mysql, tiny, -1, input);
	assert(strcmp(tiny, "abc") == 0);
	db_escape(mysql, tiny, 1, input);
	assert(tiny[0] == '\0' && tiny[1] == 'b');
	db_escape(mysql, tiny, sizeof(tiny), NULL);
	assert(tiny[1] == 'b');
	db_escape(mysql, NULL, 16, input);
	mysql_close(mysql);
}

static void test_database_addresses(void) {
	db_address_t address;
	db_address_init(&address, "localhost", true);
	assert(strcmp(address.hostname, "localhost") == 0 && address.socket == NULL);
	db_address_release(&address);
	assert(address.storage == NULL && address.hostname == NULL && address.socket == NULL);
	db_address_init(&address, "localhost:service", true);
	assert(strcmp(address.hostname, "localhost") == 0 && strcmp(address.socket, "service") == 0);
	db_address_release(&address);
	db_address_init(&address, "remote:service", false);
	assert(strcmp(address.hostname, "remote:service") == 0 && address.socket == NULL);
	db_address_release(&address);
	char directory[] = "spine-socket-test-XXXXXX";
	assert(mkdtemp(directory) != NULL);
	db_address_init(&address, directory, true);
	assert(strcmp(address.hostname, directory) == 0 && address.socket == NULL);
	db_address_release(&address);
	struct sockaddr_un socket_address = {0};
	socket_address.sun_family = AF_UNIX;
#ifdef __APPLE__
	socket_address.sun_len = sizeof(socket_address);
#endif
	spine_snprintf(socket_address.sun_path, sizeof(socket_address.sun_path), "%s/db.sock", directory);
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd >= 0);
	int bound = bind(fd, (struct sockaddr *) &socket_address, sizeof(socket_address));
	if (bound != 0) perror("bind regression socket");
	assert(bound == 0);
	db_address_init(&address, socket_address.sun_path, true);
	assert(address.hostname == NULL && strcmp(address.socket, socket_address.sun_path) == 0);
	db_address_release(&address);
	assert(close(fd) == 0);
	assert(unlink(socket_address.sun_path) == 0);
	assert(rmdir(directory) == 0);
}

static void test_database_option_failure(void) {
	MYSQL *mysql = mysql_init(NULL);
	assert(mysql != NULL);
	unsigned int timeout = 5;
	db_set_option(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout, "test timeout");
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		db_set_option(mysql, (enum mysql_option) 999999, NULL, "unsupported test option");
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
	mysql_close(mysql);
}

static void test_regex_storage(void) {
	char first[] = "abc123xyz";
	char second[] = "x4y";
	char absent[] = "no digits";
	const char *match = regex_replace("[0-9][0-9]*", first);
	assert(strcmp(match, "123") == 0);
	/* The result remains valid across another function's stack use. */
	char stack[4096];
	memset(stack, 'z', sizeof stack);
	assert(strcmp(match, "123") == 0);
	assert(strcmp(regex_replace("[0-9][0-9]*", second), "4") == 0);
	assert(regex_replace("[0-9][0-9]*", absent) == absent);
	assert(regex_replace("[", first) == first);
	char large[RESULTS_BUFFER + 1];
	memset(large, '9', sizeof large - 1);
	large[sizeof large - 1] = '\0';
	assert(regex_replace("[0-9][0-9]*", large) == large);
}

static pthread_mutex_t regex_test_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t regex_test_ready = PTHREAD_COND_INITIALIZER;
static int regex_threads_ready;

static void *test_regex_thread(void *argument) {
	char *input = argument;
	const char *match = regex_replace("[0-9][0-9]*", input);
	assert(pthread_mutex_lock(&regex_test_mutex) == 0);
	regex_threads_ready++;
	assert(pthread_cond_broadcast(&regex_test_ready) == 0);
	while (regex_threads_ready < 2) {
		assert(pthread_cond_wait(&regex_test_ready, &regex_test_mutex) == 0);
	}
	/* Both threads have produced a result; neither may overwrite the other. */
	assert(strcmp(match, input) == 0);
	assert(pthread_mutex_unlock(&regex_test_mutex) == 0);
	return NULL;
}

static void test_regex_concurrency(void) {
	char first[] = "123";
	char second[] = "4567";
	pthread_t threads[2];
	assert(pthread_create(&threads[0], NULL, test_regex_thread, first) == 0);
	assert(pthread_create(&threads[1], NULL, test_regex_thread, second) == 0);
	assert(pthread_join(threads[0], NULL) == 0);
	assert(pthread_join(threads[1], NULL) == 0);
}

static void test_formatting(void) {
	char output[8];
	assert(spine_snprintf(output, sizeof output, "%s", "1234567") == 7);
	assert(strcmp(output, "1234567") == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		spine_snprintf(output, sizeof output, "%s", "12345678");
		_exit(0);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
}

static void test_secret_clear(void) {
	unsigned char bytes[8];
	memset(bytes, 0xa5, sizeof bytes);
	spine_clear_sensitive(bytes + 1, 6);
	assert(bytes[0] == 0xa5 && bytes[7] == 0xa5);
	for (size_t i = 1; i < 7; i++) assert(bytes[i] == 0);
	spine_clear_sensitive(NULL, 0);
}

static void test_log_boundary(void) {
	char *message = malloc(LOGSIZE + 1);
	assert(message != NULL);
	memset(message, 'x', LOGSIZE);
	message[LOGSIZE] = '\0';
	set.logging.log_level = POLLER_VERBOSITY_NONE;
	set.logging.log_destination = 0;
	set.console.stdout_notty = TRUE;
	spine_log("%s", message);
	free(message);
}

static void test_log_sanitization(void) {
	char message[] = "a\r\nb\t\033\177c\302\205d\342\200\250e\342\200\251f";
	spine_sanitize_log_message(message);
	assert(strcmp(message, "a  b   c  d   e   f") == 0);
	char unicode[] = "caf\303\251";
	spine_sanitize_log_message(unicode);
	assert(strcmp(unicode, "caf\303\251") == 0);
	char truncated[] = "\342\200";
	spine_sanitize_log_message(truncated);
	assert(strcmp(truncated, "\342\200") == 0);
	char path[] = "spine-log-test-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0 && close(fd) == 0);
	set.logging.log_destination = LOGDEST_FILE;
	set.logging.log_level = POLLER_VERBOSITY_LOW;
	set.logging.logfile_processed = TRUE;
	strncopy(set.logging.path_logfile, path, sizeof(set.logging.path_logfile));
	spine_log("device: %s", "first\r\nsecond");
	FILE *file = fopen(path, "r");
	assert(file != NULL);
	char line[BUFSIZE];
	assert(fgets(line, sizeof(line), file) != NULL);
	assert(strstr(line, "device: first  second") != NULL);
	assert(fgets(line, sizeof(line), file) == NULL && !ferror(file));
	assert(fclose(file) == 0 && unlink(path) == 0);
	set.logging.log_destination = 0;
}

static void *test_log_writer(void *argument) {
	const char *message = argument;
	for (int count = 0; count < 5; count++) assert(spine_log("%s", message));
	return NULL;
}

static void test_log_append_and_failures(void) {
	config_t previous = set;
	char path[] = "spine-log-append-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	static const char retained[] = "retained record\n";
	assert(write(fd, retained, sizeof(retained) - 1) == (ssize_t) (sizeof(retained) - 1));
	assert(close(fd) == 0);
	set.logging.log_destination = LOGDEST_FILE;
	set.logging.log_level = POLLER_VERBOSITY_LOW;
	set.logging.logfile_processed = TRUE;
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	strncopy(set.logging.path_logfile, path, sizeof(set.logging.path_logfile));
	char first[20001];
	char second[20001];
	memset(first, 'a', sizeof(first) - 1);
	memset(second, 'b', sizeof(second) - 1);
	first[sizeof(first) - 1] = '\0';
	second[sizeof(second) - 1] = '\0';
	pthread_t threads[2];
	assert(pthread_create(&threads[0], NULL, test_log_writer, first) == 0);
	assert(pthread_create(&threads[1], NULL, test_log_writer, second) == 0);
	assert(pthread_join(threads[0], NULL) == 0);
	assert(pthread_join(threads[1], NULL) == 0);
	FILE *file = fopen(path, "r");
	assert(file != NULL);
	char *line = NULL;
	size_t capacity = 0;
	assert(getline(&line, &capacity, file) == (ssize_t) (sizeof(retained) - 1));
	assert(strcmp(line, retained) == 0);
	int first_count = 0;
	int second_count = 0;
	while (getline(&line, &capacity, file) >= 0) {
		const char *body = strstr(line, first);
		if (body != NULL) first_count++;
		else {
			body = strstr(line, second);
			second_count++;
		}
		assert(body != NULL && strcmp(body + 20000, "\n") == 0);
	}
	assert(!ferror(file) && first_count == 5 && second_count == 5);
	free(line);
	assert(fclose(file) == 0 && unlink(path) == 0);
	/* Append mode must also create a missing file. */
	assert(spine_log("created record"));
	assert(file_exists(path) && unlink(path) == 0);
	char directory[] = "spine-log-directory-XXXXXX";
	assert(mkdtemp(directory) != NULL);
	strncopy(set.logging.path_logfile, directory, sizeof(set.logging.path_logfile));
	assert(!spine_log("must fail to open directory"));
	assert(rmdir(directory) == 0);
#ifdef __linux__
	STRNCOPY(set.logging.path_logfile, "/dev/full");
	assert(!spine_log("must detect buffered write/close failure"));
#endif
	set = previous;
}

static void test_config_directives(void) {
	char path[] = "spine-config-test-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != NULL);
	fputs("# comment\nDB_Host localhost\nDB_Port 3307\nRDB_UseSSL 1\n"
		  "Poller 2\nCacti_Log /tmp/spine-test.log\n"
		  "SNMP_Clientaddr 127.0.0.1\nDB_Pass\nDB_Database final_line",
		file);
	assert(fclose(file) == 0);
	memset(&set, 0, sizeof set);
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	config_defaults();
	assert(read_spine_config(path) == 0);
	assert(strcmp(set.database.host, "localhost") == 0);
	assert(set.database.port == 3307 && set.remote_database.ssl == 1 && set.poller.poller_id == 2);
	assert(strcmp(set.logging.path_logfile, "/tmp/spine-test.log") == 0);
	assert(strcmp(set.snmp.snmp_clientaddr, "127.0.0.1") == 0);
	assert(strcmp(set.database.database, "final_line") == 0);
	assert(set.logging.logfile_processed == 1 && set.logging.log_destination == LOGDEST_BOTH);
	assert(unlink(path) == 0);
	assert(read_spine_config(path) == -1);
}

/* -C accepts any readable path, so a warning about a line that is not a
 * directive must not reveal what the line holds. */
static void test_config_unknown_lines_not_echoed(void) {
	char path[] = "spine-config-echo-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != NULL);
	assert(fputs("DB_Host localhost\nroot:$6$saltsecret:19000:0:99999:7:::\n", file) != EOF);
	assert(fclose(file) == 0);
	int errors[2];
	assert(pipe(errors) == 0);
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		assert(close(errors[0]) == 0);
		assert(dup2(errors[1], STDERR_FILENO) == STDERR_FILENO);
		assert(close(errors[1]) == 0);
		memset(&set, 0, sizeof set);
		set.console.stdout_notty = TRUE;
		set.console.stderr_notty = FALSE;
		config_defaults();
		_exit(read_spine_config(path) == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	assert(close(errors[1]) == 0);
	char message[1024];
	size_t used = 0;
	for (;;) {
		ssize_t received = read(errors[0], message + used, sizeof(message) - used - 1);
		if (received < 0 && errno == EINTR) continue;
		assert(received >= 0);
		if (received == 0) break;
		used += (size_t) received;
		assert(used < sizeof(message) - 1);
	}
	message[used] = '\0';
	assert(close(errors[0]) == 0);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
	assert(unlink(path) == 0);
	assert(strstr(message, "line 2") != NULL);
	assert(strstr(message, "root") == NULL && strstr(message, "salt") == NULL);
}

static void test_config_structure_bindings(void) {
	config_t previous = set;
	memset(&set, 0, sizeof set);
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	set.d_b = 37;
	set.cacti_version = 1232;
	set.cygwinshloc = 1;
	config_defaults();
	assert(strcmp(set.database.host, DEFAULT_DB_HOST) == 0);
	assert(strcmp(set.remote_database.host, DEFAULT_DB_HOST) == 0);
	assert(set.database.port == DEFAULT_DB_PORT && set.remote_database.port == DEFAULT_DB_PORT);
	assert(set.poller.threads == DEFAULT_THREADS && set.logging.log_destination == LOGDEST_FILE);
	char path[] = "spine-config-bindings-XXXXXX";
	int fd = mkstemp(path);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != NULL);
	assert(fputs("DB_Host local-fixture\nDB_Database local-schema\nDB_User local-user\n"
				 "DB_Pass fixture-local-password\nDB_SSL_Key local-key\nDB_SSL_Cert local-cert\nDB_SSL_CA local-ca\n"
				 "RDB_Host remote-fixture\nRDB_Database remote-schema\nRDB_User remote-user\n"
				 "RDB_Pass fixture-remote-password\nRDB_SSL_Key remote-key\nRDB_SSL_Cert remote-cert\nRDB_SSL_CA remote-ca\n"
				 "DB_Port 3307\nRDB_Port 3308\nDB_UseSSL 1\nRDB_UseSSL 2\nPoller 3\n"
				 "SNMP_Clientaddr 127.0.0.2\nCacti_Log /tmp/spine-bindings.log\n",
			   file) != EOF);
	assert(fclose(file) == 0 && read_spine_config(path) == 0);
	assert(strcmp(set.database.host, "local-fixture") == 0);
	assert(strcmp(set.database.database, "local-schema") == 0);
	assert(strcmp(set.database.user, "local-user") == 0);
	assert(strcmp(set.database.password, "fixture-local-password") == 0);
	assert(strcmp(set.database.ssl_key, "local-key") == 0);
	assert(strcmp(set.database.ssl_cert, "local-cert") == 0);
	assert(strcmp(set.database.ssl_ca, "local-ca") == 0);
	assert(strcmp(set.remote_database.host, "remote-fixture") == 0);
	assert(strcmp(set.remote_database.database, "remote-schema") == 0);
	assert(strcmp(set.remote_database.user, "remote-user") == 0);
	assert(strcmp(set.remote_database.password, "fixture-remote-password") == 0);
	assert(strcmp(set.remote_database.ssl_key, "remote-key") == 0);
	assert(strcmp(set.remote_database.ssl_cert, "remote-cert") == 0);
	assert(strcmp(set.remote_database.ssl_ca, "remote-ca") == 0);
	assert(set.database.port == 3307 && set.remote_database.port == 3308);
	assert(set.database.ssl == 1 && set.remote_database.ssl == 2);
	assert(set.poller.poller_id == 3 && set.poller.threads == DEFAULT_THREADS);
	assert(strcmp(set.snmp.snmp_clientaddr, "127.0.0.2") == 0);
	assert(strcmp(set.logging.path_logfile, "/tmp/spine-bindings.log") == 0);
	assert(set.logging.logfile_processed == 1 && set.logging.log_destination == LOGDEST_BOTH);
	assert(set.d_b == 37 && set.cacti_version == 1232 && set.cygwinshloc == 1);
	assert(set.console.stdout_notty && set.console.stderr_notty);
	assert(unlink(path) == 0);
	set = previous;
	puts("production config structure bindings passed");
}

static void test_date_formats(void) {
	const char *const expected[] = {
		"%m/%d/%Y %H:%M:%S - ", "%b/%d/%Y %H:%M:%S - ",
		"%d/%m/%Y %H:%M:%S - ", "%d/%b/%Y %H:%M:%S - ",
		"%Y/%m/%d %H:%M:%S - ", "%Y/%b/%d %H:%M:%S - "};
	set.logging.log_datetime_separator = GDC_SLASH;
	for (int i = GD_MIN; i <= GD_MAX; i++) {
		set.logging.log_datetime_format = i;
		set_date_format();
		assert(strcmp(get_date_format(), expected[i]) == 0);
	}
	set.logging.log_datetime_format = -1;
	set.logging.log_datetime_separator = -1;
	set_date_format();
	assert(strcmp(get_date_format(), expected[GD_DEFAULT]) == 0);
}

static void test_device_logging(void) {
	extern int *debug_devices;
	int devices[100] = {7, 0};
	int *previous = debug_devices;
	debug_devices = devices;
	for (int level = POLLER_VERBOSITY_NONE; level <= POLLER_VERBOSITY_DEVDBG; level++) {
		set.logging.log_level = level;
		for (int minimum = POLLER_VERBOSITY_LOW; minimum <= POLLER_VERBOSITY_DEVDBG; minimum++) {
			assert(spine_should_log_device(7, minimum));
			assert(spine_should_log_device(8, minimum) == (level >= minimum));
		}
	}
	set.logging.log_level = POLLER_VERBOSITY_NONE;
	int evaluated = 0;
	SPINE_LOG_DEVICE(8, POLLER_VERBOSITY_DEBUG, ("hidden %i", ++evaluated));
	assert(evaluated == 0);
	SPINE_LOG_DEVICE(7, POLLER_VERBOSITY_DEBUG, ("visible %i", ++evaluated));
	assert(evaluated == 1);
	debug_devices = previous;
}

static void test_debug_device_bounds(void) {
	struct {
		int before;
		int devices[100];
		int after;
	} output;
	output.before = 123;
	output.after = 456;
	char list[2048];
	size_t used = 0;
	for (int i = 1; i <= 110; i++) {
		used += (size_t) spine_snprintf(list + used, sizeof(list) - used, "%i,", i);
	}
	parse_debug_devices(list, output.devices, 100);
	assert(output.before == 123 && output.after == 456);
	for (int i = 0; i < 99; i++) assert(output.devices[i] == i + 1);
	assert(output.devices[99] == 0);
	char empty[] = "";
	parse_debug_devices(empty, output.devices, 100);
	assert(output.devices[0] == 0);
	char single[] = "7";
	parse_debug_devices(single, output.devices, 1);
	assert(output.devices[0] == 0);
	output.devices[0] = 7;
	parse_debug_devices(single, output.devices, 0);
	assert(output.devices[0] == 7);
}

static void test_poll_result_formats(void) {
	const struct {
		const char *input;
		const char *output;
		enum poll_result_status status;
	} cases[] = {
		{"123", "123", POLL_RESULT_VALID},
		{"-12.5", "-12.5", POLL_RESULT_VALID},
		{"4096 Bytes", "4096", POLL_RESULT_VALID},
		{"a:1 b!2", "a:1 b!2", POLL_RESULT_VALID},
		{"a!1", "a!1", POLL_RESULT_VALID},
		{"U", "U", POLL_RESULT_UNDEFINED},
		{"nonsense", "U", POLL_RESULT_INVALID},
		/* Padding is not data: " 42" once parsed as the octets 0x42. */
		{" 42", "42", POLL_RESULT_VALID},
		{"42\n", "42", POLL_RESULT_VALID},
		{"  10\n", "10", POLL_RESULT_VALID},
		{"\"42\"", "42", POLL_RESULT_VALID},
		{"1F FF FF FF FF FF FF F1", "2305843009213693937", POLL_RESULT_VALID},
		{"0x1A", "U", POLL_RESULT_INVALID},
		{"---", "U", POLL_RESULT_INVALID},
		{"   ", "U", POLL_RESULT_INVALID}};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (int snmp = 0; snmp <= 1; snmp++) {
			char result[RESULTS_BUFFER];
			strncopy(result, cases[i].input, sizeof(result));
			assert(normalize_poll_result(result, snmp) == cases[i].status);
			assert(strcmp(result, cases[i].output) == 0);
		}
	}
	/* An agent's "u" or "NaN" is unknown, and poller_output stores it as U. */
	static const char *const unknown[] = {"u", "NaN", "nan"};
	for (size_t i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
		char undefined[RESULTS_BUFFER];
		strncopy(undefined, unknown[i], sizeof(undefined));
		assert(normalize_poll_result(undefined, true) == POLL_RESULT_UNDEFINED);
		assert(strcmp(undefined, "U") == 0);
		strncopy(undefined, unknown[i], sizeof(undefined));
		assert(normalize_poll_result(undefined, false) == POLL_RESULT_INVALID);
		assert(strcmp(undefined, "U") == 0);
	}
}

static void test_hostnames(void) {
	const char *const inputs[] = {"router.example", "router.example:161", "TCP:router.example:443",
		"udp:router.example:53", "[2001:db8::1]"};
	const char *const outputs[] = {"router.example", "router.example", "router.example", "router.example", "[2001:db8::1]"};
	const int ports[] = {0, 161, 443, 53, 0};
	const int methods[] = {0, 0, 1, 2, 0};
	for (size_t i = 0; i < sizeof(inputs) / sizeof(inputs[0]); i++) {
		char input[128];
		strncopy(input, inputs[i], sizeof(input));
		name_t *name = get_namebyhost(input, NULL);
		assert(strcmp(name->hostname, outputs[i]) == 0);
		assert(name->port == ports[i] && name->method == methods[i]);
		free(name);
	}
}

static void test_snmp_initialization_failure(void) {
	/* These inputs fail before a network session opens. Temporary connection
	 * parameters and passphrase copies must be released on every error path. */
	assert(snmp_host_init(&(snmp_connection_t){
			   .host_id = 1,
			   .hostname = "127.0.0.1",
			   .snmp_version = 99,
			   .snmp_community = "public",
			   .snmp_username = "",
			   .snmp_password = "",
			   .snmp_auth_protocol = "SHA",
			   .snmp_priv_passphrase = "",
			   .snmp_priv_protocol = "[None]",
			   .snmp_context = "",
			   .snmp_engine_id = "",
			   .snmp_port = 161,
			   .snmp_timeout = 1000,
		   }) == NULL);
	assert(snmp_host_init(&(snmp_connection_t){
			   .host_id = 1,
			   .hostname = "127.0.0.1",
			   .snmp_version = 3,
			   .snmp_community = "public",
			   .snmp_username = "user",
			   .snmp_password = "short",
			   .snmp_auth_protocol = "INVALID",
			   .snmp_priv_passphrase = "",
			   .snmp_priv_protocol = "[None]",
			   .snmp_context = "",
			   .snmp_engine_id = "",
			   .snmp_port = 161,
			   .snmp_timeout = 1000,
		   }) == NULL);
	assert(snmp_host_init(&(snmp_connection_t){
			   .host_id = 1,
			   .hostname = "127.0.0.1",
			   .snmp_version = 3,
			   .snmp_community = "public",
			   .snmp_username = "user",
			   .snmp_password = "short",
			   .snmp_auth_protocol = "SHA",
			   .snmp_priv_passphrase = "short",
			   .snmp_priv_protocol = "AES",
			   .snmp_context = "",
			   .snmp_engine_id = "",
			   .snmp_port = 161,
			   .snmp_timeout = 1000,
		   }) == NULL);
	assert(snmp_host_init(&(snmp_connection_t){
			   .host_id = 1,
			   .hostname = "127.0.0.1",
			   .snmp_version = 3,
			   .snmp_community = "public",
			   .snmp_username = "user",
			   .snmp_password = "regression-password",
			   .snmp_auth_protocol = "SHA",
			   .snmp_priv_passphrase = "short",
			   .snmp_priv_protocol = "AES",
			   .snmp_context = "",
			   .snmp_engine_id = "",
			   .snmp_port = 161,
			   .snmp_timeout = 1000,
		   }) == NULL);
}

static void test_snmp_security_protocols(void) {
	snmp_spine_init();
	snmp_connection_t options = {
		.host_id = 1,
		.hostname = "127.0.0.1",
		.snmp_version = 3,
		.snmp_community = "",
		.snmp_username = "regression-user",
		.snmp_password = "",
		.snmp_auth_protocol = "SHA",
		.snmp_priv_passphrase = "",
		.snmp_priv_protocol = "[None]",
		.snmp_context = "regression-context",
		.snmp_engine_id = "",
		.snmp_port = 1161,
		.snmp_timeout = 500,
	};
	const int levels[] = {SNMP_SEC_LEVEL_NOAUTH, SNMP_SEC_LEVEL_AUTHNOPRIV, SNMP_SEC_LEVEL_AUTHPRIV};
	for (size_t index = 0; index < sizeof(levels) / sizeof(levels[0]); index++) {
		options.snmp_password = index == 0 ? "" : "regression-password";
		options.snmp_priv_protocol = index == 2 ? "AES" : "[None]";
		options.snmp_priv_passphrase = index == 2 ? "regression-privacy" : "";
		void *handle = snmp_host_init(&options);
		assert(handle != NULL);
		const struct snmp_session *session = snmp_sess_session(handle);
		assert(session != NULL && session->version == SNMP_VERSION_3);
		assert(session->securityLevel == levels[index]);
		assert(strcmp(session->securityName, options.snmp_username) == 0);
		assert(strcmp(session->contextName, options.snmp_context) == 0);
		assert(session->securityAuthProto != NULL && session->securityPrivProto != NULL);
		if (index == 2) {
			assert(session->securityAuthKeyLen == 20); /* SHA-1 Ku length. */
			assert(session->securityPrivKeyLen == 20);
		}
		snmp_host_cleanup(handle);
	}
	test_additional_snmp_session_boundaries();
	options.snmp_priv_protocol = "INVALID";
	assert(snmp_host_init(&options) == NULL);
	snmp_spine_close();
}

static void test_child_process(void) {
	int fd = nft_popen("printf spine-test", "r");
	assert(fd >= 0);
	char output[32] = {0};
	size_t used = 0;
	ssize_t received;
	while ((received = read(fd, output + used, sizeof(output) - 1 - used)) != 0) {
		if (received < 0 && errno == EINTR) continue;
		assert(received > 0);
		used += (size_t) received;
		assert(used < sizeof(output) - 1);
	}
	assert(used == 10);
	assert(strcmp(output, "spine-test") == 0);
	int status = nft_pclose(fd);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	assert(nft_popen("printf ignored", "invalid") == -1);
	assert(nft_popen("printf ignored", "invalid+") == -1 && errno == EINVAL);
	assert(nft_popen(NULL, "r") == -1 && errno == EINVAL);
	assert(nft_popen("printf ignored", NULL) == -1 && errno == EINVAL);
}

static void test_duplex_process(void) {
	int fd = nft_popen("IFS= read -r value; printf '%s' \"$value\"", "r+");
	assert(fd >= 0);
	assert(write(fd, "duplex\n", 7) == 7);
	char output[7] = {0};
	size_t used = 0;
	while (used < 6) {
		ssize_t received = read(fd, output + used, 6 - used);
		if (received < 0 && errno == EINTR) continue;
		assert(received > 0);
		used += (size_t) received;
	}
	assert(strcmp(output, "duplex") == 0);
	int status = nft_pclose(fd);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_write_process(void) {
	char path[] = "spine-write-process-XXXXXX";
	int temporary = mkstemp(path);
	assert(temporary >= 0 && close(temporary) == 0);
	char command[BUFSIZE];
	spine_snprintf(command, sizeof(command), "cat > %s", path);
	int fd = nft_popen(command, "w");
	assert(fd >= 0 && write(fd, "written", 7) == 7);
	/* cat copies each read straight through, so the data reaches the file
	 * before EOF. Check it while the writer is still open: nft_pclose() never
	 * blocks the poller on a slow child and may signal it once closed. */
	char output[8] = {0};
	FILE *file = NULL;
	for (int attempt = 0; attempt < 200; attempt++) {
		file = fopen(path, "r");
		assert(file != NULL);
		memset(output, 0, sizeof(output));
		if (fread(output, 1, 7, file) == 7) break;
		assert(fclose(file) == 0);
		file = NULL;
		spine_sleep_usec(10000);
	}
	assert(file != NULL && strcmp(output, "written") == 0);
	int status = nft_pclose(fd);
	assert(status == -1 || (WIFEXITED(status) && WEXITSTATUS(status) == 0) || WIFSIGNALED(status));
	assert(fgetc(file) == EOF && !ferror(file));
	assert(fclose(file) == 0 && unlink(path) == 0);
}

static void test_process_descriptor_aliases(void) {
	for (int mask = 1; mask <= 3; mask++) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			alarm(5);
			if (mask & 1) assert(close(STDIN_FILENO) == 0);
			if (mask & 2) assert(close(STDOUT_FILENO) == 0);
			/* Keep an earlier parent pipe in the list, possibly at 0 or 1. */
			int retained = nft_popen("printf retained", "r");
			assert(retained >= 0);
			test_duplex_process();
			char output[16] = {0};
			assert(read(retained, output, sizeof(output) - 1) == 8);
			assert(strcmp(output, "retained") == 0);
			int status = nft_pclose(retained);
			assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
			_exit(0);
		}
		int status;
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
}

/* Drive the shipped php_readpipe() against a pipe that stands in for a
 * script server. A failed read restarts the slot, so point the restart at a
 * missing executable to keep it local. */
static char *read_php_pipe(int fd, int timeout) {
	config_t previous_config = set;
	php_t *previous_processes = php_processes;
	php_t process;
	php_processes_initialize(&process, 1);
	process.php_read_fd = fd;
	process.php_state = PHP_BUSY;
	php_processes = &process;
	set.php.php_servers = 1;
	set.php.script_timeout = timeout;
	STRNCOPY(set.php.path_php, "/nonexistent-spine-regression-executable");
	char *result = php_readpipe(0, "regression");
	if (process.php_read_fd >= 0) close(process.php_read_fd);
	if (process.php_write_fd >= 0) close(process.php_write_fd);
	php_processes = previous_processes;
	set = previous_config;
	return result;
}

static void test_php_response(size_t length, bool newline) {
	int pipes[2];
	assert(pipe(pipes) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		close(pipes[0]);
		char *data = malloc(length);
		assert(data != NULL);
		memset(data, '7', length);
		if (newline) data[length - 1] = '\n';
		size_t sent = 0;
		while (sent < length) {
			ssize_t count = write(pipes[1], data + sent, length - sent);
			if (count < 0 && errno == EINTR) continue;
			if (count < 0 && errno == EPIPE) break;
			assert(count > 0);
			sent += (size_t) count;
		}
		free(data);
		close(pipes[1]);
		_exit(0);
	}
	close(pipes[1]);
	char *result = read_php_pipe(pipes[0], 5);
	if (newline) {
		assert(strlen(result) == length && result[length - 1] == '\n');
	} else {
		assert(strcmp(result, "U") == 0);
	}
	free(result);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_php_partial_response_timeout(void) {
	/* A server that writes part of a line and stalls must not hold the
	 * poller thread past the response deadline. */
	int pipes[2];
	assert(pipe(pipes) == 0);
	assert(write(pipes[1], "7", 1) == 1);
	double begin = spine_monotonic_time();
	char *result = read_php_pipe(pipes[0], 1);
	assert(spine_monotonic_time() - begin < 5);
	assert(strcmp(result, "U") == 0);
	free(result);
	close(pipes[1]);
}

/* Script server arguments can carry SNMP communities and v3 passphrases, so
 * no failure line may repeat the command arguments, at any verbosity.
 * Drives the timeout, partial-line and lost-server paths of the real code. */
static void run_php_failure_logs(int level) {
	static const char secret[] = "regression-community-7d1f";
	config_t previous_config = set;
	php_t *previous_processes = php_processes;
	char path[] = "spine-php-redaction-XXXXXX";
	int log_fd = mkstemp(path);
	assert(log_fd >= 0 && close(log_fd) == 0);
	set.logging.log_destination = LOGDEST_FILE;
	set.logging.log_level = level;
	set.logging.logfile_processed = TRUE;
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	strncopy(set.logging.path_logfile, path, sizeof(set.logging.path_logfile));
	set.php.php_servers = 1;
	set.php.script_timeout = 1;
	STRNCOPY(set.php.path_php, "/nonexistent-spine-regression-executable");
	char command[BUFSIZE];
	spine_snprintf(command, sizeof(command), "ss_regression.php ss_regression 127.0.0.1 %s\r\n", secret);
	php_t *process = malloc(sizeof(*process));
	assert(process != NULL);
	php_processes = process;
	for (int partial = 0; partial <= 1; partial++) {
		int pipes[2];
		assert(pipe(pipes) == 0);
		if (partial) assert(write(pipes[1], "7", 1) == 1);
		php_processes_initialize(process, 1);
		process->php_read_fd = pipes[0];
		char *result = php_readpipe(0, command);
		assert(strcmp(result, "U") == 0);
		free(result);
		if (process->php_read_fd >= 0) close(process->php_read_fd);
		assert(close(pipes[1]) == 0);
	}
	int requests[2];
	assert(pipe(requests) == 0 && close(requests[0]) == 0);
	int responses[2];
	assert(pipe(responses) == 0);
	fflush(NULL);
	pid_t server = fork();
	assert(server >= 0);
	if (server == 0) {
		pause();
		_exit(0);
	}
	php_processes_initialize(process, 1);
	process->php_state = PHP_READY;
	process->php_pid = server;
	process->php_write_fd = requests[1];
	process->php_read_fd = responses[0];
	/* The write fails with EPIPE; restarts fail on the missing executable. */
	char *result = php_cmd(command, 0);
	assert(strcmp(result, "U") == 0);
	free(result);
	assert(close(responses[1]) == 0);
	int status;
	assert(waitpid(server, &status, 0) == server);
	/* The script poller logs the same commands; drive its empty-result and
	 * missing-file lines with the secret in the arguments. */
	assert(spine_permits_init(&available_scripts, 1) == 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "regression-device");
	char script_command[BUFSIZE];
	spine_snprintf(script_command, sizeof(script_command), "/usr/bin/printf '' %s", secret);
	result = exec_poll(&host, script_command, 1, "DS");
	assert(strcmp(result, "U") == 0);
	free(result);
	spine_snprintf(script_command, sizeof(script_command), "/spine-regression/missing-script %s", secret);
	result = exec_poll(&host, script_command, 1, "DS");
	assert(strcmp(result, "U") == 0);
	free(result);
	assert(spine_permits_destroy(&available_scripts) == 0);
	FILE *file = fopen(path, "r");
	assert(file != NULL);
	char logged[16384];
	size_t bytes = fread(logged, 1, sizeof(logged) - 1, file);
	assert(!ferror(file) && fclose(file) == 0);
	logged[bytes] = '\0';
	assert(strstr(logged, "did not respond in time") != NULL);
	assert(strstr(logged, "partial response") != NULL);
	assert(strstr(logged, "communications lost") != NULL);
	assert(strstr(logged, "Empty result [regression-device]: '/usr/bin/printf'") != NULL);
	assert(strstr(logged, "File '/spine-regression/missing-script' does not exist") != NULL);
	fprintf(stderr, "php failure logs at level %d contain command arguments: %s\n", level, strstr(logged, secret) != NULL ? "yes" : "no");
	assert(strstr(logged, secret) == NULL);
	/* Debug output still names the script, which is enough to find it. */
	if (level == POLLER_VERBOSITY_DEBUG) {
		assert(strstr(logged, "ss_regression.php") != NULL);
		assert(strstr(logged, "The executable is '/usr/bin/printf'") != NULL);
	}
	assert(unlink(path) == 0);
	php_processes = previous_processes;
	free(process);
	set = previous_config;
}

static void test_php_failure_logs_omit_command(void) {
	run_php_failure_logs(POLLER_VERBOSITY_LOW);
	run_php_failure_logs(POLLER_VERBOSITY_DEBUG);
}

static void test_script_execution(void) {
	assert(spine_permits_init(&available_scripts, 1) == 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "regression-device");
	int previous_timeout = set.php.script_timeout;
	set.php.script_timeout = 1;
	char command[] = "/usr/bin/printf 7";
	char *result = exec_poll(&host, command, 1, "DS");
	assert(strcmp(result, "7") == 0);
	free(result);
	char delayed[] = "/bin/sleep 2";
	double begin = spine_monotonic_time();
	result = exec_poll(&host, delayed, 1, "DS");
	assert(strcmp(result, "U") == 0);
	assert(spine_monotonic_time() - begin < 5);
	free(result);
	assert(spine_permits_available(&available_scripts) == 1);
	for (int timeout = -1; timeout <= 0; timeout++) {
		set.php.script_timeout = timeout;
		result = exec_poll(&host, command, 1, "DS");
		assert(strcmp(result, "U") == 0);
		free(result);
		assert(spine_permits_available(&available_scripts) == 1);
	}
	set.php.script_timeout = 1;
	assert(spine_permits_try_acquire(&available_scripts) == 0);
	begin = spine_monotonic_time();
	result = exec_poll(&host, command, 1, "DS");
	assert(strcmp(result, "U") == 0);
	assert(spine_monotonic_time() - begin < 1);
	free(result);
	assert(spine_permits_available(&available_scripts) == 0);
	assert(spine_permits_release(&available_scripts) == 0);
	/* exec_poll() reads a script's answer once, so the script must write it
	 * in one call. printf(1) does not promise that: the uutils printf in
	 * Ubuntu 26.04 writes 1024 bytes at a time. dd copies its single input
	 * block with one write(). */
	char output_command[128];
	char output_path[] = "spine-script-output-XXXXXX";
	char output[RESULTS_BUFFER + 1];
	memset(output, 'x', sizeof(output));
	for (int excess = 0; excess <= 1; excess++) {
		int output_fd = mkstemp(output_path);
		assert(output_fd >= 0);
		assert(write(output_fd, output, RESULTS_BUFFER - 1 + excess) == RESULTS_BUFFER - 1 + excess);
		assert(close(output_fd) == 0);
		spine_snprintf(output_command, sizeof(output_command), "/bin/dd if=%s bs=%d count=1 2>/dev/null", output_path, 2 * RESULTS_BUFFER);
		result = exec_poll(&host, output_command, 1, "DS");
		assert(strlen(result) == RESULTS_BUFFER - 1);
		assert(result[RESULTS_BUFFER - 1] == '\0');
		free(result);
		assert(unlink(output_path) == 0);
		memcpy(output_path + sizeof(output_path) - 7, "XXXXXX", 6);
		assert(spine_permits_available(&available_scripts) == 1);
	}
	char empty[] = "/usr/bin/printf ''";
	result = exec_poll(&host, empty, 1, "DQ");
	assert(strcmp(result, "U") == 0);
	free(result);
	char missing[] = "/spine-regression/nonexistent-executable";
	result = exec_poll(&host, missing, 1, "DS");
	assert(strcmp(result, "U") == 0);
	free(result);
	assert(spine_permits_available(&available_scripts) == 1);
	assert(spine_permits_destroy(&available_scripts) == 0);
	set.php.script_timeout = previous_timeout;
}

/* A timed-out script is killed with everything it started. The background
 * sleep inherits the write end of the witness pipe, so EOF on the read end
 * proves that no descendant outlived the timeout. */
static void test_script_timeout_kills_descendants(void) {
	assert(spine_permits_init(&available_scripts, 1) == 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "regression-device");
	int previous_timeout = set.php.script_timeout;
	set.php.script_timeout = 1;
	int witness[2];
	assert(pipe(witness) == 0);
	char command[] = "/bin/sh -c '/bin/sleep 30 & /bin/sleep 30'";
	char *result = exec_poll(&host, command, 1, "DS");
	assert(strcmp(result, "U") == 0);
	free(result);
	assert(close(witness[1]) == 0);
	assert(witness[0] < FD_SETSIZE);
	fd_set readable;
	FD_ZERO(&readable);
	FD_SET(witness[0], &readable);
	struct timeval timeout = {3, 0};
	int ready = select(witness[0] + 1, &readable, NULL, NULL, &timeout);
	char byte;
	fprintf(stderr, "script timeout descendants: ready=%d\n", ready);
	assert(ready == 1 && read(witness[0], &byte, 1) == 0);
	assert(close(witness[0]) == 0);
	assert(spine_permits_available(&available_scripts) == 1);
	assert(spine_permits_destroy(&available_scripts) == 0);
	set.php.script_timeout = previous_timeout;
}

/* nft_pclose() kills a script that is still running after its output was
 * read, and the kill must reach the script's descendants as well. */
static void test_pclose_kills_descendants(void) {
	int witness[2];
	assert(pipe(witness) == 0);
	int fd = nft_popen("printf 7; /bin/sleep 30 & /bin/sleep 30", "r");
	assert(fd >= 0);
	char byte;
	assert(read(fd, &byte, 1) == 1 && byte == '7');
	assert(nft_pclose(fd) == -1 && errno == ETIMEDOUT);
	assert(close(witness[1]) == 0);
	assert(witness[0] < FD_SETSIZE);
	fd_set readable;
	FD_ZERO(&readable);
	FD_SET(witness[0], &readable);
	struct timeval timeout = {3, 0};
	int ready = select(witness[0] + 1, &readable, NULL, NULL, &timeout);
	fprintf(stderr, "pclose descendants: ready=%d\n", ready);
	assert(ready == 1 && read(witness[0], &byte, 1) == 0);
	assert(close(witness[0]) == 0);
}

static void test_php_command(size_t length) {
	char command[BUFSIZE];
	assert(length <= sizeof(command) - 3);
	memset(command, 'c', length);
	command[length] = '\0';
	int requests[2];
	int responses[2];
	assert(pipe(requests) == 0 && pipe(responses) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		close(requests[1]);
		close(responses[0]);
		char received[BUFSIZE] = {0};
		size_t used = 0;
		while (used < length + 2) {
			ssize_t bytes = read(requests[0], received + used, length + 2 - used);
			if (bytes < 0 && errno == EINTR) continue;
			assert(bytes > 0);
			used += (size_t) bytes;
		}
		assert(memcmp(received, command, length) == 0);
		assert(received[length] == '\r' && received[length + 1] == '\n');
		assert(write(responses[1], "7\n", 2) == 2);
		close(requests[0]);
		close(responses[1]);
		_exit(0);
	}
	close(requests[0]);
	close(responses[1]);
	php_t process = {0};
	/* php_cmd() only talks to a READY slot that owns a live child. */
	process.php_state = PHP_READY;
	process.php_pid = child;
	process.php_write_fd = requests[1];
	process.php_read_fd = responses[0];
	php_t *previous = php_processes;
	php_processes = &process;
	set.php.php_servers = 1;
	set.php.script_timeout = 5;
	char *result = php_cmd(command, 0);
	assert(strcmp(result, "7\n") == 0);
	free(result);
	php_processes = previous;
	close(requests[1]);
	close(responses[0]);
	int status;
	assert(waitpid(child, &status, 0) == child);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void test_invalid_php_commands(void) {
	/* Invalid requests must return before touching server state or writing. */
	char *result = php_cmd("invalid\r\nline", 0);
	assert(strcmp(result, "U") == 0);
	free(result);
	char oversized[BUFSIZE];
	memset(oversized, 'c', sizeof(oversized) - 1);
	oversized[sizeof(oversized) - 1] = '\0';
	result = php_cmd(oversized, 0);
	assert(strcmp(result, "U") == 0);
	free(result);
	result = php_cmd("valid", -1);
	assert(strcmp(result, "U") == 0);
	free(result);
}

static int run_test_script_server(int argc, char **argv) {
	assert(argc >= 5);
	if (strncmp(argv[2], "regression-server:", 18) == 0) {
		char *end;
		errno = 0;
		long descriptor = strtol(argv[2] + 18, &end, 10);
		assert(errno == 0 && *end == 0 && descriptor >= 3 && descriptor <= INT_MAX);
		char token;
		ssize_t received = read((int) descriptor, &token, 1);
		assert(close((int) descriptor) == 0);
		if (received == 0) return 127;
		assert(received == 1 && token == 82);
	} else assert(strcmp(argv[2], "regression-server") == 0);
	if (strcmp(argv[3], "spine") == 0) {
		assert(argc == 5 && strcmp(argv[4], "1") == 0);
	} else {
		assert(strcmp(argv[3], "--environ=spine") == 0);
		assert(strcmp(argv[4], "--poller=1") == 0 || strcmp(argv[4], "--poller=2") == 0);
		if (strcmp(argv[4], "--poller=2") == 0) {
			assert(argc == 6 && (strcmp(argv[5], "--mode=online") == 0 || strcmp(argv[5], "--mode=offline") == 0));
		} else assert(argc == 5);
	}
	puts("Started");
	fflush(stdout);
	char command[BUFSIZE];
	while (fgets(command, sizeof(command), stdin) != NULL) {
		if (strcmp(command, "quit\r\n") == 0) return 0;
		puts("7");
		fflush(stdout);
	}
	return 17; /* EOF without quit must not count as graceful protocol shutdown. */
}

static void assert_php_responses(const php_t *processes, int count) {
	for (int index = 0; index < count; index++) {
		assert(processes[index].php_state == PHP_READY);
		char *result = php_cmd("regression request", index);
		assert(strcmp(result, "7\n") == 0);
		free(result);
	}
}

static void assert_php_children_reaped(const php_t *processes, const pid_t *children, size_t count) {
	for (size_t index = 0; index < count; index++) {
		int status;
		assert(waitpid(children[index], &status, WNOHANG) == -1 && errno == ECHILD);
		assert(processes[index].php_pid == -1);
	}
}

static void test_php_startup(const char *executable) {
	char *absolute = realpath(executable, NULL);
	assert(absolute != NULL);
	config_t previous_config = set;
	php_t *previous_processes = php_processes;
	php_t processes[2];
	memset(processes, 0, sizeof(processes));
	php_processes = processes;
	STRNCOPY(set.php.path_php, absolute);
	free(absolute);
	STRNCOPY(set.php.path_php_server, "regression-server");
	set.php.script_timeout = 5;
	set.php.php_servers = 2;
	const int versions[] = {1222, 1223, 1223, 1223};
	const int pollers[] = {1, 1, 2, 2};
	const int modes[] = {REMOTE_ONLINE, REMOTE_ONLINE, REMOTE_ONLINE, REMOTE_OFFLINE};
	for (size_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
		set.cacti_version = versions[i];
		set.poller.poller_id = pollers[i];
		set.poller.mode = modes[i];
		assert(php_init(PHP_INIT));
		assert_php_responses(processes, set.php.php_servers);
		pid_t children[] = {processes[0].php_pid, processes[1].php_pid};
		php_close(PHP_INIT);
		assert_php_children_reaped(processes, children, sizeof(children) / sizeof(children[0]));
	}
	/* An inherited one-byte pipe admits the first child and rejects the second. */
	int admissions[2];
	assert(pipe(admissions) == 0);
	assert(write(admissions[1], "R", 1) == 1 && close(admissions[1]) == 0);
	spine_snprintf(set.php.path_php_server, sizeof(set.php.path_php_server), "regression-server:%d", admissions[0]);
	assert(php_init(PHP_INIT));
	/* A server that never answered stays BUSY for the restart path; shutdown
	 * still reaps both children. */
	assert(processes[0].php_state == PHP_READY && processes[1].php_state == PHP_BUSY);
	php_close(PHP_INIT);
	assert(processes[0].php_pid == -1 && processes[1].php_pid == -1);
	assert(close(admissions[0]) == 0);
	STRNCOPY(set.php.path_php_server, "regression-server");
	assert(!php_init(-2) && !php_init(set.php.php_servers));
	STRNCOPY(set.php.path_php, "/nonexistent-spine-regression-executable");
	/* Some libcs return an exec error to the parent; OpenBSD reports it
	 * through the child exit instead. Neither path may produce a READY slot. */
	if (php_init(0)) {
		assert(processes[0].php_state == PHP_BUSY);
		php_close(0);
	}
	assert(processes[0].php_state == PHP_BUSY);
	assert(processes[0].php_read_fd == -1 && processes[0].php_write_fd == -1);
	/* posix_spawn reports a missing executable to the parent (or the child
	 * exits 127 where the libc defers exec errors), so no server is left. */
	assert(processes[0].php_pid == -1);
	char *failed_command = php_cmd("request on stopped server", 0);
	assert(strcmp(failed_command, "U") == 0);
	free(failed_command);
	assert(processes[0].php_pid == -1 && processes[0].php_state == PHP_BUSY);
	php_processes = previous_processes;
	set = previous_config;
}

static void test_php_owned_shutdown(void) {
	int requests[2];
	int responses[2];
	assert(pipe(requests) == 0 && pipe(responses) == 0);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		close(requests[1]);
		close(responses[0]);
		assert(signal(SIGTERM, SIG_IGN) != SIG_ERR);
		assert(write(responses[1], "R", 1) == 1);
		for (;;) pause();
	}
	close(requests[0]);
	close(responses[1]);
	char ready;
	assert(read(responses[0], &ready, 1) == 1 && ready == 'R');
	int flags = fcntl(requests[1], F_GETFL);
	assert(flags >= 0 && fcntl(requests[1], F_SETFL, flags | O_NONBLOCK) == 0);
	char padding[1024] = {0};
	while (write(requests[1], padding, sizeof(padding)) > 0) { /* Fill the pipe until the nonblocking write refuses more data. */
	}
	assert(errno == EAGAIN || errno == EWOULDBLOCK);
	assert(fcntl(requests[1], F_SETFL, flags) == 0);
	php_t server = {0};
	server.php_pid = child;
	server.php_write_fd = requests[1];
	server.php_read_fd = responses[0];
	php_t *previous_processes = php_processes;
	int previous_count = set.php.php_servers;
	php_processes = &server;
	set.php.php_servers = 1;
	double begin = spine_monotonic_time();
	alarm(5);
	php_close(0);
	alarm(0);
	assert(spine_monotonic_time() - begin < 4.0);
	assert(server.php_pid == -1 && server.php_read_fd == -1 && server.php_write_fd == -1);
	assert(fcntl(requests[1], F_GETFD) == -1 && errno == EBADF);
	assert(fcntl(responses[0], F_GETFD) == -1 && errno == EBADF);
	/* php_close() sends SIGKILL and parks a child that has not exited yet
	 * instead of blocking the poller, so it is reaped here or by the sweep. */
	int status;
	pid_t reaped = waitpid(child, &status, 0);
	assert((reaped == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL) ||
		(reaped == -1 && errno == ECHILD));
	php_close(0);
	/* A stale PID for a non-child must be retired without sending a signal. */
	server.php_pid = getpid();
	php_close(0);
	assert(server.php_pid == -1);
	php_processes = previous_processes;
	set.php.php_servers = previous_count;
}

static void test_udp_deadline(void) {
	struct sockaddr_in address = {0};
	assert(init_sockaddr(&address, "127.0.0.1", 0));
	assert(address.sin_family == AF_INET && address.sin_addr.s_addr == htonl(INADDR_LOOPBACK));
	assert(!init_sockaddr(&address, "127.0.0.1", -1));
	assert(!init_sockaddr(&address, "127.0.0.1", 65536));
	int server = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	assert(server >= 0);
	assert(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0);
	socklen_t length = sizeof(address);
	assert(getsockname(server, (struct sockaddr *) &address, &length) == 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	host.availability.port = ntohs(address.sin_port);
	host.availability.timeout = 650;
	host.availability.retries = 0;
	ping_t ping = {0};
	double begin = spine_monotonic_time();
	assert(ping_udp(&host, &ping) == HOST_DOWN);
	double elapsed = spine_monotonic_time() - begin;
	assert(elapsed >= 0.60 && elapsed < 1.25);
	assert(strcmp(ping.ping_response, "UDP: Ping timed out") == 0);
	char request[64];
	ssize_t received = recv(server, request, sizeof(request), 0);
	static const char expected[] = "cacti-monitoring-system";
	assert(received == (ssize_t) (sizeof(expected) - 1));
	assert(memcmp(request, expected, sizeof(expected) - 1) == 0);
	assert(close(server) == 0);
	host.availability.timeout = 0;
	assert(ping_udp(&host, &ping) == HOST_DOWN);
}

static bool icmp_reply_matches(const unsigned char *reply, size_t length, uint16_t id, uint16_t sequence) {
	return spine_icmp_classify_reply(reply, (ssize_t) length, id, sequence, NULL) == SPINE_ICMP_REPLY_OK;
}

static void test_icmp_reply_bounds(void) {
	unsigned char storage[29] = {0};
	unsigned char *reply = storage + 1;
	reply[0] = 0x45;
	reply[9] = IPPROTO_ICMP;
	uint16_t id = htons(123);
	uint16_t sequence = htons(456);
	memcpy(reply + 24, &id, sizeof(id));
	memcpy(reply + 26, &sequence, sizeof(sequence));
	assert(icmp_reply_matches(reply, 28, id, sequence));
	assert(!icmp_reply_matches(NULL, 28, id, sequence));
	for (size_t length = 0; length < 28; length++) assert(!icmp_reply_matches(reply, length, id, sequence));
	assert(!icmp_reply_matches(reply, 28, htons(124), sequence));
	assert(!icmp_reply_matches(reply, 28, id, htons(457)));
	reply[0] = 0x44;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
	reply[0] = 0x4f;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
	reply[0] = 0x65;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
	reply[0] = 0x45;
	reply[20] = ICMP_ECHO;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
	reply[20] = ICMP_ECHOREPLY;
	reply[21] = 1;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
	reply[21] = 0;
	reply[9] = IPPROTO_TCP;
	assert(!icmp_reply_matches(reply, 28, id, sequence));
}

static void test_icmp_loopback(void) {
	host_t host = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	host.availability.timeout = 500;
	host.availability.retries = 0;
	ping_t ping = {0};
	assert(ping_icmp(&host, &ping) == HOST_UP);
	assert(strcmp(ping.ping_response, "ICMP: Device is Alive") == 0);
	assert(geteuid() == getuid());
}

static void test_icmp_socket_failure(void) {
	assert(geteuid() != 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	host.availability.timeout = 100;
	ping_t ping = {0};
	/* Where net.ipv4.ping_group_range admits this user, ICMP works through an
	 * unprivileged datagram socket and needs no capability at all. */
	int datagram = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (datagram >= 0) {
		close(datagram);
		host.availability.timeout = 500;
		assert(ping_icmp(&host, &ping) == HOST_UP);
		assert(strcmp(ping.ping_response, "ICMP: Device is Alive") == 0);
		assert(geteuid() == getuid());
		return;
	}
	/* Failed socket retries must give up without regaining root. */
	alarm(6);
	assert(ping_icmp(&host, &ping) == HOST_DOWN);
	alarm(0);
	assert(strcmp(ping.ping_response, "ICMP: Ping unable to create ICMP Socket") == 0);
	assert(geteuid() == getuid());
}

static unsigned int query_sample_count(MYSQL *mysql, const char *query) {
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_fields(result) == 2);
	unsigned int samples = 0;
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) samples += (unsigned int) atoi(row[1]);
	db_free_result(result);
	return samples;
}

static void test_poller_query_case(MYSQL *mysql, int poller, int active, int ports) {
	static const unsigned int all_rows[] = {3, 2, 1};
	static const unsigned int due_rows[] = {2, 1, 1};
	set.poller.poller_id = poller;
	set.poller.active_profiles = active;
	set.snmp.total_snmp_ports = ports;
	poller_queries_t queries;
	poller_prepare_queries(&queries, 42, 1, 0);
	MYSQL_RES *result = db_query(mysql, LOCAL, queries.items);
	assert(result != NULL && mysql_num_fields(result) == 20);
	assert(mysql_num_rows(result) == all_rows[poller]);
	db_free_result(result);
	result = db_query(mysql, LOCAL, queries.due_items);
	unsigned int expected_due = active ? all_rows[poller] : due_rows[poller];
	assert(result != NULL && mysql_num_rows(result) == expected_due);
	db_free_result(result);
	assert(query_sample_count(mysql, queries.agents) == all_rows[poller]);
	assert(query_sample_count(mysql, queries.due_agents) == expected_due);
}

static void test_poller_schedule(MYSQL *mysql) {
	poller_queries_t queries;
	set.poller.poller_interval = 60;
	set.poller.poller_id = 1;
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET rrd_step=300,rrd_next_step=180 WHERE host_id=42") == TRUE);
	poller_prepare_queries(&queries, 42, 1, 0);
	assert(db_insert(mysql, LOCAL, queries.schedule) == TRUE);
	MYSQL_RES *result = db_query(mysql, LOCAL, "SELECT local_data_id,rrd_next_step FROM poller_item WHERE host_id=42 ORDER BY local_data_id");
	assert(result != NULL && mysql_num_rows(result) == 3);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "101") == 0 && strcmp(row[1], "120") == 0);
	row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "102") == 0 && strcmp(row[1], "120") == 0);
	row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "103") == 0 && strcmp(row[1], "180") == 0);
	db_free_result(result);
	set.poller.poller_id = 0;
	poller_prepare_queries(&queries, 42, 1, 0);
	assert(db_insert(mysql, LOCAL, queries.schedule) == TRUE);
	result = db_query(mysql, LOCAL, "SELECT rrd_next_step FROM poller_item WHERE local_data_id=103");
	assert(result != NULL && mysql_num_rows(result) == 1);
	row = mysql_fetch_row(result);
	assert(row != NULL && strcmp(row[0], "120") == 0);
	db_free_result(result);
}

static void test_poller_queries(MYSQL *mysql) {
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item") == TRUE);
	assert(db_insert(mysql, LOCAL, "DELETE FROM host") == TRUE);
	assert(db_insert(mysql, LOCAL, "INSERT INTO host (id,hostname) VALUES (42,'127.0.0.1')") == TRUE);
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,rrd_next_step,snmp_port) VALUES (101,42,1,0,161),(102,42,1,1,162),(103,42,2,0,161),(104,99,1,0,161),(105,0,1,0,161)") == TRUE);
	poller_queries_t queries;
	for (int poller = 0; poller <= 2; poller++) {
		for (int active = 0; active <= 1; active++) {
			for (int ports = 1; ports <= 2; ports++) {
				test_poller_query_case(mysql, poller, active, ports);
			}
		}
	}
	set.poller.poller_id = 1;
	poller_prepare_queries(&queries, 42, 1, 1);
	MYSQL_RES *result = db_query(mysql, LOCAL, queries.items);
	assert(result != NULL && mysql_num_rows(result) == 1);
	db_free_result(result);
	poller_prepare_queries(&queries, 42, 3, 1);
	result = db_query(mysql, LOCAL, queries.items);
	assert(result != NULL && mysql_num_rows(result) == 0);
	db_free_result(result);
	poller_prepare_queries(&queries, 42, INT_MAX, INT_MAX);
	result = db_query(mysql, LOCAL, queries.items);
	assert(result != NULL && mysql_num_rows(result) == 0);
	db_free_result(result);
	poller_prepare_queries(&queries, 42, 1, 0);
	result = db_query(mysql, LOCAL, queries.host);
	assert(result != NULL && mysql_num_fields(result) == 37 && mysql_num_rows(result) == 1);
	db_free_result(result);
	assert(db_insert(mysql, LOCAL, "UPDATE host SET deleted='on' WHERE id=42") == TRUE);
	result = db_query(mysql, LOCAL, queries.host);
	assert(result != NULL && mysql_num_rows(result) == 0);
	db_free_result(result);
	result = db_query(mysql, LOCAL, queries.reindex);
	assert(result != NULL && mysql_num_fields(result) == 5 && mysql_num_rows(result) == 0);
	db_free_result(result);
	poller_prepare_queries(&queries, 0, 1, 0);
	result = db_query(mysql, LOCAL, queries.items);
	assert(result != NULL && mysql_num_rows(result) == 1);
	db_free_result(result);
	test_poller_schedule(mysql);
}

static unsigned long database_count(MYSQL *mysql, const char *query) {
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1 && mysql_num_fields(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	unsigned long value = strtoul(row[0], NULL, 10);
	db_free_result(result);
	return value;
}

static void seed_transfer_rows(MYSQL *source) {
	assert(db_insert(source, LOCAL, "DELETE FROM host"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item"));
	for (int index = 1; index <= 502; index++) {
		char query[BUFSIZE];
		spine_snprintf(query, sizeof(query), "INSERT INTO host (id,poller_id,snmp_sysDescr,status_last_error,last_updated,min_time) VALUES (%d,%d,'quote\\\' and slash\\\\',NULL,NULL,NULL)", index, index == 502 ? 3 : 2);
		assert(db_insert(source, LOCAL, query));
	}
	assert(db_insert(source, LOCAL, "UPDATE host SET snmp_sysDescr=REPEAT(CONVERT(0xF09F8CB5 USING utf8mb4),300) WHERE id=501"));
	for (int begin = 1; begin <= 10002; begin += 100) {
		char query[BUFSIZE * 8];
		size_t used = (size_t) spine_snprintf(query, sizeof(query), "INSERT INTO poller_item (local_data_id,host_id,poller_id,rrd_name,rrd_step,rrd_next_step) VALUES ");
		int end = begin + 100;
		if (end > 10003) end = 10003;
		for (int index = begin; index < end; index++) {
			used += (size_t) spine_snprintf(query + used, sizeof(query) - used, "%s(%d,%d,%d,'r\\\'r',300,120)", index == begin ? "" : ",", index, index == 10002 ? 502 : 501, index == 10002 ? 3 : 2);
		}
		assert(db_insert(source, LOCAL, query));
	}
}

static void test_transfer_boundary(MYSQL *source, MYSQL *destination) {
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM host") == 501);
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 10001);
	assert(database_count(destination, "SELECT COUNT(*) FROM host WHERE status_last_error IS NULL AND min_time IS NULL") == 501);
	assert(database_count(destination, "SELECT COUNT(*) FROM host d JOIN spine_regressions.host s ON s.id=d.id WHERE NOT (d.last_updated <=> s.last_updated)") == 0);
	assert(database_count(destination, "SELECT CHAR_LENGTH(snmp_sysDescr) FROM host WHERE id=501") == 300);
	assert(database_count(destination, "SELECT OCTET_LENGTH(snmp_sysDescr) FROM host WHERE id=501") == 1200);
	assert(database_count(destination, "SELECT COUNT(*) FROM host WHERE snmp_sysDescr=CONCAT('quote',CHAR(39),' and slash',CHAR(92))") == 500);
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item WHERE rrd_name='r\\\'r' AND rrd_next_step=120") == 10001);
	/* Upsert retries must update only the existing documented columns. */
	assert(db_insert(destination, REMOTE, "UPDATE poller_item SET rrd_step=900,rrd_next_step=999"));
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item WHERE rrd_step=900 AND rrd_next_step=120") == 10001);
}

static void test_transfer_failure_and_filter(MYSQL *source, MYSQL *destination) {
	assert(db_insert(destination, REMOTE, "DELETE FROM host"));
	assert(db_insert(destination, REMOTE, "DELETE FROM poller_item"));
	assert(db_insert(destination, REMOTE, "CREATE TRIGGER reject_transfer BEFORE INSERT ON host FOR EACH ROW BEGIN IF NEW.id=501 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='regression late-batch failure'; END IF; END"));
	assert(!poller_transfer_status(source, destination));
	set.exit.exit_code = EXIT_SUCCESS;
	poller_push_data_to_main();
	assert(set.exit.exit_code == EXIT_FAILURE);
	assert(database_count(destination, "SELECT COUNT(*) FROM host") == 500);
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 0);
	assert(database_count(source, "SELECT COUNT(*) FROM host") == 502);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_item") == 10002);
	assert(db_insert(destination, REMOTE, "DROP TRIGGER reject_transfer"));
	set.exit.exit_code = EXIT_SUCCESS;
	poller_push_data_to_main();
	assert(set.exit.exit_code == EXIT_SUCCESS);
	assert(database_count(destination, "SELECT COUNT(*) FROM host") == 501);
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 10001);
	assert(db_insert(destination, REMOTE, "DELETE FROM poller_item"));
	assert(db_insert(destination, REMOTE, "CREATE TRIGGER reject_item_transfer BEFORE INSERT ON poller_item FOR EACH ROW BEGIN IF NEW.local_data_id=10001 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='regression final-item failure'; END IF; END"));
	assert(!poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 10000);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_item") == 10002);
	assert(db_insert(destination, REMOTE, "DROP TRIGGER reject_item_transfer"));
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 10001);
	/* Full-width Unicode across all text fields must flush by bytes before 500 rows. */
	assert(db_insert(source, LOCAL, "UPDATE host SET snmp_sysDescr=REPEAT(CONVERT(0xF09F8CB5 USING utf8mb4),300),snmp_sysContact=snmp_sysDescr,snmp_sysName=snmp_sysDescr,snmp_sysLocation=snmp_sysDescr WHERE poller_id=2"));
	assert(db_insert(destination, REMOTE, "DELETE FROM host"));
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM host WHERE OCTET_LENGTH(snmp_sysDescr)=1200 AND OCTET_LENGTH(snmp_sysLocation)=1200") == 501);
	assert(db_insert(destination, REMOTE, "DELETE FROM host"));
	assert(db_insert(destination, REMOTE, "DELETE FROM poller_item"));
	STRNCOPY(set.hosts.host_id_list, "1");
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM host") == 1);
	assert(database_count(destination, "SELECT COUNT(*) FROM poller_item") == 0);
	set.hosts.host_id_list[0] = '\0';
	assert(db_insert(source, LOCAL, "DELETE FROM host"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item"));
	assert(poller_transfer_status(source, destination));
	assert(database_count(destination, "SELECT COUNT(*) FROM host") == 1);
}

static void test_collector_transfer(MYSQL *source) {
	config_t previous = set;
	set.poller.poller_id = 2;
	set.database.onupdate = 0;
	set.hosts.host_id_list[0] = '\0';
	char database[80];
	char query[BUFSIZE];
	spine_snprintf(database, sizeof(database), "spine_transfer_%ld", (long) getpid());
	STRNCOPY(set.remote_database.host, set.database.host);
	STRNCOPY(set.remote_database.user, set.database.user);
	STRNCOPY(set.remote_database.password, set.database.password);
	STRNCOPY(set.remote_database.database, database);
	set.remote_database.port = set.database.port;
	set.remote_database.ssl = FALSE;
	spine_snprintf(query, sizeof(query), "CREATE DATABASE %s CHARACTER SET utf8mb4", database);
	assert(db_insert(source, LOCAL, query));
	MYSQL destination;
	db_connect(LOCAL, &destination);
	assert(mysql_select_db(&destination, database) == 0);
	assert(mysql_set_character_set(source, "utf8mb4") == 0 && mysql_set_character_set(&destination, "utf8mb4") == 0);
	assert(db_insert(&destination, REMOTE, "CREATE TABLE host LIKE spine_regressions.host"));
	assert(db_insert(&destination, REMOTE, "CREATE TABLE poller_item LIKE spine_regressions.poller_item"));
	seed_transfer_rows(source);
	test_transfer_boundary(source, &destination);
	test_transfer_failure_and_filter(source, &destination);
	db_disconnect(&destination);
	spine_snprintf(query, sizeof(query), "DROP DATABASE %s", database);
	assert(db_insert(source, LOCAL, query));
	set = previous;
}

static void test_database_version(MYSQL *mysql) {
	const struct {
		const char *text;
		int expected;
	} cases[] = {
		{"1.2.32", 1232}, {"1.3.0_develop", 1300}, {"1.2.33-beta1", 1233},
		{"2147483.6.47", INT_MAX}, {"2147483.6.48", 0}, {"2147483647.0.0", 0},
		{"99999999999999999999", 0}, {"new_install", 0}, {"", 0},
		{"1.2", 0}, {"1.x.3", 0}, {"1.2.-1", 0}, {"-1.2.3", 0}};
	for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
		assert(db_insert(mysql, LOCAL, "DELETE FROM version"));
		char query[BUFSIZE];
		spine_snprintf(query, sizeof(query), "INSERT INTO version(cacti) VALUES ('%s')", cases[index].text);
		assert(db_insert(mysql, LOCAL, query));
		assert(get_cacti_version(mysql, LOCAL) == cases[index].expected);
	}
	assert(db_insert(mysql, LOCAL, "DELETE FROM version"));
	assert(get_cacti_version(mysql, LOCAL) == 0);
	assert(db_insert(mysql, LOCAL, "INSERT INTO version(cacti) VALUES ('1.2.32')"));
}

typedef struct {
	poller_thread_t thread;
	int errors;
} test_poll_work_t;

static void *test_poll_worker(void *argument) {
	test_poll_work_t *work = argument;
	assert(mysql_thread_init() == 0);
	poll_host(&work->thread, &work->errors);
	return NULL;
}

/* A worker without a connection fails its device and returns; the process
 * keeps polling other devices and still exits with a failure status. */
static void test_poll_missing_connection(const poller_thread_t *work) {
	for (int remote = 0; remote <= 1; remote++) {
		pid_t child = fork();
		assert(child >= 0);
		if (child == 0) {
			pool_t unavailable = {0};
			if (remote) {
				set.poller.poller_id = 2;
				set.poller.mode = REMOTE_ONLINE;
				db_pool_remote = &unavailable;
			} else db_pool_local[0].free = FALSE;
			extern poller_thread_t **details;
			poller_thread_t *device = details[work->device_counter];
			device->complete = FALSE;
			device->threads_complete = 0;
			int errors = 0;
			set.exit.exit_code = EXIT_SUCCESS;
			poll_host(work, &errors);
			if (!device->poll_failed || device->complete || device->threads_complete != 1) _exit(3);
			/* The local slot borrowed for a remote poll goes back to the pool. */
			if (remote && !db_pool_local[0].free) _exit(4);
			/* The failure still reaches the process exit status. */
			_exit(set.exit.exit_code == EXIT_FAILURE ? 0 : 5);
		}
		int status;
		assert(waitpid(child, &status, 0) == child);
		fprintf(stderr, "missing connection: remote=%d raw_status=%d\n", remote, status);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	}
}

static void test_reindex_pipeline(MYSQL *mysql, test_poll_work_t *work) {
	static const struct {
		const char *op;
		const char *expected;
		const char *command;
		int action;
		int queued;
		const char *stored;
		const char *output;
	} cases[] = {
		{"=", "123", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 0, "123", "123"},
		{"=", "122", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 1, "123", "123"},
		{">", "122", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 1, "123", "123"},
		{">", "124", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 0, "123", "123"},
		{"<", "124", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 1, "123", "U"},
		{"<", "122", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 0, "123", "123"},
		{"<", "0", "/usr/bin/printf 123", POLLER_ACTION_SCRIPT, 0, "123", "123"},
		{"=", "123", "/usr/bin/printf 'a\\nb\\n'", POLLER_ACTION_SCRIPT_COUNT, 1, "2", "123"},
		{"=", "123", "/usr/bin/printf U", POLLER_ACTION_SCRIPT, 0, "123", "123"},
		{"<", "124", "/usr/bin/printf U", POLLER_ACTION_SCRIPT, 0, "124", "123"},
		{"<", "124", "unknown", 99, 0, "124", "123"}};
	for (int level = 0; level <= 2; level++) {
		set.logging.spine_log_level = level;
		for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
			assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
			assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
			assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
			assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
			char escaped_command[BUFSIZE];
			db_escape(mysql, escaped_command, sizeof(escaped_command), cases[index].command);
			char query[LRG_BUFSIZE];
			spine_snprintf(query, sizeof(query), "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (%d,7,%d,'%s','%s','%s')", work->thread.host_id, cases[index].action, cases[index].op, cases[index].expected, escaped_command);
			assert(db_insert(mysql, LOCAL, query));
			work->thread.complete = FALSE;
			work->thread.threads_complete = 0;
			work->errors = 0;
			pthread_t worker;
			start_test_worker(&worker, test_poll_worker, work);
			assert(pthread_join(worker, NULL) == 0);
			assert(work->thread.complete && work->thread.threads_complete == 1);
			int expected_errors = 1;
			if (level == 1) expected_errors += cases[index].queued + (cases[index].queued && STRMATCH(cases[index].output, "U"));
			assert(work->errors == expected_errors);
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_command WHERE poller_id=1 AND action=%d AND command='%d:7'", POLLER_COMMAND_REINDEX, work->thread.host_id);
			assert(database_count(mysql, query) == (unsigned long) cases[index].queued);
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_reindex WHERE assert_value='%s'", cases[index].stored);
			assert(database_count(mysql, query) == 1);
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output WHERE local_data_id=601 AND output='%s'", cases[index].output);
			assert(database_count(mysql, query) == 1);
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=601 AND output='%s'", cases[index].output);
			assert(database_count(mysql, query) == 1);
			assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
		}
	}
	set.logging.spine_log_level = 0;
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
}

/* A reindex that could not be queued must leave the stored assertion alone;
 * advancing it would hide the change from every later poll. Hiding the
 * poller_command table makes the server itself reject the queue write. */
static void test_reindex_queue_failure(MYSQL *mysql, test_poll_work_t *work) {
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (43,7,1,'=','122','/usr/bin/printf 123'),(43,8,1,'>','122','/usr/bin/printf 123')"));
	assert(db_insert(mysql, LOCAL, "RENAME TABLE poller_command TO poller_command_regression_hidden"));
	work->thread.complete = FALSE;
	work->thread.threads_complete = 0;
	work->errors = 0;
	pthread_t worker;
	start_test_worker(&worker, test_poll_worker, work);
	assert(pthread_join(worker, NULL) == 0);
	assert(db_insert(mysql, LOCAL, "RENAME TABLE poller_command_regression_hidden TO poller_command"));
	long long kept = (long long) database_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE (data_query_id=7 AND assert_value='122') OR (data_query_id=8 AND assert_value='122')");
	fprintf(stderr, "reindex queue failure: assertions kept=%lld\n", kept);
	assert(kept == 2);
	assert(work->thread.threads_complete == 1);
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
}

static void test_reindex_query_shortcut(MYSQL *mysql, test_poll_work_t *work) {
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (43,7,1,'=','122','/usr/bin/printf 123'),(43,7,1,'=','777','/usr/bin/printf 888'),(43,8,1,'=','455','/usr/bin/printf 456')"));
	work->thread.complete = FALSE;
	work->thread.threads_complete = 0;
	work->errors = 0;
	pthread_t worker;
	start_test_worker(&worker, test_poll_worker, work);
	assert(pthread_join(worker, NULL) == 0);
	assert(work->thread.complete && work->thread.threads_complete == 1 && work->errors == 1);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_command") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE (data_query_id=7 AND arg1='/usr/bin/printf 123' AND assert_value='123') OR (data_query_id=7 AND arg1='/usr/bin/printf 888' AND assert_value='777') OR (data_query_id=8 AND arg1='/usr/bin/printf 456' AND assert_value='456')") == 3);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
}

static void test_profile_schedule_completion(MYSQL *mysql, test_poll_work_t *aggregate) {
	config_t previous = set;
	test_poll_work_t original = *aggregate;
	set.poller.active_profiles = 2;
	set.poller.poller_interval = 5;
	set.snmp.total_snmp_ports = 1;
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET rrd_step=300,rrd_next_step=0 WHERE host_id=43"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,action,arg1,rrd_name,rrd_step,rrd_next_step) VALUES (603,43,1,1,'/usr/bin/printf 789','not-due',300,100)"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
	aggregate->thread.host_thread = 2;
	aggregate->thread.host_threads = 2;
	aggregate->thread.host_data_ids = 1;
	aggregate->thread.complete = FALSE;
	aggregate->thread.threads_complete = 0;
	/* Deliberately finish partition 2 before partition 1 has selected its rows. */
	test_poll_work_t second = *aggregate;
	second.thread.host_thread = 2;
	pthread_t worker;
	start_test_worker(&worker, test_poll_worker, &second);
	assert(pthread_join(worker, NULL) == 0);
	assert(aggregate->thread.threads_complete == 1 && !aggregate->thread.complete);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=43 AND rrd_next_step=0") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=602 AND output='U'") == 1);
	test_poll_work_t first = *aggregate;
	first.thread.host_thread = 1;
	start_test_worker(&worker, test_poll_worker, &first);
	assert(pthread_join(worker, NULL) == 0);
	assert(aggregate->thread.threads_complete == 2 && aggregate->thread.complete);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=603") == 0);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=43 AND ((local_data_id IN (601,602) AND rrd_next_step=295) OR (local_data_id=603 AND rrd_next_step=95))") == 3);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
	*aggregate = original;
	set = previous;
}

/* A real, non-retryable SQL error inside a worker fails that device and the
 * worker returns: the schedule is not advanced, nothing is written, and the
 * connection goes back to the pool for the next device. The item query names
 * a column the fixture schema lacks, so MariaDB itself rejects it. */
static void test_poll_database_failure(MYSQL *mysql, test_poll_work_t *aggregate) {
	config_t previous = set;
	test_poll_work_t original = *aggregate;
	assert(database_count(mysql, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='poller_item' AND COLUMN_NAME='output_regex'") == 0);
	set.poller.active_profiles = 2;
	set.poller.poller_interval = 5;
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=43 AND local_data_id NOT IN (601,602)"));
	for (int failing = 1; failing >= 0; failing--) {
		set.hosts.has_output_regex = failing;
		assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET rrd_step=300,rrd_next_step=0 WHERE host_id=43"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
		aggregate->thread.host_thread = 1;
		aggregate->thread.host_threads = 1;
		aggregate->thread.host_data_ids = 0;
		aggregate->thread.complete = FALSE;
		aggregate->thread.threads_complete = 0;
		aggregate->thread.output_failed = FALSE;
		aggregate->thread.poll_failed = FALSE;
		set.exit.exit_code = EXIT_SUCCESS;
		pthread_t worker;
		start_test_worker(&worker, test_poll_worker, aggregate);
		assert(pthread_join(worker, NULL) == 0);
		assert(aggregate->thread.threads_complete == 1);
		assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
		if (failing) {
			assert(aggregate->thread.poll_failed && !aggregate->thread.complete);
			assert(set.exit.exit_code == EXIT_FAILURE);
			assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output") == 0);
			assert(database_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=43 AND rrd_next_step=0") == 2);
		} else {
			assert(!aggregate->thread.poll_failed && aggregate->thread.complete);
			assert(set.exit.exit_code == EXIT_SUCCESS);
			assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
			assert(database_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=43 AND rrd_next_step=295") == 2);
		}
	}
	*aggregate = original;
	set = previous;
}

static void prepare_nullable_snmp_profile(MYSQL *mysql) {
	/* These fields are nullable in the shipped schema; missing values
	 * must survive the real row-loader/session handoff. */
	assert(db_insert(mysql, LOCAL, "UPDATE host SET snmp_context=NULL,snmp_engine_id=NULL WHERE id=44"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_context=NULL,snmp_engine_id=NULL,arg2=NULL,arg3=NULL WHERE host_id=44"));
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=44 AND snmp_context IS NULL AND snmp_engine_id IS NULL AND arg2 IS NULL AND arg3 IS NULL") == 2);
}

static void assert_snmp_pipeline_samples(MYSQL *mysql, bool spike) {
	char query[LRG_BUFSIZE];
	/* A restarted agent invalidates every sample of the cycle, including
	 * those flushed early because the next item's credentials differ. */
	const char *first_check = spike ? "output='U'" : "output REGEXP '^[0-9]+$' AND CAST(output AS UNSIGNED)>0";
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output WHERE local_data_id=601 AND %s", first_check);
	assert(database_count(mysql, query) == 1);
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=601 AND %s", first_check);
	assert(database_count(mysql, query) == 1);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=602 AND output='U'") == 1);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=602 AND output='U'") == 1);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output_boost") == 2);
	assert(database_count(mysql, "SELECT COUNT(*) FROM poller_command") == (spike ? 1 : 0));
}

static void test_snmp_item_pipeline(MYSQL *mysql, test_poll_work_t *work, const char *agent) {
	char escaped_agent[BUFSIZE];
	db_escape(mysql, escaped_agent, sizeof(escaped_agent), agent);
	for (int scenario = 0; scenario < 9; scenario++) {
		bool change_version = (scenario & 2) != 0;
		bool spike = (scenario & 4) != 0;
		char query[LRG_BUFSIZE];
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
		spine_snprintf(query, sizeof(query), "UPDATE host SET max_oids=%d WHERE id=44", 1 + (scenario & 1));
		assert(db_insert(mysql, LOCAL, query));
		spine_snprintf(query, sizeof(query), "UPDATE poller_item SET action=0,hostname='%s',snmp_community='regression',snmp_version=2,snmp_port=1161,snmp_timeout=500,arg1='.1.3.6.1.2.1.1.3.0' WHERE host_id=44", escaped_agent);
		assert(db_insert(mysql, LOCAL, query));
		spine_snprintf(query, sizeof(query), "UPDATE poller_item SET snmp_version=%d,arg1='%s' WHERE local_data_id=602", change_version ? 1 : 2, spike ? ".1.3.6.1.2.1.1.3.0" : ".1.3.6.1.2.1.1.999.0");
		assert(db_insert(mysql, LOCAL, query));
		if (spike) assert(db_insert(mysql, LOCAL, "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (44,7,1,'<','124','/usr/bin/printf 123')"));
		if (scenario == 8) {
			prepare_nullable_snmp_profile(mysql);
		}
		work->thread.complete = FALSE;
		work->thread.threads_complete = 0;
		work->errors = 0;
		pthread_t worker;
		start_test_worker(&worker, test_poll_worker, work);
		assert(pthread_join(worker, NULL) == 0);
		assert(work->thread.complete && work->thread.threads_complete == 1);
		assert(work->errors == (spike ? 0 : 1));
		assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
		assert_snmp_pipeline_samples(mysql, spike);
		if (scenario == 8) puts("production nullable SNMP profile handoff passed");
	}
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	assert(db_insert(mysql, LOCAL, "UPDATE host SET snmp_context='',snmp_engine_id='' WHERE id=44"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_context='',snmp_engine_id='' WHERE host_id=44"));
}

/* Each item leaves through a different batch flush: 601 through the
 * batch-full flush (max_oids=1) or the credential-change flush (602 switches
 * to v1), and 602 through the final flush. All three must apply the same
 * output_regex and spike kill. */
static void test_snmp_flush_contracts(MYSQL *mysql, test_poll_work_t *work, const char *agent) {
	char escaped_agent[BUFSIZE];
	char query[LRG_BUFSIZE];
	int previous_regex = set.hosts.has_output_regex;
	db_escape(mysql, escaped_agent, sizeof(escaped_agent), agent);
	assert(db_insert(mysql, LOCAL, "ALTER TABLE poller_item ADD COLUMN output_regex varchar(255) NOT NULL DEFAULT ''"));
	set.hosts.has_output_regex = TRUE;
	for (int scenario = 0; scenario < 4; scenario++) {
		bool full_batch = (scenario & 1) != 0;
		bool spike = (scenario & 2) != 0;
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
		spine_snprintf(query, sizeof(query), "UPDATE host SET max_oids=%d WHERE id=44", full_batch ? 1 : 5);
		assert(db_insert(mysql, LOCAL, query));
		/* The leading digit of sysUpTime: a visible, still numeric rewrite. */
		spine_snprintf(query, sizeof(query), "UPDATE poller_item SET action=0,hostname='%s',snmp_community='regression',snmp_version=2,snmp_port=1161,snmp_timeout=500,arg1='.1.3.6.1.2.1.1.3.0',output_regex='^[0-9]' WHERE host_id=44", escaped_agent);
		assert(db_insert(mysql, LOCAL, query));
		if (!full_batch) assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_version=1 WHERE local_data_id=602"));
		if (spike) assert(db_insert(mysql, LOCAL, "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (44,7,1,'<','124','/usr/bin/printf 123')"));
		work->thread.complete = FALSE;
		work->thread.threads_complete = 0;
		work->errors = 0;
		pthread_t worker;
		start_test_worker(&worker, test_poll_worker, work);
		assert(pthread_join(worker, NULL) == 0);
		assert(work->thread.complete && work->thread.threads_complete == 1);
		const char *expected = spike ? "output='U'" : "output REGEXP '^[0-9]$'";
		for (int item = 601; item <= 602; item++) {
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output WHERE local_data_id=%d AND %s", item, expected);
			if (database_count(mysql, query) != 1) {
				fprintf(stderr, "flush contract: scenario=%d full_batch=%d spike=%d item=%d expected %s\n", scenario, full_batch, spike, item, expected);
				assert(0);
			}
			spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=%d AND %s", item, expected);
			assert(database_count(mysql, query) == 1);
		}
	}
	/* Units-bearing strings must become numeric before validation, through
	 * full, credential-change and final batch flushes. */
	for (int scenario = 0; scenario < 3; scenario++) {
		pthread_t units_worker;
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
		spine_snprintf(query, sizeof(query), "UPDATE host SET max_oids=%d WHERE id=44", scenario == 1 ? 1 : 5);
		assert(db_insert(mysql, LOCAL, query));
		assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_version=2,arg1='.1.3.6.1.2.1.1.6.0',output_regex='^[0-9][0-9]*' WHERE host_id=44"));
		if (scenario == 0) assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_version=1 WHERE local_data_id=602"));
		work->thread.complete = FALSE;
		work->thread.threads_complete = 0;
		work->errors = 0;
		start_test_worker(&units_worker, test_poll_worker, work);
		assert(pthread_join(units_worker, NULL) == 0);
		assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id IN (601,602) AND output='42'") == 2);
		assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id IN (601,602) AND output='42'") == 2);
	}
	/* Existing regexes were written against the normalized value: a
	 * Hex-STRING becomes 266 first, then the regex keeps "266", not "00". */
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET snmp_version=2,arg1='.1.3.6.1.2.1.1.5.0',output_regex='^[0-9][0-9]*' WHERE host_id=44"));
	work->thread.complete = FALSE;
	work->thread.threads_complete = 0;
	work->errors = 0;
	pthread_t regex_worker;
	start_test_worker(&regex_worker, test_poll_worker, work);
	assert(pthread_join(regex_worker, NULL) == 0);
	if (database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id IN (601,602) AND output='266'") != 2) {
		fprintf(stderr, "flush contract: output_regex did not see the normalized Hex-STRING\n");
		assert(0);
	}
	set.hosts.has_output_regex = previous_regex;
	assert(db_insert(mysql, LOCAL, "ALTER TABLE poller_item DROP COLUMN output_regex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex"));
	puts("production SNMP batch flush contracts passed");
}

static void assert_polled_host_statistics(MYSQL *mysql, int host_id) {
	if (host_id == 44) {
		assert(database_count(mysql, "SELECT COUNT(*) FROM host WHERE id=44 AND total_polls=1 AND failed_polls=0 AND status_last_error='' AND snmp_sysUpTimeInstance>0 AND snmp_sysDescr!='' AND snmp_sysObjectID!='' AND snmp_sysContact='regression' AND snmp_sysName!='' AND snmp_sysLocation='42 watts'") == 1);
	} else if (host_id != 0) {
		char query[256];
		spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM host WHERE id=%d AND total_polls=1 AND failed_polls=0 AND min_time=0 AND status_last_error=''", host_id);
		assert(database_count(mysql, query) == 1);
	}
}

static void test_poll_pipeline(MYSQL *mysql) {
	extern poller_thread_t **details;
	config_t previous = set;
	pool_t *previous_pool = db_pool_local;
	poller_thread_t **previous_details = details;
	set.poller.threads = 1;
	set.poller.poller_id = 1;
	set.poller.poller_interval = 0;
	set.poller.active_profiles = 1;
	set.boost.boost_enabled = TRUE;
	set.boost.boost_redirect = TRUE;
	set.availability.ping_only = FALSE;
	set.php.script_timeout = 2;
	set.logging.spine_log_level = 0;
	set.logging.log_destination = 0;
	db_pool_local = calloc(1, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_create_connection_pool(LOCAL);
	assert(spine_permits_init(&available_scripts, 2) == 0);
	set.snmp.mibs = FALSE;
	set.availability.ping_recovery_count = 1;
	set.availability.ping_failure_count = 1;
	const char *agent = getenv("SPINE_TEST_SNMP_HOST");
	const int hosts[] = {0, 42, 43, 44};
	size_t host_count = sizeof(hosts) / sizeof(hosts[0]);
	if (agent == NULL || agent[0] == '\0') host_count--;
	else snmp_spine_init();
	for (size_t index = 0; index < host_count; index++) {
		int host_id = hosts[index];
		set.snmp.mibs = host_id == 44;
		assert(db_insert(mysql, LOCAL, "DELETE FROM host"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost"));
		assert(db_insert(mysql, LOCAL, "DELETE FROM host_errors"));
		assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,action,arg1,rrd_name) VALUES (601,0,1,1,'/usr/bin/printf 123','valid'),(602,0,1,1,'/usr/bin/printf invalid','invalid')"));
		char host_query[BUFSIZE];
		spine_snprintf(host_query, sizeof(host_query), "UPDATE poller_item SET host_id=%d", host_id);
		assert(db_insert(mysql, LOCAL, host_query));
		if (host_id != 0) {
			spine_snprintf(host_query, sizeof(host_query), "INSERT INTO host (id,hostname,availability_method,status_fail_date,status_rec_date,max_oids,ping_method,ping_port,status_last_error,min_time,total_polls) VALUES (%d,'127.0.0.1',%d,'2026-10-05 00:00:00','2026-10-05 00:00:00',%d,NULL,NULL,NULL,NULL,NULL)", host_id, host_id == 42 ? AVAIL_STREAM : AVAIL_NONE, host_id == 42 ? 0 : 101);
			assert(db_insert(mysql, LOCAL, host_query));
		}
		if (host_id == 44) {
			char escaped_agent[BUFSIZE];
			db_escape(mysql, escaped_agent, sizeof(escaped_agent), agent);
			spine_snprintf(host_query, sizeof(host_query), "UPDATE host SET hostname='%s',availability_method=%d,snmp_version=2,snmp_community='regression',snmp_port=1161,snmp_timeout=500 WHERE id=44", escaped_agent, AVAIL_SNMP);
			assert(db_insert(mysql, LOCAL, host_query));
		}
		test_poll_work_t *work = calloc(1, sizeof(*work));
		assert(work != NULL);
		work->thread.host_id = host_id;
		work->thread.host_thread = 1;
		work->thread.host_threads = 1;
		work->thread.host_data_ids = 2;
		work->thread.host_time_double = get_time_as_double();
		STRNCOPY(work->thread.host_time, "1791158400");
		poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
		assert(owned_details != NULL);
		owned_details[0] = &work->thread;
		details = owned_details;
		pthread_t worker;
		start_test_worker(&worker, test_poll_worker, work);
		assert(pthread_join(worker, NULL) == 0);
		assert(work->thread.complete && work->thread.threads_complete == 1 && work->errors == 1);
		assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
		if (host_id == 0) test_poll_missing_connection(&work->thread);
		assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
		assert(database_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE (local_data_id=601 AND output='123') OR (local_data_id=602 AND output='U')") == 2);
		char query[256];
		spine_snprintf(query, sizeof(query), "SELECT errors FROM host_errors WHERE host_id=%d", host_id);
		assert(database_count(mysql, query) == 1);
		assert_polled_host_statistics(mysql, host_id);
		if (host_id == 44) {
			test_snmp_item_pipeline(mysql, work, agent);
			test_snmp_flush_contracts(mysql, work, agent);
		}
		if (host_id == 43) {
			test_reindex_pipeline(mysql, work);
			test_reindex_query_shortcut(mysql, work);
			test_reindex_queue_failure(mysql, work);
			test_profile_schedule_completion(mysql, work);
			test_poll_database_failure(mysql, work);
		}
		/* End this fixture binding before the next host or caller runs. */
		details = previous_details;
		free(owned_details);
		free(work);
	}
	assert(spine_permits_destroy(&available_scripts) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	details = previous_details;
	set = previous;
}

static void run_cli_poll_profile(const char *config, const char *poller, const char *threads, const char *interval, const char *profiles, const char *hostlist, int expected) {
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(15);
		if (hostlist != NULL) {
			execl("./spine", "spine", "--conf", config, "-p", poller, "-t", threads, "-H", hostlist, "--mode=online", "-O", interval, "-O", profiles, "-S", "-V", "2", NULL);
			_exit(127);
		}
		execl("./spine", "spine", "-C", "/nonexistent/spine-regression.conf", "--conf", config, "-p", poller, "-t", threads, "--mode=online", "-O", interval, "-O", profiles, "-S", "-V", "2", NULL);
		_exit(127);
	}
	int status;
	assert(waitpid(child, &status, 0) == child);
	printf("Spine executable exit: expected=%d raw_status=%d\n", expected, status);
	fflush(stdout);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == expected);
}

static void run_cli_poll(const char *config, const char *poller, const char *threads, const char *interval, int expected) {
	run_cli_poll_profile(config, poller, threads, interval, "active_profiles:1", NULL, expected);
}

static void test_cli_workers(MYSQL *source, const char *config) {
	assert(db_insert(source, LOCAL, "REPLACE INTO poller(id,threads) VALUES (1,2)"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_time WHERE poller_id=1"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item"));
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "UPDATE host SET hostname='127.0.0.1',poller_id=1,disabled='',device_threads=2,availability_method=%i,status_fail_date='2026-10-05 00:00:00',status_rec_date='2026-10-05 00:00:00' WHERE id=42", AVAIL_NONE);
	assert(db_insert(source, LOCAL, query));
	assert(db_insert(source, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,action,arg1,rrd_name) VALUES (701,42,1,1,'/usr/bin/printf 123','first'),(702,42,1,1,'/usr/bin/printf 456','second')"));
	run_cli_poll(config, "1", "2", "poller_interval:5", EXIT_SUCCESS);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=701 AND output='123') OR (local_data_id=702 AND output='456')") == 2);
	assert(db_insert(source, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(source, LOCAL, "INSERT INTO host(id,hostname,poller_id,disabled,device_threads,availability_method,status_fail_date,status_rec_date) VALUES(43,'127.0.0.1',1,'',1,0,'2026-10-05 00:00:00','2026-10-05 00:00:00')"));
	assert(db_insert(source, LOCAL, "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name) VALUES(704,43,1,1,'/usr/bin/printf 789','excluded')"));
	run_cli_poll_profile(config, "1", "2", "poller_interval:5", "active_profiles:1", " 0042 , 42 ", EXIT_SUCCESS);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=701 AND output='123') OR (local_data_id=702 AND output='456')") == 2);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=704") == 0);
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item WHERE local_data_id=704"));
	assert(db_insert(source, LOCAL, "DELETE FROM host WHERE id=43"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(source, LOCAL, "UPDATE poller_item SET rrd_next_step=0 WHERE local_data_id IN (701,702)"));
	assert(db_insert(source, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,action,arg1,rrd_name,rrd_next_step) VALUES (703,42,1,1,'/usr/bin/printf 789','not-due',100)"));
	run_cli_poll_profile(config, "1", "2", "poller_interval:5", "active_profiles:2", NULL, EXIT_SUCCESS);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE (local_data_id=701 AND output='123') OR (local_data_id=702 AND output='456')") == 2);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=703") == 0);
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item WHERE local_data_id=703"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_output"));
	assert(db_insert(source, LOCAL, "UPDATE poller_item SET arg1='/bin/sleep 3' WHERE local_data_id=702"));
	double start = spine_monotonic_time();
	run_cli_poll(config, "1", "2", "poller_interval:1", EXIT_FAILURE);
	assert(spine_monotonic_time() - start < 3);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=701 AND output='123'") == 1);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=702") == 0);
	assert(database_count(source, "SELECT COUNT(*) FROM poller_time WHERE poller_id=1 AND end_time='0000-00-00 00:00:00'") == 1);
}

static void test_cli_transfer_exit(MYSQL *source) {
	char database[80];
	char username[80];
	char query[BUFSIZE];
	spine_snprintf(database, sizeof(database), "spine_exit_%ld", (long) getpid());
	spine_snprintf(username, sizeof(username), "spine_cli_%ld", (long) getpid());
	spine_snprintf(query, sizeof(query), "CREATE DATABASE %s CHARACTER SET utf8mb4", database);
	assert(db_insert(source, LOCAL, query));
	/* Public fixture credentials, restricted to the two isolated regression databases. */
	spine_snprintf(query, sizeof(query), "CREATE USER '%s'@'%%' IDENTIFIED BY 'regression-only'", username);
	assert(db_insert(source, LOCAL, query));
	spine_snprintf(query, sizeof(query), "GRANT SELECT,INSERT,UPDATE,DELETE ON spine_regressions.* TO '%s'@'%%'", username);
	assert(db_insert(source, LOCAL, query));
	spine_snprintf(query, sizeof(query), "GRANT SELECT,INSERT,UPDATE,DELETE ON %s.* TO '%s'@'%%'", database, username);
	assert(db_insert(source, LOCAL, query));
	MYSQL destination;
	db_connect(LOCAL, &destination);
	assert(mysql_select_db(&destination, database) == 0);
	const char *const tables[] = {"settings", "poller", "poller_item", "version", "host", "poller_time"};
	for (size_t index = 0; index < sizeof(tables) / sizeof(tables[0]); index++) {
		spine_snprintf(query, sizeof(query), "CREATE TABLE %s LIKE spine_regressions.%s", tables[index], tables[index]);
		assert(db_insert(&destination, REMOTE, query));
	}
	assert(db_insert(&destination, REMOTE, "INSERT INTO version VALUES ('1.2.32')"));
	assert(db_insert(source, LOCAL, "REPLACE INTO poller(id,threads) VALUES (2,1)"));
	assert(db_insert(&destination, REMOTE, "INSERT INTO poller(id,threads) VALUES (2,1)"));
	assert(db_insert(source, LOCAL, "DELETE FROM host"));
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item"));
	/* Disabled devices are excluded from CLI polling, but their status still syncs. */
	assert(db_insert(source, LOCAL, "INSERT INTO host (id,poller_id,disabled) VALUES (42,2,'on')"));
	assert(db_insert(&destination, REMOTE, "CREATE TRIGGER reject_cli_transfer BEFORE INSERT ON host FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='regression transfer failure'"));
	char config[] = "spine-cli-exit-XXXXXX";
	int fd = mkstemp(config);
	assert(fd >= 0);
	FILE *file = fdopen(fd, "w");
	assert(file != NULL);
	assert(fprintf(file, "DB_Host %s\nDB_Database spine_regressions\nDB_User %s\nDB_Pass regression-only\nDB_Port 3306\nRDB_Host %s\nRDB_Database %s\nRDB_User %s\nRDB_Pass regression-only\nRDB_Port 3306\nCacti_Log %s.log\n", set.database.host, username, set.database.host, database, username, config) > 0);
	assert(fclose(file) == 0);
	run_cli_poll(config, "2", "1", "poller_interval:5", EXIT_FAILURE);
	assert(database_count(&destination, "SELECT COUNT(*) FROM host") == 0);
	assert(database_count(source, "SELECT COUNT(*) FROM host") == 1);
	assert(db_insert(&destination, REMOTE, "DROP TRIGGER reject_cli_transfer"));
	run_cli_poll(config, "2", "1", "poller_interval:5", EXIT_SUCCESS);
	assert(database_count(&destination, "SELECT COUNT(*) FROM host WHERE id=42") == 1);
	test_cli_workers(source, config);
	assert(unlink(config) == 0);
	spine_snprintf(query, sizeof(query), "%s.log", config);
	if (file_exists(query)) assert(unlink(query) == 0);
	db_disconnect(&destination);
	spine_snprintf(query, sizeof(query), "DROP USER '%s'@'%%'", username);
	assert(db_insert(source, LOCAL, query));
	spine_snprintf(query, sizeof(query), "DROP DATABASE %s", database);
	assert(db_insert(source, LOCAL, query));
}

static void test_database_configuration(void) {
	const char *hostname = getenv("SPINE_TEST_DB_HOST");
	assert(hostname != NULL && hostname[0] != '\0');
	config_defaults();
	strncopy(set.database.host, hostname, sizeof(set.database.host));
	STRNCOPY(set.database.user, "root");
	STRNCOPY(set.database.database, "spine_regressions");
	set.database.password[0] = '\0';
	set.database.port = 3306;
	set.poller.poller_id = 1;
	set.hosts.start_host_id = -1;
	set.hosts.end_host_id = -1;
	set.poller.parent_fork = SPINE_PARENT;
	MYSQL mysql;
	db_connect(LOCAL, &mysql);
	/* Restore the fixture input before testing configuration, including after a failed CLI run. */
	assert(db_insert(&mysql, LOCAL, "REPLACE INTO poller (id,threads) VALUES (1,7)"));
	test_database_version(&mysql);
	assert(db_insert(&mysql, LOCAL, "DELETE FROM settings") == TRUE);
	assert(db_insert(&mysql, LOCAL, "INSERT INTO settings (name,value) VALUES ('path_webroot','/srv/cacti'),('path_cactilog',''),('ping_timeout','650'),('script_timeout','2'),('php_servers','100'),('max_get_size','200'),('default_datechar','99')") == TRUE);
	assert(db_insert(&mysql, LOCAL, "DELETE FROM poller_item") == TRUE);
	assert(db_insert(&mysql, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,action) VALUES (1,42,2)") == TRUE);
	db_disconnect(&mysql);
	read_config_options();
	assert(set.cacti_version == 1232);
	assert(strcmp(set.php.path_php_server, "/srv/cacti/script_server.php") == 0);
	assert(strcmp(set.logging.path_logfile, "/srv/cacti/log/cacti.log") == 0);
	assert(set.availability.ping_timeout == 650 && set.php.script_timeout == 5);
	assert(set.php.php_servers == MAX_PHP_SERVERS && set.snmp.snmp_max_get_size == 128);
	assert(set.logging.log_datetime_separator == GDC_DEFAULT);
	assert(set.poller.threads == 7 && set.php.php_required);
	db_connect(LOCAL, &mysql);
	MYSQL_RES *result = db_query(&mysql, LOCAL, "SELECT value FROM settings WHERE name='spine_capabilities'");
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL && strstr(row[0], "authProtocols") != NULL);
	db_free_result(result);
	assert(db_insert(&mysql, LOCAL, "DELETE FROM poller_item") == TRUE);
	assert(db_insert(&mysql, LOCAL, "UPDATE settings SET value='/tmp/configured.log' WHERE name='path_cactilog'") == TRUE);
	db_disconnect(&mysql);
	set.poller.threads_set = TRUE;
	set.poller.threads = 3;
	STRNCOPY(set.hosts.host_id_list, "42");
	read_config_options();
	assert(set.poller.threads == 3 && !set.php.php_required);
	assert(strcmp(set.logging.path_logfile, "/tmp/configured.log") == 0);
	set_option("ping_timeout", "777");
	read_config_options();
	assert(set.availability.ping_timeout == 777);
	read_config_options();
	assert(set.availability.ping_timeout == 777);
	db_connect(LOCAL, &mysql);
	test_config_option_boundaries(&mysql);
	test_settings_write_contracts(&mysql);
	test_additional_database_contracts(&mysql);
	test_poller_queries(&mysql);
	test_collector_transfer(&mysql);
	test_poll_pipeline(&mysql);
	test_output_write_contracts(&mysql);
	test_reindex_result_contracts(&mysql);
	const char *reindex_agent = getenv("SPINE_TEST_SNMP_HOST");
	if (reindex_agent != NULL && reindex_agent[0] != '\0') test_additional_reindex_contracts(&mysql);
	test_cli_transfer_exit(&mysql);
	db_disconnect(&mysql);
}

static void test_snmp_multi_responses(host_t *host) {
	target_t items[4] = {0};
	snmp_oids_t oids[4] = {0};
	static const char *const names[] = {".1.3.6.1.2.1.1.6.0", "invalid-regression-oid", ".1.3.6.1.2.1.1.1.999", ".1.3.6.1.2.1.1.4.0"};
	for (int index = 0; index < 4; index++) {
		strncopy(oids[index].oid, names[index], sizeof(oids[index].oid));
		oids[index].array_position = index;
		items[index].local_data_id = 100 + index;
	}
	snmp_get_multi(host, items, oids, 4);
	assert(!host->ignore_host);
	assert(strstr(oids[0].result, "42 watts") != NULL);
	assert(strcmp(oids[1].result, "U") == 0);
	/* v1 reports the missing instance as a PDU error and v2c as an inline
	 * exception varbind; neither is data, so both store U. */
	assert(strcmp(oids[2].result, "U") == 0);
	assert(strstr(oids[3].result, "regression") != NULL);
	snmp_get_multi(NULL, NULL, NULL, 0);
	host_t missing_session = {0};
	snmp_oids_t undefined[2] = {0};
	STRNCOPY(undefined[0].result, "123");
	STRNCOPY(undefined[1].result, "456");
	snmp_get_multi(&missing_session, items, undefined, 2);
	assert(missing_session.snmp.status == STAT_DESCRIP_ERROR);
	assert(IS_UNDEFINED(undefined[0].result) && IS_UNDEFINED(undefined[1].result));
	struct variable_list value = {0};
	u_char text[] = "regression";
	value.type = ASN_OCTET_STR;
	value.val.string = text;
	value.val_len = sizeof(text) - 1;
	char formatted[128];
	snmp_snprint_value(formatted, sizeof(formatted), NULL, 0, &value);
	assert(strstr(formatted, "regression") != NULL);
	struct {
		char before;
		char value;
		char after;
	} bounded = {'a', 'x', 'z'};
	snmp_snprint_value(&bounded.value, 0, NULL, 0, &value);
	assert(bounded.before == 'a' && bounded.value == 'x' && bounded.after == 'z');
	snmp_snprint_value(&bounded.value, 1, NULL, 0, &value);
	assert(bounded.before == 'a' && bounded.value == '\0' && bounded.after == 'z');
	snmp_snprint_value(NULL, 0, NULL, 0, &value);
	snmp_snprint_value(NULL, 1, NULL, 0, &value);
	char insufficient[3] = "xx";
	snmp_snprint_value(insufficient, 2, NULL, 0, &value);
	assert(strcmp(insufficient, "U") == 0 && insufficient[2] == '\0');
}

static void test_snmp_scalar_responses(host_t *host) {
	char *result = snmp_get(host, ".1.3.6.1.2.1.1.6.0");
	assert(strstr(result, "42 watts") != NULL && !host->ignore_host);
	free(result);
	/* A malformed configured OID must not poison later requests or leak a PDU. */
	for (int count = 0; count < 50; count++) {
		result = snmp_get(host, "invalid-regression-oid");
		assert(strcmp(result, "U") == 0 && host->snmp.status == STAT_ERROR && !host->ignore_host);
		free(result);
		result = snmp_getnext(host, "invalid-regression-oid");
		assert(strcmp(result, "U") == 0 && host->snmp.status == STAT_ERROR && !host->ignore_host);
		free(result);
	}
	result = snmp_get_base(host, ".1.3.6.1.2.1.1.1.999", FALSE);
	assert(!host->ignore_host);
	if (host->snmp.profile.version == 2) assert(strcmp(result, "U") == 0);
	else assert(strcmp(result, "") == 0);
	free(result);
	result = snmp_get(host, ".1.3.6.1.2.1.1.6.0");
	assert(strstr(result, "42 watts") != NULL && !host->ignore_host);
	free(result);
	if (host->snmp.profile.version == 2) {
		result = snmp_get(host, ".1.3.6.1.2.1.1.1.999");
		assert(strcmp(result, "U") == 0 && host->ignore_host);
		free(result);
		result = snmp_get(host, ".1.3.6.1.2.1.1.6.0");
		assert(strcmp(result, "U") == 0);
		free(result);
		host->ignore_host = FALSE;
	}
}

static void test_system_information(host_t *host) {
	MYSQL mysql;
	assert(mysql_init(&mysql) != NULL);
	int previous_mibs = set.snmp.mibs;
	set.snmp.mibs = FALSE;
	STRNCOPY(host->system.snmp_sysLocation, "untouched");
	get_system_information(host, &mysql, FALSE);
	assert(strcmp(host->system.snmp_sysLocation, "untouched") == 0);
	assert(host->system.snmp_sysUpTimeInstance > 0 && !host->ignore_host);
	for (int explicit_update = 0; explicit_update <= 1; explicit_update++) {
		set.snmp.mibs = !explicit_update;
		get_system_information(host, &mysql, explicit_update);
		assert(strcmp(host->system.snmp_sysLocation, "42 watts") == 0);
		assert(strcmp(host->system.snmp_sysContact, "regression") == 0);
		assert(host->system.snmp_sysDescr[0] != '\0' && host->system.snmp_sysObjectID[0] != '\0');
		assert(host->system.snmp_sysName[0] != '\0' && !host->ignore_host);
	}
	/* Missing sessions return allocated U responses; repeated short polls must free them. */
	void *session = host->snmp.session;
	int previous_ignore = host->ignore_host;
	int previous_status = host->snmp.status;
	host->snmp.session = NULL;
	unsigned long long previous_uptime = host->system.snmp_sysUpTimeInstance;
	set.snmp.mibs = FALSE;
	for (int count = 0; count < 100; count++) get_system_information(host, &mysql, FALSE);
	assert(host->system.snmp_sysUpTimeInstance == previous_uptime);
	host->snmp.session = session;
	host->ignore_host = previous_ignore;
	host->snmp.status = previous_status;
	set.snmp.mibs = previous_mibs;
	mysql_close(&mysql);
}

static void test_snmp_multi_timeout(void) {
	int previous_retries = set.snmp.snmp_retries;
	set.snmp.snmp_retries = 1;
	int silent = socket(AF_INET, SOCK_DGRAM, 0);
	assert(silent >= 0);
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	assert(bind(silent, (struct sockaddr *) &address, sizeof(address)) == 0);
	socklen_t address_length = sizeof(address);
	assert(getsockname(silent, (struct sockaddr *) &address, &address_length) == 0);
	assert(address.sin_family == AF_INET && ntohs(address.sin_port) > 0);
	/* Keep the UDP endpoint bound, without receiving or answering requests.
	 * This produces a real transport timeout instead of ICMP port rejection. */
	for (int version = 1; version <= 2; version++) {
		host_t host = {0};
		STRNCOPY(host.hostname, "127.0.0.1");
		STRNCOPY(host.snmp.profile.community, "regression");
		host.snmp.profile.version = version;
		host.snmp.profile.port = ntohs(address.sin_port);
		host.snmp.profile.timeout = 100;
		host.snmp.session = snmp_host_init(&(snmp_connection_t){
			.host_id = 1,
			.hostname = host.hostname,
			.snmp_version = host.snmp.profile.version,
			.snmp_community = host.snmp.profile.community,
			.snmp_username = "",
			.snmp_password = "",
			.snmp_auth_protocol = "SHA",
			.snmp_priv_passphrase = "",
			.snmp_priv_protocol = "[None]",
			.snmp_context = "",
			.snmp_engine_id = "",
			.snmp_port = host.snmp.profile.port,
			.snmp_timeout = host.snmp.profile.timeout,
		});
		assert(host.snmp.session != NULL);
		const struct snmp_session *session = snmp_sess_session(host.snmp.session);
		assert(session != NULL && session->timeout == 100000L && session->retries == 1);
		const struct netsnmp_transport_s *transport = snmp_sess_transport(host.snmp.session);
		assert(transport != NULL && transport->sock >= 0 && transport->sock != silent);
		int session_fd = transport->sock;
		target_t items[2] = {0};
		snmp_oids_t oids[2] = {0};
		STRNCOPY(oids[0].oid, ".1.3.6.1.2.1.1.3.0");
		STRNCOPY(oids[1].oid, ".1.3.6.1.2.1.1.1.0");
		for (int index = 0; index < 2; index++) {
			oids[index].array_position = index;
			items[index].local_data_id = 100 + index;
			STRNCOPY(oids[index].result, "123");
		}
		snmp_get_multi(&host, items, oids, 2);
		assert(host.snmp.status == STAT_TIMEOUT && host.ignore_host);
		assert(IS_UNDEFINED(oids[0].result) && IS_UNDEFINED(oids[1].result));
		assert(fcntl(session_fd, F_GETFD) >= 0);
		snmp_host_cleanup(host.snmp.session);
		host.snmp.session = NULL;
		errno = 0;
		assert(fcntl(session_fd, F_GETFD) == -1 && errno == EBADF);
	}
	/* Readiness proves requests reached our local fixture; do not drain them. */
	assert(spine_wait_readable(silent, spine_monotonic_time() + 1) == 1);
	assert(close(silent) == 0);
	errno = 0;
	assert(fcntl(silent, F_GETFD) == -1 && errno == EBADF);
	set.snmp.snmp_retries = previous_retries;
	puts("production local silent UDP SNMP multi timeout regressions passed");
}

static void test_snmp_agent(void) {
	const char *address = getenv("SPINE_TEST_SNMP_HOST");
	assert(address != NULL && address[0] != '\0');
	snmp_spine_init();
	set.snmp.snmp_retries = 0;
	const int methods[] = {AVAIL_SNMP, AVAIL_SNMP_GET_SYSDESC, AVAIL_SNMP_GET_NEXT};
	for (int version = 1; version <= 2; version++) {
		host_t host = {0};
		ping_t ping = {0};
		strncopy(host.hostname, address, sizeof(host.hostname));
		STRNCOPY(host.snmp.profile.community, "regression");
		host.snmp.profile.version = version;
		host.snmp.session = snmp_host_init(&(snmp_connection_t){
			.host_id = 1,
			.hostname = host.hostname,
			.snmp_version = version,
			.snmp_community = host.snmp.profile.community,
			.snmp_username = "",
			.snmp_password = "",
			.snmp_auth_protocol = "SHA",
			.snmp_priv_passphrase = "",
			.snmp_priv_protocol = "[None]",
			.snmp_context = "",
			.snmp_engine_id = "",
			.snmp_port = 1161,
			.snmp_timeout = 500,
		});
		assert(host.snmp.session != NULL);
		test_snmp_scalar_responses(&host);
		test_snmp_multi_responses(&host);
		test_system_information(&host);
		assert(snmp_count(&host, ".1.3.6.1.2.1.1.6") == 1 && !host.ignore_host);
		assert(snmp_count(&host, ".1.3.6.1.2.1.1.9999") == 0 && !host.ignore_host);
		/* At the end of the entire MIB, v1 sends an agent error. The old
		 * walker repeated that same request forever. */
		alarm(5);
		double begin = spine_monotonic_time();
		int terminal_count = snmp_count(&host, ".2.999");
		alarm(0);
		assert(terminal_count >= 0 && terminal_count <= 1);
		assert(spine_monotonic_time() - begin < 2.0);
		host.ignore_host = FALSE;
		for (size_t index = 0; index < sizeof(methods) / sizeof(methods[0]); index++) {
			host.availability.method = methods[index];
			assert(ping_host(&host, &ping) == HOST_UP);
			assert(strcmp(ping.snmp_response, "Device responded to SNMP") == 0);
			assert(atof(ping.snmp_status) >= 0.0);
		}
		host.availability.ping_method = PING_TCP;
		host.availability.port = -1;
		host.availability.timeout = 100;
		host.availability.method = AVAIL_SNMP_OR_PING;
		assert(ping_host(&host, &ping) == HOST_UP);
		assert(strcmp(ping.snmp_response, "Device responded to SNMP") == 0);
		STRNCOPY(host.hostname, "localhost");
		host.availability.method = AVAIL_SNMP_AND_PING;
		assert(ping_host(&host, &ping) == HOST_UP);
		snmp_host_cleanup(host.snmp.session);
	}
	test_snmp_multi_timeout();
	snmp_spine_close();
}

static void test_host_status_transitions(void) {
	config_t previous = set;
	set.logging.log_level = POLLER_VERBOSITY_NONE;
	set.availability.ping_failure_count = 2;
	set.availability.ping_recovery_count = 2;
	host_t host = {0};
	ping_t ping = {0};
	STRNCOPY(host.snmp.profile.community, "regression");
	host.snmp.profile.version = 2;
	host.state.status = HOST_UP;
	host.statistics.min_time = 1000;
	STRNCOPY(ping.ping_status, "4");
	STRNCOPY(ping.snmp_status, "8");
	STRNCOPY(ping.ping_response, "network unavailable");
	STRNCOPY(ping.snmp_response, "SNMP unavailable");
	update_host_status(HOST_DOWN, &host, &ping, AVAIL_SNMP_AND_PING);
	assert(host.state.status == HOST_UP && host.state.status_event_count == 1 && host.state.status_fail_date[0] != '\0');
	assert(strcmp(host.state.status_last_error, "SNMP unavailable, network unavailable") == 0);
	update_host_status(HOST_DOWN, &host, &ping, AVAIL_SNMP_AND_PING);
	assert(host.state.status == HOST_DOWN && host.state.status_event_count == 2);
	update_host_status(HOST_UP, &host, &ping, AVAIL_SNMP_AND_PING);
	assert(host.state.status == HOST_RECOVERING && host.state.status_event_count == 1 && host.state.status_rec_date[0] != '\0');
	assert(host.statistics.cur_time == 6 && host.statistics.min_time == 6 && host.statistics.max_time == 6 && host.statistics.avg_time == 6);
	update_host_status(HOST_DOWN, &host, &ping, AVAIL_SNMP);
	assert(host.state.status == HOST_DOWN && host.state.status_event_count == 1);
	update_host_status(HOST_UP, &host, &ping, AVAIL_SNMP);
	update_host_status(HOST_UP, &host, &ping, AVAIL_PING);
	assert(host.state.status == HOST_UP && host.state.status_event_count == 0);
	assert(host.statistics.total_polls == 6 && host.statistics.failed_polls == 3 && host.statistics.availability == 50);
	assert(host.statistics.cur_time == 4 && host.statistics.avg_time == 6 && host.statistics.min_time == 4 && host.statistics.max_time == 8);
	const int methods[] = {AVAIL_NONE, AVAIL_SNMP, AVAIL_PING, AVAIL_SNMP_AND_PING, AVAIL_SNMP_OR_PING};
	const double expected[] = {0, 8, 4, 6, 4};
	for (size_t index = 0; index < sizeof(methods) / sizeof(methods[0]); index++) {
		host_t sample = {0};
		sample.statistics.min_time = 1000;
		sample.snmp.profile.version = 3; /* v3 needs no community. */
		update_host_status(HOST_UP, &sample, &ping, methods[index]);
		assert(sample.state.status == HOST_UP && sample.statistics.cur_time == expected[index] && sample.statistics.avg_time == expected[index]);
	}
	host_t no_snmp = {0};
	no_snmp.snmp.profile.version = 2;
	update_host_status(HOST_UP, &no_snmp, &ping, AVAIL_SNMP);
	assert(no_snmp.statistics.cur_time == 0);
	update_host_status(HOST_DOWN, &no_snmp, &ping, AVAIL_SNMP);
	assert(strcmp(no_snmp.state.status_last_error, "Device does not require SNMP") == 0);
	/* Public transition/output matrix, including devices that do not require
	 * SNMP. A failed poll never contributes a response-time sample. */
	set.logging.log_level = POLLER_VERBOSITY_HIGH;
	set.logging.log_destination = LOGDEST_STDOUT;
	const int states[] = {HOST_UNKNOWN, HOST_UP, HOST_DOWN, HOST_RECOVERING};
	for (int threshold = 1; threshold <= 2; threshold++) {
		set.availability.ping_failure_count = threshold;
		set.availability.ping_recovery_count = threshold;
		for (size_t method = 0; method < sizeof(methods) / sizeof(methods[0]); method++) {
			for (size_t state = 0; state < sizeof(states) / sizeof(states[0]); state++) {
				for (int snmp = 0; snmp <= 1; snmp++) {
					for (int up = 0; up <= 1; up++) {
						host_t sample = {0};
						int expected_status;
						double expected_time = expected[method];

						sample.state.status = states[state];
						sample.snmp.profile.version = snmp ? 3 : 2;
						sample.statistics.min_time = 1000;
						if (!snmp && methods[method] == AVAIL_SNMP) expected_time = 0;
						if (!snmp && methods[method] == AVAIL_SNMP_AND_PING) expected_time = 4;
						update_host_status(up ? HOST_UP : HOST_DOWN, &sample, &ping, methods[method]);
						if (up) {
							expected_status = threshold == 2 && (states[state] == HOST_DOWN || states[state] == HOST_RECOVERING) ? HOST_RECOVERING : HOST_UP;
							assert(sample.statistics.failed_polls == 0 && sample.statistics.availability == 100);
							assert(sample.statistics.cur_time == expected_time && sample.statistics.avg_time == expected_time);
							assert(sample.statistics.min_time == expected_time && sample.statistics.max_time == expected_time);
						} else {
							expected_status = states[state] == HOST_UP && threshold == 2 ? HOST_UP : HOST_DOWN;
							assert(sample.statistics.failed_polls == 1 && sample.statistics.availability == 0);
							assert(sample.statistics.cur_time == 0 && sample.statistics.avg_time == 0);
							if (methods[method] == AVAIL_SNMP) {
								assert(strcmp(sample.state.status_last_error, snmp ? "SNMP unavailable" : "Device does not require SNMP") == 0);
							} else {
								const char *message = snmp && (methods[method] == AVAIL_SNMP_AND_PING || methods[method] == AVAIL_SNMP_OR_PING) ? "SNMP unavailable, network unavailable" : "network unavailable";
								assert(strcmp(sample.state.status_last_error, message) == 0);
							}
						}
						assert(sample.statistics.total_polls == 1 && sample.state.status == expected_status);
					}
				}
			}
		}
	}
	set = previous;
}

static void test_availability_modes(void) {
	host_t host = {0};
	ping_t ping = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	STRNCOPY(host.snmp.profile.community, "regression");
	host.snmp.profile.version = 2;
	host.availability.ping_method = PING_TCP;
	host.availability.port = -1;
	host.availability.timeout = 100;
	/* A failed network check must fall back to SNMP in OR mode. */
	host.availability.method = AVAIL_SNMP_OR_PING;
	assert(ping_host(&host, &ping) == HOST_DOWN);
	assert(strcmp(ping.snmp_response, "Invalid SNMP Session") == 0);
	STRNCOPY(ping.snmp_response, "untouched");
	host.availability.method = AVAIL_SNMP_AND_PING;
	assert(ping_host(&host, &ping) == HOST_DOWN);
	assert(strcmp(ping.snmp_response, "untouched") == 0);
	/* Preserve the existing localhost exemption, and OR short circuit. */
	STRNCOPY(host.hostname, "localhost");
	host.availability.method = AVAIL_SNMP_OR_PING;
	assert(ping_host(&host, &ping) == HOST_UP);
	assert(strcmp(ping.snmp_response, "untouched") == 0);
	host.availability.method = AVAIL_SNMP_AND_PING;
	assert(ping_host(&host, &ping) == HOST_DOWN);
	assert(strcmp(ping.snmp_response, "Invalid SNMP Session") == 0);
	host.availability.method = AVAIL_NONE;
	assert(ping_host(&host, &ping) == HOST_UP);
	host.availability.method = AVAIL_PING;
	assert(ping_host(&host, &ping) == HOST_UP);
	host.availability.method = AVAIL_STREAM;
	assert(ping_host(&host, &ping) == HOST_DOWN);
	host.availability.method = AVAIL_SNMP;
	host.snmp.profile.community[0] = '\0';
	assert(ping_host(&host, &ping) == HOST_UP);
	host.snmp.profile.version = 3;
	assert(ping_host(&host, &ping) == HOST_DOWN);
}

static void test_tcp_loopback(void) {
	int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(server >= 0);
	struct sockaddr_in address = {0};
	assert(init_sockaddr(&address, "127.0.0.1", 0));
	assert(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0);
	socklen_t length = sizeof(address);
	assert(getsockname(server, (struct sockaddr *) &address, &length) == 0);
	host_t host = {0};
	STRNCOPY(host.hostname, "127.0.0.1");
	host.availability.port = ntohs(address.sin_port);
	host.availability.timeout = 100;
	host.availability.retries = 0;
	host.availability.ping_method = PING_TCP;
	ping_t ping = {0};
	/* Close the reservation so both Darwin and Linux return a refusal. */
	assert(close(server) == 0);
	assert(ping_tcp(&host, &ping) == HOST_DOWN);
	host.availability.ping_method = PING_TCP_CLOSED;
	assert(ping_tcp(&host, &ping) == HOST_UP);
	assert(strcmp(ping.ping_response, "TCP: Device is Alive") == 0);
	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(server >= 0);
	address.sin_port = 0;
	assert(bind(server, (struct sockaddr *) &address, sizeof(address)) == 0);
	assert(getsockname(server, (struct sockaddr *) &address, &length) == 0);
	host.availability.port = ntohs(address.sin_port);
	assert(listen(server, 1) == 0);
	host.availability.ping_method = PING_TCP;
	assert(ping_tcp(&host, &ping) == HOST_UP);
	int client = accept(server, NULL, NULL);
	assert(client >= 0);
	char byte;
	assert(read(client, &byte, 1) == 0);
	assert(close(client) == 0 && close(server) == 0);
	host.availability.timeout = 0;
	assert(ping_tcp(&host, &ping) == HOST_DOWN);
}

static void test_error_id_buffer_boundaries(void) {
	config_t previous = set;
	set.logging.log_destination = 0;
	set.logging.log_level = POLLER_VERBOSITY_NONE;
	char storage[DBL_BUFSIZE + 1] = {0};
	storage[DBL_BUFSIZE] = 'G';
	int size = 0;
	int count = 0;
	buffer_output_errors(storage, &size, &count, 1, 1, INT_MIN, FALSE);
	buffer_output_errors(storage, &size, &count, 1, 1, 0, FALSE);
	buffer_output_errors(storage, &size, &count, 1, 1, INT_MAX, FALSE);
	assert(strcmp(storage, "-2147483648, 0, 2147483647") == 0);
	assert(count == 3 && size == (int) strlen(storage));
	assert(strpbrk(storage, "\r\n") == NULL && storage[DBL_BUFSIZE] == 'G');
	/* Fill the caller-owned numeric list to its real boundary, then verify
	 * overflow starts a fresh record rather than overrunning storage. */
	memset(storage, '7', DBL_BUFSIZE - 2);
	storage[DBL_BUFSIZE - 2] = '\0';
	size = DBL_BUFSIZE - 2;
	count = 1;
	buffer_output_errors(storage, &size, &count, 1, 1, INT_MAX, FALSE);
	assert(strcmp(storage, "2147483647") == 0 && size == 10 && count == 1);
	assert(storage[DBL_BUFSIZE] == 'G');
	buffer_output_errors(storage, &size, &count, 1, 1, 0, TRUE);
	assert(strcmp(storage, "2147483647") == 0 && size == 10 && count == 1);
	set = previous;
	puts("production numeric error-list boundary regressions passed");
}


int main(int argc, char **argv) {
	if (argc == 2 && strcmp(argv[1], "--database-tls") == 0) {
		init_mutexes();
		test_database_tls_contracts();
		return 0;
	}
	if (argc == 3 && strcmp(argv[1], "--script-stream") == 0) return run_script_stream_fixture(argv[2]);
	if (argc > 1 && strcmp(argv[1], "-q") == 0) return run_test_script_server(argc, argv);
	extern int *debug_devices;
	static int devices[100];
	debug_devices = devices;
	if (argc == 2 && strcmp(argv[1], "--raw-icmp") == 0) {
		init_mutexes();
		test_icmp_loopback();
		puts("production ICMP loopback regression passed");
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--script-limits") == 0) {
		init_mutexes();
		run_script_limit_contracts();
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--privilege-drop") == 0) {
		test_privilege_contracts();
		return 0;
	}
	if (argc == 3 && strcmp(argv[1], "--setuid-stress") == 0) {
		test_setuid_stress(atoi(argv[2]));
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--setuid-icmp") == 0) {
		test_setuid_icmp();
		puts("production setuid ICMP regression passed");
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--icmp-no-capability") == 0) {
		init_mutexes();
		test_icmp_socket_failure();
		puts("production ICMP socket-failure regression passed");
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--snmpv3-agent") == 0) {
		init_mutexes();
		test_snmpv3_agent_contracts();
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--snmp-agent") == 0) {
		init_mutexes();
		test_snmp_agent();
		puts("production SNMP agent regressions passed");
		return 0;
	}
	if (argc == 2 && strcmp(argv[1], "--database") == 0) {
		init_mutexes();
		test_database_configuration();
		puts("production database configuration regressions passed");
		return 0;
	}
	test_string_conversions();
	test_result_count_range();
	test_cli_option_shape();
	test_concurrent_permits();
	test_copy_bounds();
	test_database_escape();
	test_database_addresses();
	test_database_option_failure();
	test_regex_concurrency();
	test_regex_storage();
	test_formatting();
	test_secret_clear();
	test_log_boundary();
	test_log_sanitization();
	test_log_append_and_failures();
	test_config_directives();
	test_config_unknown_lines_not_echoed();
	test_config_structure_bindings();
	test_date_formats();
	test_device_logging();
	test_debug_device_bounds();
	test_poll_result_formats();
	test_hostnames();
	test_udp_deadline();
	test_tcp_loopback();
	test_availability_modes();
	test_icmp_reply_bounds();
	test_snmp_initialization_failure();
	test_snmp_security_protocols();
	test_child_process();
	alarm(10);
	test_duplex_process();
	test_write_process();
	test_process_descriptor_aliases();
	alarm(0);
	test_php_response(4, true);
	test_php_response(RESULTS_BUFFER - 1, true);
	test_php_response(RESULTS_BUFFER, false);
	test_php_partial_response_timeout();
	init_mutexes();
	test_php_command(4);
	test_php_command(BUFSIZE - 3);
	test_invalid_php_commands();
	test_php_failure_logs_omit_command();
	test_php_startup(argv[0]);
	test_php_owned_shutdown();
	test_host_status_transitions();
	test_script_execution();
	run_script_limit_contracts();
	test_script_timeout_kills_descendants();
	test_pclose_kills_descendants();
	test_script_stream_contracts();
	test_cli_alias_contracts();
	test_privilege_contracts();
	test_error_id_buffer_boundaries();
	test_additional_contracts();
	puts("production regression tests passed");
	return 0;
}
