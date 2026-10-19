/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

/* spine_log() stack use and the spine.conf tokenizer.
 *
 * Poller threads run on the platform's default stack: 128 KiB on musl,
 * 512 KiB on macOS.  The logging cases run on a thread of the musl size in a
 * child process, so an overflow is a reported failure rather than a crash of
 * the runner.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "internal/common.h"
#include "app/spine.h"
#include "tests/support/child_run.h"

#define MUSL_DEFAULT_STACK (128 * 1024)

static char log_path[] = "spine-log-stack-XXXXXX";

static void *log_from_thread(void *argument) {
	char *message;

	(void) argument;
	message = malloc(LOGSIZE);
	if (message == NULL) return argument;
	memset(message, 'x', LOGSIZE - 1);
	message[LOGSIZE - 1] = '\0';

	set.logging.log_destination = LOGDEST_FILE;
	spine_log("stack check %s", message);
	set.logging.log_destination = LOGDEST_STDOUT;
	spine_log("stack check %s", message);

	free(message);
	return NULL;
}

static void test_spine_log_fits_a_musl_thread_stack(void **state) {
	pid_t child;
	int status;
	int fd;

	(void) state;
	fd = mkstemp(log_path);
	assert_true(fd >= 0);
	assert_int_equal(close(fd), 0);

	fflush(NULL);
	child = fork();
	assert_true(child >= 0);

	if (child == 0) {
		pthread_attr_t attr;
		pthread_t thread;
		void *result = &status;

		/* cmocka traps SIGSEGV; let an overflow kill the child visibly */
		signal(SIGSEGV, SIG_DFL);
		signal(SIGBUS, SIG_DFL);
		if (freopen("/dev/null", "w", stdout) == NULL) _exit(3);
		memset(&set, 0, sizeof(set));
		config_defaults();
		set.logging.log_level         = POLLER_VERBOSITY_LOW;
		set.logging.logfile_processed = TRUE;
		set.console.stdout_notty      = FALSE;
		set.console.stderr_notty      = TRUE;
		STRNCOPY(set.logging.path_logfile, log_path);

		if (pthread_attr_init(&attr) != 0) _exit(4);
		if (pthread_attr_setstacksize(&attr, MUSL_DEFAULT_STACK) != 0) _exit(5);
		if (pthread_create(&thread, &attr, log_from_thread, NULL) != 0) _exit(6);
		if (pthread_join(thread, &result) != 0 || result != NULL) _exit(7);
		_exit(0);
	}

	assert_int_equal(waitpid(child, &status, 0), child);
	unlink(log_path);
	if (!WIFEXITED(status)) {
		fail_msg("spine_log() killed a 128 KiB thread with signal %d", WTERMSIG(status));
	}
	assert_int_equal(WEXITSTATUS(status), 0);
}

static void test_new_log_permissions(void **state) {
	char directory[] = "spine-log-mode-XXXXXX";
	char path[128];
	struct stat info;
	mode_t previous_umask;
	int result;

	(void) state;
	assert_non_null(mkdtemp(directory));
	snprintf(path, sizeof(path), "%s/poller.log", directory);
	memset(&set, 0, sizeof(set));
	config_defaults();
	set.logging.log_destination = LOGDEST_FILE;
	set.logging.logfile_processed = TRUE;
	set.console.stdout_notty = FALSE;
	set.console.stderr_notty = TRUE;
	STRNCOPY(set.logging.path_logfile, path);
	previous_umask = umask(0); /* NOSONAR: the test needs umask 0 to show the 0640 mode comes from spine */
	spine_log("permission check");
	umask(previous_umask);
	result = stat(path, &info);
	unlink(path);
	rmdir(directory);
	assert_int_equal(result, 0);
	assert_int_equal(info.st_mode & 0777, 0640);
}

/* --- spine.conf parsing -------------------------------------------------- */

static char config_path[64];

static void write_config(const char *contents) {
	FILE *fp;
	int fd;

	strcpy(config_path, "spine-conf-test-XXXXXX");
	fd = mkstemp(config_path);
	assert_true(fd >= 0);
	fp = fdopen(fd, "w");
	assert_non_null(fp);
	assert_true(fputs(contents, fp) != EOF);
	assert_int_equal(fclose(fp), 0);
}

static int config_setup(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	config_defaults();
	set.console.stdout_notty = TRUE;
	set.console.stderr_notty = TRUE;
	config_path[0] = '\0';
	return 0;
}

static int config_teardown(void **state) {
	(void) state;
	if (config_path[0] != '\0') unlink(config_path);
	return 0;
}

/* sscanf("%15s") cut a long key short and handed its tail over as the value,
 * so a misspelt key could set a real one. */
static void test_config_long_key_is_not_truncated_into_a_known_key(void **state) {
	(void) state;
	write_config("SNMP_ClientaddrX 10.9.9.9\nDB_Port 3311\n");
	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.snmp.snmp_clientaddr, "");
	assert_int_equal(set.database.port, 3311);
}

static void test_config_every_known_key_is_accepted(void **state) {
	static const char *const keys[] = {
		"RDB_Host", "RDB_Database", "RDB_User", "RDB_Pass", "RDB_SSL_Key",
		"RDB_SSL_Cert", "RDB_SSL_CA", "DB_Host", "DB_Database", "DB_User",
		"DB_Pass", "DB_SSL_Key", "DB_SSL_Cert", "DB_SSL_CA", "SNMP_Clientaddr",
		"RDB_Port", "RDB_UseSSL", "DB_Port", "DB_UseSSL", "Poller", "Cacti_Log",
	};
	char contents[2048];
	char *cursor = contents;
	size_t remaining = sizeof(contents);
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		assert_true(spine_appendf(&cursor, &remaining, "%s 1\n", keys[i]));
	}
	write_config(contents);
	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.snmp.snmp_clientaddr, "1");
	assert_string_equal(set.remote_database.ssl_ca, "1");
	assert_int_equal(set.remote_database.ssl, 1);
	assert_int_equal(set.poller.poller_id, 1);
}

/* %255s cut a long certificate path, and the shortened path was used. */
static void test_config_long_value_is_kept_whole(void **state) {
	char contents[BUFSIZE];
	char path[700];

	(void) state;
	memset(path, 'p', sizeof(path) - 1);
	path[0] = '/';
	path[sizeof(path) - 1] = '\0';
	snprintf(contents, sizeof(contents), "DB_SSL_CA %s\n", path);
	write_config(contents);
	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.database.ssl_ca, path);
}

/* A line longer than the read buffer came back from fgets() in pieces, and
 * the tail was parsed as a directive of its own. */
static void test_config_overlong_line_is_ignored_whole(void **state) {
	char *contents;
	size_t used;

	(void) state;
	contents = malloc(4 * BUFSIZE);
	assert_non_null(contents);
	strcpy(contents, "# ");
	used = strlen(contents);
	memset(contents + used, 'c', BUFSIZE - 1 - used);
	used = BUFSIZE - 1;
	strcpy(contents + used, "DB_Host injected\nDB_Port 3312\n");
	write_config(contents);
	free(contents);

	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.database.host, DEFAULT_DB_HOST);
	assert_int_equal(set.database.port, 3312);
}

static void test_config_line_filling_the_buffer_exactly_is_read(void **state) {
	char contents[2 * BUFSIZE];
	char value[BUFSIZE];
	size_t length;

	(void) state;
	/* "DB_User " plus the value is BUFSIZE - 1 characters before the newline */
	length = BUFSIZE - 1 - strlen("DB_User ");
	memset(value, 'u', length);
	value[length] = '\0';
	snprintf(contents, sizeof(contents), "DB_User %s\nDB_Port 3313\n", value);
	write_config(contents);
	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.database.user, value);
	assert_int_equal(set.database.port, 3313);
}

/* strchr() stopped at the NUL, so the line looked unfinished and the next
 * one was thrown away as its remainder. */
static void test_config_embedded_nul_does_not_swallow_the_next_line(void **state) {
	static const char contents[] = "DB_Host a\0junk\nDB_Port 3307\n";
	FILE *fp;
	int fd;

	(void) state;
	strcpy(config_path, "spine-conf-test-XXXXXX");
	fd = mkstemp(config_path);
	assert_true(fd >= 0);
	fp = fdopen(fd, "w");
	assert_non_null(fp);
	assert_int_equal(fwrite(contents, 1, sizeof(contents) - 1, fp), sizeof(contents) - 1);
	assert_int_equal(fclose(fp), 0);

	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.database.host, "a");
	assert_int_equal(set.database.port, 3307);
}

static void test_config_last_line_without_newline_is_read(void **state) {
	(void) state;
	write_config("DB_Host first\nDB_Port 3399");
	assert_int_equal(read_spine_config(config_path), 0);
	assert_string_equal(set.database.host, "first");
	assert_int_equal(set.database.port, 3399);
}

static void test_json_record_escaping_and_capacity(void **state) {
	static const char expected[] = "{\"timestamp\":\"now\",\"severity\":\"INFO\",\"message\":\"quote\\\" slash\\\\ newline\\u000a tab\\u0009\\u007f\"}\n";
	char output[1024];
	size_t capacity;

	(void) state;
	assert_true(spine_json_log_record(output, sizeof(output), "now", "INFO", "quote\" slash\\ newline\n tab\t\177"));
	assert_string_equal(output, expected);
	for (capacity = 1; capacity <= strlen(expected); capacity++) {
		memset(output, 0xa5, sizeof(output));
		assert_false(spine_json_log_record(output, capacity, "now", "INFO", "quote\" slash\\ newline\n tab\t\177"));
		assert_string_equal(output, "");
		assert_int_equal((unsigned char) output[capacity], 0xa5);
	}
	assert_true(spine_json_log_record(output, strlen(expected) + 1, "now", "INFO", "quote\" slash\\ newline\n tab\t\177"));
	assert_false(spine_json_log_record(NULL, sizeof(output), "now", "INFO", "x"));
	assert_false(spine_json_log_record(output, 0, "now", "INFO", "x"));
	assert_false(spine_json_log_record(output, sizeof(output), NULL, "INFO", "x"));
	assert_false(spine_json_log_record(output, sizeof(output), "now", NULL, "x"));
	assert_false(spine_json_log_record(output, sizeof(output), "now", "INFO", NULL));
}

static void test_json_record_utf8_contract(void **state) {
	static const char *const valid[] = {"", "ascii", "\xc2\x80", "\xdf\xbf", "\xe0\xa0\x80",
		"\xed\x9f\xbf", "\xef\xbf\xbf", "\xf0\x90\x80\x80", "\xf4\x8f\xbf\xbf"};
	static const char *const invalid[] = {"\x80", "\xbf", "\xc0\xaf", "\xc1\xbf", "\xf5\x80\x80\x80",
		"\xc2", "\xe1\x80", "\xf1\x80\x80", "\xe0\x9f\xbf", "\xed\xa0\x80", "\xf0\x8f\xbf\xbf",
		"\xf4\x90\x80\x80", "\xe1\x41\x80", "\xe1\xc0\x80", "\xe1\x80\x41"};
	char output[512];
	size_t index;

	(void) state;
	for (index = 0; index < sizeof(valid) / sizeof(valid[0]); index++) {
		assert_true(spine_json_log_record(output, sizeof(output), "now", "INFO", valid[index]));
		assert_non_null(strstr(output, valid[index]));
	}
	for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
		/* every byte that begins no valid sequence becomes U+FFFD */
		assert_true(spine_json_log_record(output, sizeof(output), "now", "INFO", invalid[index]));
		assert_non_null(strstr(output, "\xef\xbf\xbd"));
	}
}

static void test_json_log_file_and_config(void **state) {
	char path[] = "spine-json-log-XXXXXX";
	char line[1024];
	FILE *file;
	int fd;

	(void) state;
	fd = mkstemp(path);
	assert_true(fd >= 0);
	assert_int_equal(close(fd), 0);
	write_config("Log_Format json\n");
	assert_int_equal(read_spine_config(config_path), 0);
	assert_true(set.logging.json_logs);
	STRNCOPY(set.logging.path_logfile, path);
	set.logging.logfile_processed = TRUE;
	set.logging.log_level = POLLER_VERBOSITY_LOW;
	assert_true(spine_log("WARNING: Device[7] quote\" slash\\ value\nnext"));
	assert_true(spine_log("bad UTF-8: %s", "\xff"));
	file = fopen(path, "r");
	assert_non_null(file);
	assert_non_null(fgets(line, sizeof(line), file));
	assert_non_null(strstr(line, "\"severity\":\"WARNING\""));
	assert_non_null(strstr(line, "quote\\\" slash\\\\ value\\u000anext"));
	assert_non_null(fgets(line, sizeof(line), file));
	assert_non_null(strstr(line, "\"severity\":\"INFO\""));
	assert_non_null(strstr(line, "bad UTF-8: \xef\xbf\xbd"));
	assert_null(strstr(line, "\xff"));
	assert_null(fgets(line, sizeof(line), file));
	assert_int_equal(fclose(file), 0);
	unlink(path);
	unlink(config_path);
	write_config("Log_Format text\n");
	assert_int_equal(read_spine_config(config_path), 0);
	assert_false(set.logging.json_logs);
}

static void test_json_stdout_is_a_single_record(void **state) {
	int descriptors[2];
	pid_t child;
	int status;
	char output[1024];
	ssize_t received;

	(void) state;
	assert_int_equal(pipe(descriptors), 0);
	fflush(NULL);
	child = fork();
	assert_true(child >= 0);
	if (child == 0) {
		close(descriptors[0]);
		assert_int_equal(dup2(descriptors[1], STDOUT_FILENO), STDOUT_FILENO);
		close(descriptors[1]);
		set.logging.json_logs = TRUE;
		set.logging.log_destination = LOGDEST_STDOUT;
		if (!spine_log("ERROR: quote\" newline\n")) _exit(1);
		fflush(stdout);
		_exit(0);
	}
	close(descriptors[1]);
	received = read(descriptors[0], output, sizeof(output) - 1);
	assert_true(received > 0);
	output[received] = '\0';
	close(descriptors[0]);
	assert_int_equal(waitpid(child, &status, 0), child);
	assert_true(WIFEXITED(status));
	assert_int_equal(WEXITSTATUS(status), 0);
	assert_true(output[0] == '{');
	assert_non_null(strstr(output, "\"severity\":\"ERROR\""));
	assert_non_null(strstr(output, "quote\\\" newline\\u000a"));
	assert_ptr_equal(strchr(output, '\n'), output + received - 1);
}

static void test_invalid_log_format_is_refused(void **state) {
	pid_t child;
	int status;

	(void) state;
	write_config("Log_Format unknown\n");
	fflush(NULL);
	child = fork();
	assert_true(child >= 0);
	if (child == 0) {
		read_spine_config(config_path);
		_exit(0);
	}
	assert_int_equal(waitpid(child, &status, 0), child);
	assert_true(WIFEXITED(status));
	assert_int_not_equal(WEXITSTATUS(status), 0);
}

static void test_local_and_remote_tls_configuration(void **state) {
	(void) state;
	write_config("DB_SSL_Mode required\nDB_SSL_MinVersion TLSv1.2\n"
				 "DB_SSL_Cipher ECDHE-RSA-AES128-GCM-SHA256\n"
				 "RDB_SSL_Mode verify-full\nRDB_SSL_MinVersion TLSv1.3\n"
				 "RDB_SSL_CA /fixture/ca.pem\nRDB_SSL_Ciphersuites TLS_AES_128_GCM_SHA256\n");
	assert_int_equal(read_spine_config(config_path), 0);
	assert_int_equal(set.database.tls_mode, SPINE_TLS_REQUIRED);
	assert_int_equal(set.database.tls_min_version, 12);
	assert_string_equal(set.database.tls_cipher, "ECDHE-RSA-AES128-GCM-SHA256");
	assert_string_equal(set.database.tls_ciphersuites, "");
	assert_int_equal(set.remote_database.tls_mode, SPINE_TLS_VERIFY_FULL);
	assert_int_equal(set.remote_database.tls_min_version, 13);
	assert_string_equal(set.remote_database.tls_cipher, "");
	assert_string_equal(set.remote_database.ssl_ca, "/fixture/ca.pem");
	assert_string_equal(set.remote_database.tls_ciphersuites, "TLS_AES_128_GCM_SHA256");
	config_defaults();
	assert_int_equal(set.database.tls_mode, SPINE_TLS_LEGACY);
	assert_int_equal(set.remote_database.tls_min_version, 0);
	assert_string_equal(set.database.tls_cipher, "");
}

static void test_invalid_tls_configuration_is_refused(void **state) {
	const char *invalid[] = {"DB_SSL_Mode pretend\n", "RDB_SSL_MinVersion TLSv1.0\n"};
	size_t index;
	(void) state;
	for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++) {
		pid_t child;
		int status;
		write_config(invalid[index]);
		fflush(NULL);
		child = fork();
		assert_true(child >= 0);
		if (child == 0) {
			read_spine_config(config_path);
			_exit(0);
		}
		assert_int_equal(waitpid(child, &status, 0), child);
		assert_true(WIFEXITED(status));
		assert_int_not_equal(WEXITSTATUS(status), 0);
		assert_int_equal(unlink(config_path), 0);
		config_path[0] = '\0';
	}
}

/* On a terminal the reader explains what it skipped: a retired directive, an
 * unreadable file at debug level and a line that did not fit the buffer. */
static void test_config_warnings_reach_a_terminal(void **state) {
	char capture_path[] = "spine-conf-stderr-XXXXXX";
	char output[1024] = "";
	char *long_line;
	int saved_stderr;
	int capture;
	ssize_t length;

	(void) state;
	capture = mkstemp(capture_path);
	assert_true(capture >= 0);
	saved_stderr = dup(STDERR_FILENO);
	assert_true(saved_stderr >= 0);
	fflush(stderr);
	assert_true(dup2(capture, STDERR_FILENO) >= 0);
	set.console.stderr_notty = FALSE;
	set.logging.log_level = POLLER_VERBOSITY_DEBUG;

	write_config("DB_PreG 1\n");
	assert_int_equal(read_spine_config(config_path), 0);
	unlink(config_path);

	long_line = malloc(2 * BUFSIZE);
	assert_non_null(long_line);
	memset(long_line, 'c', 2 * BUFSIZE - 2);
	long_line[2 * BUFSIZE - 2] = '\n';
	long_line[2 * BUFSIZE - 1] = '\0';
	write_config(long_line);
	free(long_line);
	assert_int_equal(read_spine_config(config_path), 0);

	assert_int_equal(read_spine_config("spine-conf-does-not-exist"), -1);

	fflush(stderr);
	assert_true(dup2(saved_stderr, STDERR_FILENO) >= 0);
	close(saved_stderr);
	assert_true(lseek(capture, 0, SEEK_SET) == 0);
	length = read(capture, output, sizeof(output) - 1);
	assert_true(length > 0);
	close(capture);
	unlink(capture_path);

	assert_non_null(strstr(output, "DB_PreG is no longer supported"));
	assert_non_null(strstr(output, "Ignoring line 1 of"));
	assert_non_null(strstr(output, "Could not open config file [spine-conf-does-not-exist]"));
}

static void die_with_an_errno_description(void) {
	set.logging.log_perror = TRUE;
	set.logging.log_destination = LOGDEST_STDOUT;
	errno = ENOENT;
	die("ERROR: scripted failure");
}

static void die_from_the_parent_with_a_script_server(void) {
	set.poller.parent_fork = SPINE_PARENT;
	set.php.php_initialized = TRUE;
	die("ERROR: scripted failure");
}

static void test_fatal_errors_report_errno_and_close_the_script_server(void **state) {
	(void) state;
	assert_int_equal(spine_test_run_child(die_with_an_errno_description), EXIT_FAILURE);
	assert_int_equal(spine_test_run_child(die_from_the_parent_with_a_script_server), EXIT_FAILURE);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_local_and_remote_tls_configuration, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_invalid_tls_configuration_is_refused, config_setup, config_teardown),
		cmocka_unit_test(test_spine_log_fits_a_musl_thread_stack),
		cmocka_unit_test(test_new_log_permissions),
		cmocka_unit_test(test_json_record_escaping_and_capacity),
		cmocka_unit_test(test_json_record_utf8_contract),
		cmocka_unit_test_setup_teardown(test_json_stdout_is_a_single_record, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_json_log_file_and_config, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_invalid_log_format_is_refused, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_long_key_is_not_truncated_into_a_known_key, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_every_known_key_is_accepted, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_long_value_is_kept_whole, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_overlong_line_is_ignored_whole, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_line_filling_the_buffer_exactly_is_read, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_embedded_nul_does_not_swallow_the_next_line, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_last_line_without_newline_is_read, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_warnings_reach_a_terminal, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_fatal_errors_report_errno_and_close_the_script_server, config_setup, config_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
