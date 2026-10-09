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
	previous_umask = umask(0);
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
	size_t used = 0;
	size_t i;

	(void) state;
	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		used += (size_t) snprintf(contents + used, sizeof(contents) - used, "%s 1\n", keys[i]);
		assert_true(used < sizeof(contents));
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

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_spine_log_fits_a_musl_thread_stack),
		cmocka_unit_test(test_new_log_permissions),
		cmocka_unit_test_setup_teardown(test_config_long_key_is_not_truncated_into_a_known_key, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_every_known_key_is_accepted, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_long_value_is_kept_whole, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_overlong_line_is_ignored_whole, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_line_filling_the_buffer_exactly_is_read, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_embedded_nul_does_not_swallow_the_next_line, config_setup, config_teardown),
		cmocka_unit_test_setup_teardown(test_config_last_line_without_newline_is_read, config_setup, config_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
