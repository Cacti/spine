/* Production-linked PHP Script Server runtime tests.
 *
 * These use a real child, real close-on-exec pipes and the shipped php.c.
 * They deliberately avoid a Cacti/PHP installation while covering the hot
 * init -> command -> response -> close lifecycle and deterministic failures.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "spine.h"
#include "php.h"

static int php_setup(void **state) {
	int i;

	(void) state;
	memset(&set, 0, sizeof(set));
	init_mutexes();
	signal(SIGPIPE, SIG_IGN);

	php_processes = calloc(MAX_PHP_SERVERS, sizeof(*php_processes));
	assert_non_null(php_processes);
	for (i = 0; i < MAX_PHP_SERVERS; i++) {
		php_processes[i].php_pid = -1;
		php_processes[i].php_read_fd = -1;
		php_processes[i].php_write_fd = -1;
	}

	set.php_servers = 2;
	set.script_timeout = 1;
	set.cacti_version = 1300;
	set.poller_id = 1;
	set.log_destination = LOGDEST_STDOUT;
	snprintf(set.path_php, sizeof(set.path_php), "%s", PHP_TEST_SERVER_PATH);
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "normal");
	return 0;
}

static int php_teardown(void **state) {
	int i;

	(void) state;
	if (php_processes != NULL) {
		for (i = 0; i < MAX_PHP_SERVERS; i++) {
			if (php_processes[i].php_pid > 1 ||
			    php_processes[i].php_read_fd >= 0 ||
			    php_processes[i].php_write_fd >= 0) {
				php_close(i);
			}
		}
		free(php_processes);
		php_processes = NULL;
	}
	return 0;
}

static void test_round_robin_wraps_at_server_count(void **state) {
	(void) state;
	set.php_current_server = set.php_servers;
	assert_int_equal(php_get_process(), 0);
	assert_int_equal(php_get_process(), 1);
	assert_int_equal(php_get_process(), 0);
}

static void test_full_script_server_lifecycle(void **state) {
	char *result;

	(void) state;
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_READY);
	assert_true(php_processes[0].php_pid > 1);
	assert_true(php_processes[0].php_read_fd >= 0);
	assert_true(php_processes[0].php_write_fd >= 0);

	result = php_cmd("poll 7", 0);
	assert_non_null(result);
	assert_string_equal(result, "42\n");
	free(result);

	php_close(0);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
}

static void test_init_marks_an_unexpected_handshake_busy(void **state) {
	(void) state;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "bad-start");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_init_timeout_does_not_recurse(void **state) {
	(void) state;
	set.script_timeout = 0;
	snprintf(set.path_php_server, sizeof(set.path_php_server), "%s", "silent");
	assert_int_equal(php_init(0), TRUE);
	assert_int_equal(php_processes[0].php_state, PHP_BUSY);
}

static void test_spawn_failure_releases_every_resource(void **state) {
	(void) state;
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");
	assert_int_equal(php_init(0), FALSE);
	assert_int_equal(php_processes[0].php_pid, -1);
	assert_int_equal(php_processes[0].php_read_fd, -1);
	assert_int_equal(php_processes[0].php_write_fd, -1);
}

static void test_readpipe_rejects_fd_at_fd_setsize(void **state) {
	char command[] = "test";
	char *result;

	(void) state;
	php_processes[0].php_read_fd = FD_SETSIZE;
	result = php_readpipe(0, command);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	php_processes[0].php_read_fd = -1;
}

static void test_readpipe_rejects_an_oversized_response(void **state) {
	char payload[RESULTS_BUFFER];
	char command[] = "test";
	char *result;
	int pdes[2];

	(void) state;
	memset(payload, 'x', sizeof(payload));
	assert_int_equal(pipe(pdes), 0);
	assert_int_equal(write(pdes[1], payload, sizeof(payload)), (ssize_t)sizeof(payload));
	close(pdes[1]);
	php_processes[0].php_read_fd = pdes[0];

	result = php_readpipe(0, command);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
	close(pdes[0]);
	php_processes[0].php_read_fd = -1;
}

static void test_command_gives_up_after_three_failed_writes(void **state) {
	char *result;
	int pdes[2];

	(void) state;
	assert_int_equal(pipe(pdes), 0);
	close(pdes[0]);
	php_processes[0].php_write_fd = pdes[1];
	snprintf(set.path_php, sizeof(set.path_php), "%s", "/does/not/exist/spine-php-test");

	result = php_cmd("poll 9", 0);
	assert_non_null(result);
	assert_string_equal(result, "U");
	free(result);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_round_robin_wraps_at_server_count, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_full_script_server_lifecycle, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_init_marks_an_unexpected_handshake_busy, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_init_timeout_does_not_recurse, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_spawn_failure_releases_every_resource, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_readpipe_rejects_fd_at_fd_setsize, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_readpipe_rejects_an_oversized_response, php_setup, php_teardown),
		cmocka_unit_test_setup_teardown(test_command_gives_up_after_three_failed_writes, php_setup, php_teardown),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
