/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#include "internal/common.h"
#include "app/spine.h"
#include "app/startup_internal.h"
#include "tests/support/child_run.h"
#include <fcntl.h>

#define SCRIPT_SERVER "./tests/support/php_test_server"

/* Device 0 data sources and the output_regex column change how the poller
 * selects and stores work, so startup has to notice both. */
static void test_startup_database_detection(MYSQL *mysql) {
	MYSQL local;
	MYSQL remote;
	pool_t *previous_pool = db_pool_local;
	config_t previous = set;
	int mode;

	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item (local_data_id,host_id,poller_id,action) VALUES (951,0,1,1)"));
	assert(db_insert(mysql, LOCAL, "ALTER TABLE poller_item ADD COLUMN output_regex varchar(255) NOT NULL DEFAULT ''"));
	set.poller.threads = 1;
	set.poller.poller_id = 1;
	set.poller.mode = REMOTE_OFFLINE;
	set.hosts.has_device_0 = FALSE;
	set.hosts.has_output_regex = FALSE;

	mode = initialize_main_database(&local, &remote);
	assert(mode == LOCAL);
	assert(set.hosts.has_device_0 && set.hosts.has_output_regex);

	db_close_connection_pool(LOCAL);
	free(db_pool_local);
	db_pool_local = previous_pool;
	db_disconnect(&local);
	assert(db_insert(mysql, LOCAL, "ALTER TABLE poller_item DROP COLUMN output_regex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=951"));
	set = previous;
}

static void prepare_script_server_pool(const char *mode) {
	php_processes = calloc(MAX_PHP_SERVERS, sizeof(*php_processes));
	assert(php_processes != NULL);
	php_processes_initialize(php_processes, MAX_PHP_SERVERS);
	set.php.php_required = TRUE;
	set.php.php_initialized = FALSE;
	set.availability.ping_only = FALSE;
	set.php.php_servers = 2;
	set.php.script_timeout = 1;
	set.cacti_version = 1300;
	set.poller.poller_id = 1;
	snprintf(set.php.path_php, sizeof(set.php.path_php), "%s", SCRIPT_SERVER);
	snprintf(set.php.path_php_server, sizeof(set.php.path_php_server), "%s", mode);
}

static void start_script_servers_that_cannot_run(void) {
	prepare_script_server_pool("normal");
	snprintf(set.php.path_php, sizeof(set.php.path_php), "%s", "/nonexistent/spine-php");
	initialize_main_php();
}

static void test_startup_script_servers(void) {
	php_t *previous_processes = php_processes;
	config_t previous = set;
	char claim[] = "spine-startup-claim-XXXXXX";
	char mode[SMALL_BUFSIZE];
	int fd = mkstemp(claim);

	assert(fd >= 0);
	assert(close(fd) == 0);
	assert(unlink(claim) == 0);

	/* a pool in which only the first server answers still lets polling start */
	snprintf(mode, sizeof(mode), "first-only:%s", claim);
	prepare_script_server_pool(mode);
	initialize_main_php();
	assert(set.php.php_initialized);
	assert(php_processes[0].php_state == PHP_READY);
	assert(php_processes[1].php_state == PHP_BUSY);
	php_close(PHP_INIT);
	free(php_processes);
	assert(unlink(claim) == 0);

	prepare_script_server_pool("normal");
	initialize_main_php();
	assert(php_processes[0].php_state == PHP_READY && php_processes[1].php_state == PHP_READY);
	php_close(PHP_INIT);
	free(php_processes);

	/* with no server able to start there is nothing to poll with */
	php_processes = NULL;
	assert(spine_test_run_child(start_script_servers_that_cannot_run) == EXIT_FAILURE);
	php_processes = previous_processes;
	set = previous;
}

static char search_directory[SMALL_BUFSIZE];

static void search_for_a_configuration_that_does_not_exist(void) {
	for (int index = 0; index < CONFIG_PATHS; index++) {
		snprintf(config_paths[index], sizeof(config_paths[index]), "%s", "/nonexistent/");
	}
	(void) load_startup_configuration(NULL);
}

static void read_a_named_configuration_that_does_not_exist(void) {
	char path[] = "/nonexistent/spine-startup.conf";

	(void) load_startup_configuration(path);
}

static void test_startup_configuration_search(void) {
	char directory[] = "/tmp/spine-startup-XXXXXX";
	char file_name[SMALL_BUFSIZE];
	char expected[SMALL_BUFSIZE];
	char saved_paths[CONFIG_PATHS][BUFSIZE];
	config_t previous = set;
	char *found;
	FILE *file;

	assert(mkdtemp(directory) != NULL);
	snprintf(search_directory, sizeof(search_directory), "%s/", directory);
	snprintf(file_name, sizeof(file_name), "%s/%s", directory, DEFAULT_CONF_FILE);
	snprintf(expected, sizeof(expected), "%s%s", search_directory, DEFAULT_CONF_FILE);
	file = fopen(file_name, "w");
	assert(file != NULL);
	assert(fprintf(file, "DB_Host %s\nDB_Database spine_regressions\nDB_User root\nDB_Port 3306\n", set.database.host) > 0);
	assert(fclose(file) == 0);

	memcpy(saved_paths, config_paths, sizeof(saved_paths));
	snprintf(config_paths[0], sizeof(config_paths[0]), "%s", "/nonexistent/");
	snprintf(config_paths[1], sizeof(config_paths[1]), "%s", search_directory);
	found = load_startup_configuration(NULL);
	assert(found != NULL && strcmp(found, expected) == 0);
	free(found);

	assert(spine_test_run_child(search_for_a_configuration_that_does_not_exist) == EXIT_FAILURE);
	assert(spine_test_run_child(read_a_named_configuration_that_does_not_exist) == EXIT_FAILURE);

	memcpy(config_paths, saved_paths, sizeof(saved_paths));
	set = previous;
	assert(unlink(file_name) == 0);
	assert(rmdir(directory) == 0);
}

/* Both streams being a terminal changes how much startup chatter is printed;
 * a pseudo-terminal stands in for the operator's console. */
static void detect_a_console(void) {
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	int slave;

	if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) _exit(77);
	slave = open(ptsname(master), O_RDWR | O_NOCTTY);
	if (slave < 0) _exit(77);
	if (dup2(slave, STDOUT_FILENO) < 0 || dup2(slave, STDERR_FILENO) < 0) _exit(77);
	(void) initialize_process_defaults();
	_exit(!set.console.stdout_notty && !set.console.stderr_notty ? 0 : 3);
}

static void test_startup_console_detection(void) {
	int status = spine_test_run_child(detect_a_console);

	assert(status == 0 || status == 77);
}

void test_startup_contracts(MYSQL *mysql) {
	test_startup_database_detection(mysql);
	test_startup_script_servers();
	test_startup_configuration_search();
	test_startup_console_detection();
	puts("production startup regressions passed");
}
