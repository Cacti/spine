/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Project contributor history: CONTRIBUTORS.md.
 */

/* posix_openpt() and the other pty calls are XSI declarations on glibc, which
 * the coverage job only saw through its -include of a header that defines this. */
#define _GNU_SOURCE
#include "internal/common.h"
#include "app/spine.h"
#include "app/startup_internal.h"
#include "tests/support/child_run.h"
#include <fcntl.h>

#define SCRIPT_SERVER "./tests/support/php_test_server"

/* Concurrent processes split the devices with --first/--last or a host list.
 * Device 0 belongs only to a run whose selection covers it, as in cmd.php;
 * otherwise every process polled its items and advanced their schedule. */
static void assert_device_0_scope(int first, int last, const char *host_list, int expected) {
	MYSQL local;
	MYSQL remote;
	pool_t *previous_pool = db_pool_local;

	set.hosts.start_host_id = first;
	set.hosts.end_host_id = last;
	snprintf(set.hosts.host_id_list, sizeof(set.hosts.host_id_list), "%s", host_list);
	set.hosts.has_device_0 = FALSE;
	(void) initialize_main_database(&local, &remote);
	assert(set.hosts.has_device_0 == expected);
	db_close_connection_pool(LOCAL);
	free(db_pool_local);
	db_pool_local = previous_pool;
	db_disconnect(&local);
	set.hosts.start_host_id = -1;
	set.hosts.end_host_id = -1;
	set.hosts.host_id_list[0] = '\0';
}

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
	/* the configuration test left a host list that excludes device 0 */
	set.hosts.host_id_list[0] = '\0';

	mode = initialize_main_database(&local, &remote);
	assert(mode == LOCAL);
	assert(set.hosts.has_device_0 && set.hosts.has_output_regex);

	db_close_connection_pool(LOCAL);
	free(db_pool_local);
	db_pool_local = previous_pool;
	db_disconnect(&local);

	assert_device_0_scope(1, 10, "", FALSE);
	assert_device_0_scope(0, 10, "", TRUE);
	assert_device_0_scope(-1, -1, "4,10", FALSE);
	assert_device_0_scope(-1, -1, "4,0", TRUE);
	/* a host list replaces the range, as it does in the device query */
	assert_device_0_scope(1, 10, "0", TRUE);
	assert(db_insert(mysql, LOCAL, "ALTER TABLE poller_item DROP COLUMN output_regex"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=951"));
	set = previous;
}

/* An online collector writes its poller_time start row through the remote
 * handle. The main server can be MySQL 5.7 or later, whose default sql_mode
 * rejects Cacti's zero dates, so that handle needs the local session policy. */
static void test_startup_remote_session(void) {
	MYSQL local;
	MYSQL remote;
	MYSQL_RES *result;
	MYSQL_ROW row;
	pool_t *previous_local = db_pool_local;
	pool_t *previous_remote = db_pool_remote;
	config_t previous = set;
	const char *remote_host = getenv("SPINE_TEST_REMOTE_DB_HOST");
	char query[BUFSIZE];

	set.poller.threads = 1;
	set.poller.poller_id = 2;
	set.poller.mode = REMOTE_ONLINE;
	set.hosts.host_id_list[0] = '\0';
	set.remote_database = set.database;
	set.remote_database.ssl = FALSE;
	/* The regression lane's second server is MySQL 8.4 at its default sql_mode. */
	if (remote_host != NULL && remote_host[0] != '\0') {
		snprintf(set.remote_database.host, sizeof(set.remote_database.host), "%s", remote_host);
		set.remote_database.port = 3307;
	}

	assert(initialize_main_database(&local, &remote) == REMOTE);
	result = db_query(&remote, REMOTE, "SELECT @@SESSION.sql_mode");
	assert(result != NULL);
	row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	assert(strstr(row[0], "NO_ZERO_DATE") == NULL && strstr(row[0], "STRICT_TRANS_TABLES") == NULL);
	db_free_result(result);
	snprintf(query, sizeof(query), "INSERT INTO poller_time (poller_id, pid, start_time, end_time) VALUES (2, %i, NOW(), '0000-00-00 00:00:00')", getpid());
	assert(db_insert(&remote, REMOTE, query));
	snprintf(query, sizeof(query), "DELETE FROM poller_time WHERE poller_id=2 AND pid=%i", getpid());
	assert(db_insert(&remote, REMOTE, query));

	db_close_connection_pool(REMOTE);
	free(db_pool_remote);
	db_pool_remote = previous_remote;
	db_close_connection_pool(LOCAL);
	free(db_pool_local);
	db_pool_local = previous_local;
	db_disconnect(&remote);
	db_disconnect(&local);
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
	php_processes = NULL;
	assert(unlink(claim) == 0);

	prepare_script_server_pool("normal");
	initialize_main_php();
	assert(php_processes[0].php_state == PHP_READY && php_processes[1].php_state == PHP_READY);
	php_close(PHP_INIT);
	free(php_processes);
	php_processes = NULL;

	/* with no server able to start there is nothing to poll with */
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
	char directory[] = "spine-startup-XXXXXX";
	char file_name[SMALL_BUFSIZE];
	char expected[SMALL_BUFSIZE + sizeof(DEFAULT_CONF_FILE)];
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
	test_startup_remote_session();
	test_startup_script_servers();
	test_startup_configuration_search();
	test_startup_console_detection();
	puts("production startup regressions passed");
}
