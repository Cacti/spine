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
#if defined(__GLIBC__)
#include <malloc.h>
#endif

extern poller_thread_t **details;

typedef struct {
	poller_thread_t thread;
	int errors;
} reindex_test_work_t;

static unsigned long reindex_count(MYSQL *mysql, const char *query) {
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1 && mysql_num_fields(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	unsigned long count = strtoul(row[0], NULL, 10);
	db_free_result(result);
	return count;
}

static void *run_reindex_worker(void *argument) {
	reindex_test_work_t *work = argument;
	assert(mysql_thread_init() == 0);
	poll_host(&work->thread, &work->errors);
	return NULL;
}

static void run_reindex_case(MYSQL *mysql, int action, const char *argument,
	const char *op, const char *expected, const char *stored, int commands) {
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='45:7' OR command='45:8'"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=801"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id=801"));
	char query[LRG_BUFSIZE];
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (45,7,%d,'%s','%s','%s')", action, op, expected, argument);
	assert(db_insert(mysql, LOCAL, query));
	reindex_test_work_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	work->thread.host_id = 45;
	work->thread.host_thread = 1;
	work->thread.host_threads = 1;
	work->thread.host_data_ids = 1;
	work->thread.host_time_double = get_time_as_double();
	STRNCOPY(work->thread.host_time, "1791158400");
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = &work->thread;
	poller_thread_t **prior_details = details;
	details = owned_details;
	pthread_t worker;
	assert(pthread_create(&worker, NULL, run_reindex_worker, work) == 0);
	assert(pthread_join(worker, NULL) == 0);
	assert(work->thread.complete && work->thread.threads_complete == 1 && work->errors == 0);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE poller_id=1 AND action=1 AND command='45:7'") == (unsigned long)commands);
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_reindex WHERE host_id=45 AND data_query_id=7 AND assert_value='%s'", stored);
	assert(reindex_count(mysql, query) == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=801 AND output='123'") == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=801 AND output='123'") == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=45") == 0);
	details = prior_details;
	free(owned_details);
	free(work);
}

static void run_uptime_cache_case(MYSQL *mysql) {
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='45:7' OR command='45:8'"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=801"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id=801"));
	/* Different query IDs prevent the first assertion's shortcut skipping row2. */
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (45,7,0,'>','0','.1.3.6.1.2.1.1.3.0'),(45,8,0,'>','0','.1.3.6.1.6.3.10.2.1.3.0')"));
	reindex_test_work_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	work->thread.host_id = 45;
	work->thread.host_thread = 1;
	work->thread.host_threads = 1;
	work->thread.host_data_ids = 1;
	work->thread.host_time_double = get_time_as_double();
	STRNCOPY(work->thread.host_time, "1791158400");
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = &work->thread;
	poller_thread_t **prior_details = details;
	details = owned_details;
	pthread_t worker;
	assert(pthread_create(&worker, NULL, run_reindex_worker, work) == 0);
	assert(pthread_join(worker, NULL) == 0);
	assert(work->thread.complete && work->thread.threads_complete == 1 && work->errors == 0);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE poller_id=1 AND action=1 AND command IN ('45:7','45:8')") == 2);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE host_id=45 AND assert_value REGEXP '^[0-9]+$' AND CAST(assert_value AS UNSIGNED)>0") == 2);
	/* A failed assertion on an uptime OID means the counters reset, so the
	 * cycle's samples are discarded as a spike. */
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=801 AND output='U'") == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id=801 AND output='U'") == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=45") == 0);
	details = prior_details;
	free(owned_details);
	free(work);
}

void test_additional_reindex_contracts(MYSQL *mysql) {
	const char *agent = getenv("SPINE_TEST_SNMP_HOST");
	assert(agent != NULL && agent[0] != '\0');
	config_t previous_config = set;
	pool_t *previous_pool = db_pool_local;
	poller_thread_t **previous_details = details;
	php_t *previous_processes = php_processes;
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
	set.snmp.mibs = FALSE;
	set.availability.ping_recovery_count = 1;
	set.availability.ping_failure_count = 1;
	set.php.php_servers = 1;
	set.php.php_current_server = 0;
	set.cacti_version = 1232;
	set.poller.mode = REMOTE_ONLINE;
	db_pool_local = calloc(1, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_create_connection_pool(LOCAL);
	assert(spine_permits_init(&available_scripts, 2) == 0);
	assert(db_insert(mysql, LOCAL, "DELETE FROM host_errors WHERE host_id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host WHERE id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=801"));
	char escaped_agent[BUFSIZE];
	db_escape(mysql, escaped_agent, sizeof(escaped_agent), agent);
	char query[LRG_BUFSIZE];
	spine_snprintf(query, sizeof(query), "INSERT INTO host(id,hostname,availability_method,snmp_version,snmp_community,snmp_port,snmp_timeout,status_fail_date,status_rec_date,max_oids) VALUES (45,'%s',%d,2,'regression',1161,500,'2026-10-05 00:00:00','2026-10-05 00:00:00',5)", escaped_agent, AVAIL_NONE);
	assert(db_insert(mysql, LOCAL, query));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name) VALUES(801,45,1,1,'/usr/bin/printf 123','reindex_valid')"));
	snmp_spine_init();
	run_reindex_case(mysql, POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.6.0", "=", "isolated-regression-agent", "isolated-regression-agent", 0);
	run_reindex_case(mysql, POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.6.0", "=", "previous", "isolated-regression-agent", 1);
	run_reindex_case(mysql, POLLER_ACTION_SNMP, "invalid-regression-oid", "=", "previous", "previous", 0);
	run_reindex_case(mysql, POLLER_ACTION_SNMP_COUNT, ".1.3.6.1.2.1.1.6", "=", "0", "1", 1);
	run_uptime_cache_case(mysql);
	assert(db_insert(mysql, LOCAL, "UPDATE host SET snmp_community='' WHERE id=45"));
	run_reindex_case(mysql, POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.6.0", "=", "previous", "previous", 0);

	php_t processes[1] = {0};
	php_processes = processes;
	char *executable = realpath("./test_spine_regressions", NULL);
	assert(executable != NULL);
	strncopy(set.php.path_php, executable, sizeof(set.php.path_php));
	free(executable);
	STRNCOPY(set.php.path_php_server, "regression-server");
	assert(php_init(PHP_INIT));
	run_reindex_case(mysql, POLLER_ACTION_PHP_SCRIPT_SERVER, "regression request", "=", "7", "7", 0);
	run_reindex_case(mysql, POLLER_ACTION_PHP_SCRIPT_SERVER, "regression request", "=", "6", "7", 1);
	run_reindex_case(mysql, POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT, "regression request", "=", "2", "1", 1);
	php_close(PHP_INIT);
	assert(processes[0].php_pid == -1 && processes[0].php_read_fd == -1 && processes[0].php_write_fd == -1);
	php_processes = previous_processes;
	assert(spine_permits_destroy(&available_scripts) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	details = previous_details;
	set = previous_config;
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='45:7' OR command='45:8'"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=801"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id=801"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=801"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host_errors WHERE host_id=45"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host WHERE id=45"));
	puts("production live SNMP and PHP reindex contracts passed");
}

static int poll_reindex_result(MYSQL *mysql, int action, const char *argument,
	const char *op, const char *expected) {
	char escaped_argument[BUFSIZE];
	char query[LRG_BUFSIZE];
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=46"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='46:7'"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=811"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id=811"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host_errors WHERE host_id=46"));
	db_escape(mysql, escaped_argument, sizeof(escaped_argument), argument);
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (46,7,%d,'%s','%s','%s')", action, op, expected, escaped_argument);
	assert(db_insert(mysql, LOCAL, query));
	reindex_test_work_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	work->thread.host_id = 46;
	work->thread.host_thread = 1;
	work->thread.host_threads = 1;
	work->thread.host_data_ids = 1;
	work->thread.host_time_double = get_time_as_double();
	STRNCOPY(work->thread.host_time, "1791158400");
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = &work->thread;
	poller_thread_t **prior_details = details;
	details = owned_details;
	pthread_t worker;
	assert(pthread_create(&worker, NULL, run_reindex_worker, work) == 0);
	assert(pthread_join(worker, NULL) == 0);
	details = prior_details;
	free(owned_details);
	assert(work->thread.complete && work->thread.threads_complete == 1);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
	int errors = work->errors;
	free(work);
	return errors;
}

/* Runs against the database alone: the SNMP host points at a port with no
 * agent, which is the failure the uptime case needs. */
void test_reindex_result_contracts(MYSQL *mysql) {
	config_t previous_config = set;
	pool_t *previous_pool = db_pool_local;
	set.poller.threads = 1;
	set.poller.poller_id = 1;
	set.poller.poller_interval = 0;
	set.poller.active_profiles = 1;
	set.poller.mode = REMOTE_OFFLINE;
	set.boost.boost_enabled = FALSE;
	set.boost.boost_redirect = FALSE;
	set.availability.ping_only = FALSE;
	set.php.script_timeout = 2;
	set.logging.spine_log_level = 0;
	set.logging.log_destination = 0;
	set.snmp.mibs = FALSE;
	set.snmp.snmp_retries = 0;
	db_pool_local = calloc(1, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_create_connection_pool(LOCAL);
	assert(spine_permits_init(&available_scripts, 2) == 0);
	assert(db_insert(mysql, LOCAL, "DELETE FROM host WHERE id=46"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=811"));
	char query[LRG_BUFSIZE];
	spine_snprintf(query, sizeof(query), "INSERT INTO host(id,hostname,availability_method,snmp_version,snmp_community,snmp_port,snmp_timeout,status_fail_date,status_rec_date,max_oids) VALUES (46,'127.0.0.1',%d,2,'regression',1,200,'2026-10-05 00:00:00','2026-10-05 00:00:00',5)", AVAIL_NONE);
	assert(db_insert(mysql, LOCAL, query));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name) VALUES(811,46,1,1,'/usr/bin/printf 123','reindex_result')"));
	snmp_spine_init();

	/* Trimmed script output must be freed through the pointer malloc returned. */
	assert(poll_reindex_result(mysql, POLLER_ACTION_SCRIPT, "/usr/bin/printf ' 123'", "=", "123") == 0);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE command='46:7'") == 0);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=811 AND output='123'") == 1);
	assert(poll_reindex_result(mysql, POLLER_ACTION_SCRIPT, "/usr/bin/printf '\"123\"\\n'", "=", "122") == 0);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE command='46:7'") == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE host_id=46 AND assert_value='123'") == 1);

	/* A failed assertion counts an error with no data source behind it. The
	 * error list it reports must be empty, not uninitialized heap. */
	set.logging.spine_log_level = 1;
#if defined(__GLIBC__)
	assert(mallopt(M_PERTURB, 0x5a) == 1);
#endif
	int errors = poll_reindex_result(mysql, POLLER_ACTION_SCRIPT, "/usr/bin/printf 123", "=", "122");
#if defined(__GLIBC__)
	assert(mallopt(M_PERTURB, 0) == 1);
#endif
	set.logging.spine_log_level = 0;
	assert(errors == 1);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=46 AND errors=1 AND local_data_ids=''") == 1);

	/* An uptime that cannot be read is unknown. It must not queue a reindex
	 * or replace the last good assertion. */
	poll_reindex_result(mysql, POLLER_ACTION_SNMP, ".1.3.6.1.2.1.1.3.0", "<", "124");
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE command='46:7'") == 0);
	assert(reindex_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE host_id=46 AND assert_value='124'") == 1);

	/* Good baseline, unreadable cycle, then a reboot. Keeping U as the
	 * baseline would compare as 0 and the reboot would never fire. */
	char sample_path[] = "/tmp/spine-reindex-sample-XXXXXX";
	int sample = mkstemp(sample_path);
	assert(sample >= 0);
	assert(close(sample) == 0);
	char command[BUFSIZE];
	spine_snprintf(command, sizeof(command), "/bin/cat %s", sample_path);
	static const struct { const char *sample; int commands; const char *stored; } cycles[] = {
		{"500", 0, "500"}, {"U", 0, "500"}, {"100", 1, "100"}
	};
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=46"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='46:7'"));
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_reindex(host_id,data_query_id,action,op,assert_value,arg1) VALUES (46,7,%d,'<','0','%s')", POLLER_ACTION_SCRIPT, command);
	assert(db_insert(mysql, LOCAL, query));
	for (size_t cycle = 0; cycle < sizeof(cycles) / sizeof(cycles[0]); cycle++) {
		FILE *file = fopen(sample_path, "w");
		assert(file != NULL && fputs(cycles[cycle].sample, file) >= 0 && fclose(file) == 0);
		reindex_test_work_t *work = calloc(1, sizeof(*work));
		assert(work != NULL);
		work->thread.host_id = 46;
		work->thread.host_thread = 1;
		work->thread.host_threads = 1;
		work->thread.host_data_ids = 1;
		work->thread.host_time_double = get_time_as_double();
		STRNCOPY(work->thread.host_time, "1791158400");
		poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
		assert(owned_details != NULL);
		owned_details[0] = &work->thread;
		poller_thread_t **prior_details = details;
		details = owned_details;
		pthread_t worker;
		assert(pthread_create(&worker, NULL, run_reindex_worker, work) == 0);
		assert(pthread_join(worker, NULL) == 0);
		details = prior_details;
		free(owned_details);
		spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_reindex WHERE host_id=46 AND assert_value='%s'", cycles[cycle].stored);
		if (reindex_count(mysql, "SELECT COUNT(*) FROM poller_command WHERE command='46:7'") != (unsigned long)cycles[cycle].commands ||
			reindex_count(mysql, query) != 1) {
			fprintf(stderr, "reindex baseline: cycle=%zu sample=%s expected commands=%d stored=%s\n", cycle, cycles[cycle].sample, cycles[cycle].commands, cycles[cycle].stored);
			assert(0);
		}
		free(work);
	}
	assert(unlink(sample_path) == 0);

	assert(spine_permits_destroy(&available_scripts) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	set = previous_config;
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_reindex WHERE host_id=46"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_command WHERE command='46:7'"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id=811"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id=811"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE local_data_id=811"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host_errors WHERE host_id=46"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host WHERE id=46"));
	puts("production reindex result contracts passed");
}
