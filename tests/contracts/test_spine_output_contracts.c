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
#include <fcntl.h>

extern poller_thread_t **details;
extern int *debug_devices;
extern void start_test_worker(pthread_t *worker, void *(*start)(void *), void *argument);

static unsigned long long output_count(MYSQL *mysql, const char *query) {
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL);
	unsigned long long value = strtoull(row[0], NULL, 10);
	db_free_result(result);
	return value;
}

static void assert_output_engine(MYSQL *mysql, const char *table, const char *engine) {
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='%s'", table);
	MYSQL_RES *result = db_query(mysql, LOCAL, query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	MYSQL_ROW row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL && STRIMATCH(row[0], engine));
	db_free_result(result);
}

static void run_output_partition(const poller_thread_t *aggregate, int partition) {
	poller_thread_t *work = malloc(sizeof(*work));
	assert(work != NULL);
	*work = *aggregate;
	work->host_thread = partition;
	spine_permits_t startup;
	assert(spine_permits_init(&startup, 1) == 0);
	assert(spine_permits_try_acquire(&startup) == 0);
	work->thread_init_sem = &startup;
	assert(spine_permits_try_acquire(&available_threads) == 0);
	pthread_t worker;
	/* Production child owns/frees instructions and releases thread/startup
	 * permits after poll_host, including output failures. */
	start_test_worker(&worker, child, work);
	assert(pthread_join(worker, NULL) == 0);
	assert(spine_permits_available(&startup) == 1);
	assert(spine_permits_destroy(&startup) == 0);
	assert(spine_permits_available(&available_threads) == 1);
	assert(db_pool_local[0].free && spine_permits_available(&available_scripts) == 2);
}

/* A real bounded PHP-server producer: consume command lines and send numeric
 * samples. The production PHP transport and poll_host do all interpretation. */
static void send_output_sample(int fd, const char *result, size_t length) {
	size_t sent = 0;
	while (sent < length) {
		ssize_t count = write(fd, result + sent, length - sent);
		if (count < 0 && errno == EINTR) continue;
		assert(count > 0);
		sent += (size_t) count;
	}
}

static pid_t start_output_server(php_t *server, int payload) {
	int requests[2];
	int responses[2];
	assert(pipe(requests) == 0 && pipe(responses) == 0);
	fflush(NULL);
	pid_t child = fork();
	assert(child >= 0);
	if (child == 0) {
		alarm(180);
		assert(close(requests[1]) == 0 && close(responses[0]) == 0);
		FILE *input = fdopen(requests[0], "r");
		assert(input != NULL);
		char command[BUFSIZE];
		char result[512];
		assert(payload >= 3 && payload < (int) sizeof(result));
		memset(result, '0', payload - 3);
		memcpy(result + payload - 3, "123\n", 4);
		while (fgets(command, sizeof(command), input) != NULL) {
			send_output_sample(responses[1], result, (size_t) payload + 1);
		}
		assert(!ferror(input) && fclose(input) == 0 && close(responses[1]) == 0);
		_exit(0);
	}
	assert(close(requests[0]) == 0 && close(responses[1]) == 0);
	server->php_state = PHP_READY;
	server->php_pid = child;
	server->php_write_fd = requests[1];
	server->php_read_fd = responses[0];
	return child;
}

static void reset_output_work(poller_thread_t *work, int rows, int partitions) {
	memset(work, 0, sizeof(*work));
	work->host_id = 901;
	work->host_threads = partitions;
	work->host_thread = partitions;
	work->host_data_ids = rows / partitions;
	work->host_time_double = get_time_as_double();
	STRNCOPY(work->host_time, "1791244800");
	set.exit.exit_code = EXIT_SUCCESS;
}

static void assert_sample(MYSQL *mysql, const char *table, int id, const char *expected) {
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE local_data_id=%i AND output=%s", table, id, expected);
	assert(output_count(mysql, query) == 1);
}

static void assert_sample_at(MYSQL *mysql, const char *table, int id,
	const char *timestamp, const char *expected) {
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM %s WHERE local_data_id=%i AND time=FROM_UNIXTIME(%s) AND output='%s'", table, id, timestamp, expected);
	assert(output_count(mysql, query) == 1);
}

static void test_output_recollection(MYSQL *mysql) {
	poller_thread_t **previous_details = details;
	char query[BUFSIZE];
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id BETWEEN 930001 AND 939999"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND 939999"));
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name,snmp_port,rrd_step,rrd_next_step) VALUES(930001,901,1,%i,'/usr/bin/printf 123','owned',161,300,0),(930002,901,1,%i,'/usr/bin/printf 123','owned',162,300,0)", POLLER_ACTION_SCRIPT, POLLER_ACTION_SCRIPT);
	assert(db_insert(mysql, LOCAL, query));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_output(local_data_id,rrd_name,time,output) VALUES(930001,'owned',FROM_UNIXTIME(1791244800),'old'),(930002,'owned',FROM_UNIXTIME(1791244800),'old')"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_output_boost(local_data_id,rrd_name,time,output) VALUES(930001,'owned',FROM_UNIXTIME(1791244800),'old'),(930002,'owned',FROM_UNIXTIME(1791244800),'old')"));
	assert(db_insert(mysql, LOCAL, "CREATE TRIGGER spine_owned_output_reject BEFORE INSERT ON poller_output FOR EACH ROW BEGIN IF NEW.local_data_id=930002 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned output rejection'; END IF; END"));
	poller_thread_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	reset_output_work(work, 2, 1);
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = work;
	details = owned_details;
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_FAILURE && work->output_failed && !work->complete);
	assert(work->threads_complete == 1);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=0") == 2);
	assert_sample_at(mysql, "poller_output", 930001, "1791244800", "123");
	assert_sample_at(mysql, "poller_output", 930002, "1791244800", "old");
	assert_sample_at(mysql, "poller_output_boost", 930001, "1791244800", "123");
	assert_sample_at(mysql, "poller_output_boost", 930002, "1791244800", "123");
	assert(db_insert(mysql, LOCAL, "DROP TRIGGER spine_owned_output_reject"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET arg1='/usr/bin/printf 456' WHERE host_id=901"));
	/* A later poll recollects current values, rather than replaying failed
	 * samples. Supply distinct work timestamps without depending on the clock. */
	reset_output_work(work, 2, 1);
	STRNCOPY(work->host_time, "1791244805");
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_SUCCESS && !work->output_failed && work->complete);
	assert(work->threads_complete == 1);
	for (int id = 930001; id <= 930002; id++) {
		assert_sample_at(mysql, "poller_output", id, "1791244805", "456");
		assert_sample_at(mysql, "poller_output_boost", id, "1791244805", "456");
		assert_sample_at(mysql, "poller_output_boost", id, "1791244800", "123");
	}
	assert_sample_at(mysql, "poller_output", 930001, "1791244800", "123");
	assert_sample_at(mysql, "poller_output", 930002, "1791244800", "old");
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=295") == 2);
	assert(output_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=901") == 0);
	assert_sample(mysql, "poller_output", 930000, "'unchanged'");
	assert_sample(mysql, "poller_output_boost", 930000, "'unchanged'");
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id BETWEEN 930000 AND 939999") == 5);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id BETWEEN 930000 AND 939999") == 5);
	details = previous_details;
	free(owned_details);
	free(work);
	puts("production output recollection retains incomplete historical samples passed");
}

typedef struct {
	poller_thread_t *work;
	int finished_fd;
} controlled_output_worker_t;

static void output_worker_finished(void *arg) {
	const controlled_output_worker_t *worker = arg;
	/* This outer handler runs after production child cleanup frees instructions
	 * and releases its permit, even though child exits through pthread_exit. */
	send_output_sample(worker->finished_fd, "F", 1);
}

static void *controlled_output_child(void *arg) {
	const controlled_output_worker_t *worker = arg;
	pthread_cleanup_push(output_worker_finished, arg);
	child(worker->work);
	pthread_cleanup_pop(1);
	return NULL;
}

static void output_descriptor_flags(int fd) {
	int flags = fcntl(fd, F_GETFD);
	assert(flags >= 0 && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);
	flags = fcntl(fd, F_GETFL);
	assert(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
}

static void await_output_byte(int fd, char expected, double deadline) {
	assert(spine_wait_readable(fd, deadline) == 1);
	char value;
	ssize_t count;
	do { count = read(fd, &value, 1); } while (count < 0 && errno == EINTR);
	assert(count == 1 && value == expected);
}

static void close_output_signal(int ready, int release, const int finished[2], const char *ready_path, const char *release_path) {
	assert(close(ready) == 0 && close(release) == 0);
	assert(close(finished[0]) == 0 && close(finished[1]) == 0);
	assert(unlink(ready_path) == 0 && unlink(release_path) == 0);
}

static void test_concurrent_output_failure(MYSQL *mysql) {
	pool_t *previous_pool = db_pool_local;
	poller_thread_t **previous_details = details;
	int previous_threads = set.poller.threads;
	int previous_timeout = set.php.script_timeout;
	assert(previous_threads == 1 && db_pool_local[0].free);
	assert(spine_permits_available(&available_threads) == 1);
	assert(spine_permits_available(&available_scripts) == 2);
	assert(spine_permits_destroy(&available_threads) == 0);
	assert(spine_permits_init(&available_threads, 2) == 0);
	set.poller.threads = 2;
	set.php.script_timeout = 30;
	db_pool_local = calloc(2, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_create_connection_pool(LOCAL);
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id BETWEEN 930001 AND 939999"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND 939999"));
	char directory[] = "/tmp/spine-output-overlap-XXXXXX";
	assert(mkdtemp(directory) != NULL);
	struct stat directory_status;
	assert(lstat(directory, &directory_status) == 0);
	assert(S_ISDIR(directory_status.st_mode));
	assert((directory_status.st_mode & 0777) == 0700 && directory_status.st_uid == geteuid());
	char ready_paths[2][SMALL_BUFSIZE];
	char release_paths[2][SMALL_BUFSIZE];
	int ready[2];
	int release[2];
	int finished[2][2];
	char query[LRG_BUFSIZE];
	for (int index = 0; index < 2; index++) {
		spine_snprintf(ready_paths[index], sizeof(ready_paths[index]), "%s/ready%i", directory, index);
		spine_snprintf(release_paths[index], sizeof(release_paths[index]), "%s/release%i", directory, index);
		assert(mkfifo(ready_paths[index], 0600) == 0 && mkfifo(release_paths[index], 0600) == 0);
		ready[index] = open(ready_paths[index], O_RDWR | O_NONBLOCK);
		release[index] = open(release_paths[index], O_RDWR | O_NONBLOCK);
		assert(ready[index] >= 0 && release[index] >= 0 && pipe(finished[index]) == 0);
		output_descriptor_flags(ready[index]);
		output_descriptor_flags(release[index]);
		output_descriptor_flags(finished[index][0]);
		output_descriptor_flags(finished[index][1]);
		/* Quote-free SQL string; the real shell producer signals selection then
		 * blocks on its own gate before publishing a sample to Spine. */
		spine_snprintf(query, sizeof(query), "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name,snmp_port,rrd_step,rrd_next_step) VALUES(%i,901,1,%i,'/usr/bin/printf R > %s; read token < %s; /usr/bin/printf 123','owned',%i,300,0)", 930001 + index, POLLER_ACTION_SCRIPT, ready_paths[index], release_paths[index], 161 + index);
		assert(db_insert(mysql, LOCAL, query));
	}
	assert(db_insert(mysql, LOCAL, "CREATE TRIGGER spine_owned_output_reject BEFORE INSERT ON poller_output FOR EACH ROW BEGIN IF NEW.local_data_id=930002 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned output rejection'; END IF; END"));
	poller_thread_t *aggregate = calloc(1, sizeof(*aggregate));
	assert(aggregate != NULL);
	reset_output_work(aggregate, 2, 2);
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = aggregate;
	details = owned_details;
	spine_permits_t startup;
	assert(spine_permits_init(&startup, 2) == 0);
	controlled_output_worker_t workers[2];
	pthread_t threads[2];
	for (int index = 0; index < 2; index++) {
		workers[index].work = malloc(sizeof(*workers[index].work));
		assert(workers[index].work != NULL);
		thread_mutex_lock(LOCK_THDET);
		*workers[index].work = *aggregate;
		thread_mutex_unlock(LOCK_THDET);
		workers[index].work->host_thread = index + 1;
		workers[index].work->thread_init_sem = &startup;
		workers[index].finished_fd = finished[index][1];
		assert(spine_permits_try_acquire(&startup) == 0);
		assert(spine_permits_try_acquire(&available_threads) == 0);
		start_test_worker(&threads[index], controlled_output_child, &workers[index]);
	}
	double deadline = spine_monotonic_time() + 10;
	await_output_byte(ready[0], 'R', deadline);
	await_output_byte(ready[1], 'R', deadline);
	assert(spine_permits_available(&startup) == 2);
	assert(spine_permits_available(&available_threads) == 0);
	assert(spine_permits_available(&available_scripts) == 0);
	thread_mutex_lock(LOCK_POOL);
	assert(!db_pool_local[0].free && !db_pool_local[1].free);
	thread_mutex_unlock(LOCK_POOL);
	/* Both real workers have selected their own partition and hold resources.
	 * Allow only the rejected partition to finish first. */
	send_output_sample(release[1], "resume\n", 7);
	await_output_byte(finished[1][0], 'F', spine_monotonic_time() + 10);
	assert(pthread_join(threads[1], NULL) == 0);
	thread_mutex_lock(LOCK_THDET);
	assert(set.exit.exit_code == EXIT_FAILURE && aggregate->output_failed);
	assert(aggregate->threads_complete == 1 && !aggregate->complete);
	thread_mutex_unlock(LOCK_THDET);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=0") == 2);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id IN(930001,930002)") == 0);
	assert_sample_at(mysql, "poller_output_boost", 930002, "1791244800", "123");
	assert(spine_permits_available(&available_threads) == 1);
	assert(spine_permits_available(&available_scripts) == 1);
	thread_mutex_lock(LOCK_POOL);
	assert(db_pool_local[0].free + db_pool_local[1].free == 1);
	thread_mutex_unlock(LOCK_POOL);
	send_output_sample(release[0], "resume\n", 7);
	await_output_byte(finished[0][0], 'F', spine_monotonic_time() + 10);
	assert(pthread_join(threads[0], NULL) == 0);
	assert(set.exit.exit_code == EXIT_FAILURE && aggregate->output_failed && !aggregate->complete);
	assert(aggregate->threads_complete == 2);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=0") == 2);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id=930002") == 0);
	assert_sample_at(mysql, "poller_output", 930001, "1791244800", "123");
	assert_sample_at(mysql, "poller_output_boost", 930001, "1791244800", "123");
	assert_sample_at(mysql, "poller_output_boost", 930002, "1791244800", "123");
	assert_sample(mysql, "poller_output", 930000, "'unchanged'");
	assert_sample(mysql, "poller_output_boost", 930000, "'unchanged'");
	assert(output_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=901") == 0);
	assert(spine_permits_available(&available_threads) == 2);
	assert(spine_permits_available(&available_scripts) == 2);
	assert(db_pool_local[0].free && db_pool_local[1].free);
	assert(db_insert(mysql, LOCAL, "DROP TRIGGER spine_owned_output_reject"));
	for (int index = 0; index < 2; index++) {
		close_output_signal(ready[index], release[index], finished[index], ready_paths[index], release_paths[index]);
	}
	assert(rmdir(directory) == 0);
	assert(spine_permits_destroy(&startup) == 0);
	assert(spine_permits_destroy(&available_threads) == 0);
	assert(spine_permits_init(&available_threads, 1) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	details = previous_details;
	free(owned_details);
	free(aggregate);
	set.poller.threads = previous_threads;
	set.php.script_timeout = previous_timeout;
	puts("production simultaneous output failure ordering regressions passed");
}

static void assert_remote_resources_and_local_output(MYSQL *mysql) {
	assert(db_pool_local[0].free && db_pool_remote[0].free);
	assert(spine_permits_available(&available_threads) == 1);
	assert(spine_permits_available(&available_scripts) == 2);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id BETWEEN 930001 AND 939999") == 0);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND 939999") == 0);
	assert_sample(mysql, "poller_output", 930000, "'unchanged'");
	assert_sample(mysql, "poller_output_boost", 930000, "'unchanged'");
	assert(output_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=901") == 0);
}

static void assert_remote_samples(MYSQL *mysql, const char *timestamp, const char *sample) {
	for (int id = 930001; id <= 930002; id++) {
		assert_sample_at(mysql, "spine_owned_output_remote.poller_output", id, timestamp, sample);
		assert_sample_at(mysql, "spine_owned_output_remote.poller_output_boost", id, timestamp, sample);
	}
}

static void test_remote_output_destination(MYSQL *mysql) {
	pool_t *previous_remote_pool = db_pool_remote;
	poller_thread_t **previous_details = details;
	spine_database_config_t previous_remote_database = set.remote_database;
	int previous_id = set.poller.poller_id;
	int previous_mode = set.poller.mode;
	int previous_exit = set.exit.exit_code;
	assert(set.poller.threads == 1 && db_pool_local[0].free);
	assert(output_count(mysql, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='spine_owned_output_remote'") == 0);
	assert(db_insert(mysql, LOCAL, "CREATE DATABASE spine_owned_output_remote"));
	/* Clone the actual fixture tables, preserving their keys, column defaults,
	 * and different engines rather than inventing a remote schema. */
	assert(db_insert(mysql, LOCAL, "CREATE TABLE spine_owned_output_remote.poller_output LIKE poller_output"));
	assert(db_insert(mysql, LOCAL, "CREATE TABLE spine_owned_output_remote.poller_output_boost LIKE poller_output_boost"));
	assert(output_count(mysql, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='spine_owned_output_remote' AND TABLE_NAME='poller_output' AND ENGINE='MEMORY'") == 1);
	assert(output_count(mysql, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='spine_owned_output_remote' AND TABLE_NAME='poller_output_boost' AND ENGINE='InnoDB'") == 1);
	set.remote_database = set.database;
	STRNCOPY(set.remote_database.database, "spine_owned_output_remote");
	set.poller.poller_id = 2;
	set.poller.mode = REMOTE_ONLINE;
	db_pool_remote = calloc(1, sizeof(*db_pool_remote));
	assert(db_pool_remote != NULL);
	db_create_connection_pool(REMOTE);
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id BETWEEN 930001 AND 939999"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND 939999"));
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_reindex WHERE host_id=901") == 0);
	char query[BUFSIZE];
	spine_snprintf(query, sizeof(query), "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name,snmp_port,rrd_step,rrd_next_step) VALUES(930001,901,2,%i,'/usr/bin/printf 123','owned',161,300,0),(930002,901,2,%i,'/usr/bin/printf 123','owned',162,300,0)", POLLER_ACTION_SCRIPT, POLLER_ACTION_SCRIPT);
	assert(db_insert(mysql, LOCAL, query));
	poller_thread_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	reset_output_work(work, 2, 1);
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = work;
	details = owned_details;
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_SUCCESS && work->complete && !work->output_failed);
	assert(work->threads_complete == 1);
	assert_remote_samples(mysql, "1791244800", "123");
	assert_remote_resources_and_local_output(mysql);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND poller_id=2 AND rrd_next_step=295") == 2);
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET rrd_next_step=0,arg1='/usr/bin/printf 456' WHERE host_id=901 AND poller_id=2"));
	assert(db_insert(mysql, LOCAL, "CREATE TRIGGER spine_owned_output_remote.spine_owned_output_reject BEFORE INSERT ON spine_owned_output_remote.poller_output FOR EACH ROW BEGIN IF NEW.local_data_id=930002 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned remote output rejection'; END IF; END"));
	reset_output_work(work, 2, 1);
	STRNCOPY(work->host_time, "1791244805");
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_FAILURE && work->output_failed && !work->complete);
	assert(work->threads_complete == 1);
	assert_remote_resources_and_local_output(mysql);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND poller_id=2 AND rrd_next_step=0") == 2);
	assert_remote_samples(mysql, "1791244800", "123");
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output", 930001, "1791244805", "456");
	assert(output_count(mysql, "SELECT COUNT(*) FROM spine_owned_output_remote.poller_output WHERE local_data_id=930002 AND time=FROM_UNIXTIME(1791244805)") == 0);
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output_boost", 930001, "1791244805", "456");
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output_boost", 930002, "1791244805", "456");
	assert(db_insert(mysql, LOCAL, "DROP TRIGGER spine_owned_output_remote.spine_owned_output_reject"));
	assert(db_insert(mysql, LOCAL, "UPDATE poller_item SET arg1='/usr/bin/printf 789' WHERE host_id=901 AND poller_id=2"));
	reset_output_work(work, 2, 1);
	STRNCOPY(work->host_time, "1791244810");
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_SUCCESS && !work->output_failed && work->complete);
	assert(work->threads_complete == 1);
	assert_remote_resources_and_local_output(mysql);
	assert_remote_samples(mysql, "1791244810", "789");
	assert_remote_samples(mysql, "1791244800", "123");
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output", 930001, "1791244805", "456");
	assert(output_count(mysql, "SELECT COUNT(*) FROM spine_owned_output_remote.poller_output WHERE local_data_id=930002 AND time=FROM_UNIXTIME(1791244805)") == 0);
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output_boost", 930001, "1791244805", "456");
	assert_sample_at(mysql, "spine_owned_output_remote.poller_output_boost", 930002, "1791244805", "456");
	assert(output_count(mysql, "SELECT COUNT(*) FROM spine_owned_output_remote.poller_output") == 5);
	assert(output_count(mysql, "SELECT COUNT(*) FROM spine_owned_output_remote.poller_output_boost") == 6);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND poller_id=2 AND rrd_next_step=295") == 2);
	db_close_connection_pool(REMOTE);
	db_pool_remote = previous_remote_pool;
	assert(db_insert(mysql, LOCAL, "DROP DATABASE spine_owned_output_remote"));
	assert(output_count(mysql, "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='spine_owned_output_remote'") == 0);
	details = previous_details;
	free(owned_details);
	free(work);
	set.remote_database = previous_remote_database;
	set.poller.poller_id = previous_id;
	set.poller.mode = previous_mode;
	set.exit.exit_code = previous_exit;
	puts("production remote output destination failure and recollection regressions passed");
}

static void run_output_failure_scenario(MYSQL *mysql, int scenario, int payload) {
	poller_thread_t **previous_details = details;
	bool boundary = scenario >= 2;
	bool boost_failure = (scenario & 1) != 0;
	int rows = boundary ? MAX_MYSQL_BUF_SIZE / payload + 4 : 2;
	assert(rows < 9999);
	int partitions = scenario == 0 ? 2 : 1;
	char query[LRG_BUFSIZE];
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id BETWEEN 930001 AND 939999"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND 939999"));
	for (int index = 1; index <= rows; index++) {
		spine_snprintf(query, sizeof(query), "INSERT INTO poller_item(local_data_id,host_id,poller_id,action,arg1,rrd_name,snmp_port,rrd_step,rrd_next_step) VALUES(%i,901,1,%i,'%s','owned',%i,300,0)", 930000 + index, boundary ? POLLER_ACTION_PHP_SCRIPT_SERVER : POLLER_ACTION_SCRIPT, boundary ? "owned numeric request" : "/usr/bin/printf 123", 160 + index);
		assert(db_insert(mysql, LOCAL, query));
		spine_snprintf(query, sizeof(query), "INSERT INTO poller_output(local_data_id,rrd_name,time,output) VALUES(%i,'owned',FROM_UNIXTIME(1791244800),'old')", 930000 + index);
		assert(db_insert(mysql, LOCAL, query));
		spine_snprintf(query, sizeof(query), "INSERT INTO poller_output_boost(local_data_id,rrd_name,time,output) VALUES(%i,'owned',FROM_UNIXTIME(1791244800),'old')", 930000 + index);
		assert(db_insert(mysql, LOCAL, query));
	}
	spine_snprintf(query, sizeof(query), "CREATE TRIGGER spine_owned_output_reject BEFORE INSERT ON %s FOR EACH ROW BEGIN IF NEW.local_data_id=930002 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='owned output rejection'; END IF; END", boost_failure ? "poller_output_boost" : "poller_output");
	assert(db_insert(mysql, LOCAL, query));
	poller_thread_t *work = calloc(1, sizeof(*work));
	assert(work != NULL);
	reset_output_work(work, rows, partitions);
	poller_thread_t **owned_details = calloc(1, sizeof(*owned_details));
	assert(owned_details != NULL);
	owned_details[0] = work;
	details = owned_details;
	if (partitions == 2) {
		/* Failure finishes before the other partition even selects its rows. */
		run_output_partition(work, 2);
		fprintf(stderr, "output failure partition: exit=%i threads=%i complete=%i failed=%i\n", set.exit.exit_code, work->threads_complete, work->complete, work->output_failed);
		assert(work->threads_complete == 1 && !work->complete);
		assert(set.exit.exit_code == EXIT_FAILURE);
	}
	run_output_partition(work, 1);
	fprintf(stderr, "output persistence scenario=%i boundary=%i rows=%i exit=%i completed=%i\n", scenario, boundary, rows, set.exit.exit_code, work->complete);
	assert(set.exit.exit_code == EXIT_FAILURE);
	assert(work->output_failed && !work->complete && work->threads_complete == partitions);
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=0");
	assert(output_count(mysql, query) == (unsigned long long) rows);
	assert(output_count(mysql, "SELECT COUNT(*) FROM host_errors WHERE host_id=901") == 0);
	assert_sample(mysql, "poller_output", 930000, "'unchanged'");
	assert_sample(mysql, "poller_output_boost", 930000, "'unchanged'");
	const char *failed_table = boost_failure ? "poller_output_boost" : "poller_output";
	const char *other_table = boost_failure ? "poller_output" : "poller_output_boost";
	assert_sample(mysql, failed_table, 930002, "'old'");
	char expected[100];
	spine_snprintf(expected, sizeof(expected), "CONCAT(REPEAT('0',%i),'123')", boundary ? payload - 3 : 0);
	assert_sample(mysql, other_table, 930002, expected);
	if (boundary) {
		/* Sample bytes alone exceed the configured batch limit, so the
		 * failure is in an early flush and later writes still execute. */
		assert((size_t) rows * (size_t) payload > MAX_MYSQL_BUF_SIZE);
		assert_sample(mysql, failed_table, 930000 + rows, expected);
		assert_sample(mysql, "poller_output", 930001, expected);
	}
	assert(db_insert(mysql, LOCAL, "DROP TRIGGER spine_owned_output_reject"));
	/* This controlled retry reuses its timestamp and resets completion/exit
	 * state. It proves same-key upsert repair, including partial MEMORY rows;
	 * a later CLI invocation recollects data with the current timestamp. */
	reset_output_work(work, rows, partitions);
	if (partitions == 2) run_output_partition(work, 2);
	run_output_partition(work, 1);
	assert(set.exit.exit_code == EXIT_SUCCESS && !work->output_failed && work->complete);
	assert(work->threads_complete == partitions);
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output WHERE local_data_id BETWEEN 930001 AND %i AND output=%s", 930000 + rows, expected);
	assert(output_count(mysql, query) == (unsigned long long) rows);
	spine_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id BETWEEN 930001 AND %i AND output=%s", 930000 + rows, expected);
	assert(output_count(mysql, query) == (unsigned long long) rows);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 AND rrd_next_step=295") == (unsigned long long) rows);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id BETWEEN 930000 AND 939999") == (unsigned long long) rows + 1);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id BETWEEN 930000 AND 939999") == (unsigned long long) rows + 1);
	details = previous_details;
	free(owned_details);
	free(work);
}

void test_output_write_contracts(MYSQL *mysql) {
	config_t previous = set;
	pool_t *previous_pool = db_pool_local;
	poller_thread_t **previous_details = details;
	php_t *previous_servers = php_processes;
	int *previous_debug = debug_devices;
	static int owned_debug[100];
	debug_devices = owned_debug;
	assert_output_engine(mysql, "poller_output", "MEMORY");
	assert_output_engine(mysql, "poller_output_boost", "InnoDB");
	assert(output_count(mysql, "SELECT COUNT(*) FROM host WHERE id=901") == 0);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_item WHERE host_id=901 OR local_data_id BETWEEN 930000 AND 939999") == 0);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output WHERE local_data_id BETWEEN 930000 AND 939999") == 0);
	assert(output_count(mysql, "SELECT COUNT(*) FROM poller_output_boost WHERE local_data_id BETWEEN 930000 AND 939999") == 0);
	set.poller.threads = 1;
	set.poller.poller_id = 1;
	set.poller.mode = REMOTE_OFFLINE;
	set.poller.active_profiles = 2;
	set.poller.poller_interval = 5;
	set.poller.SQL_readonly = FALSE;
	set.availability.ping_only = FALSE;
	set.snmp.total_snmp_ports = 0;
	set.snmp.mibs = FALSE;
	set.boost.boost_enabled = TRUE;
	set.boost.boost_redirect = TRUE;
	set.logging.spine_log_level = 0;
	set.logging.log_destination = 0;
	set.php.script_timeout = 5;
	set.php.php_servers = 1;
	set.php.php_current_server = 0;
	set.php.php_initialized = TRUE;
	set.php.php_required = TRUE;
	db_pool_local = calloc(1, sizeof(*db_pool_local));
	assert(db_pool_local != NULL);
	db_create_connection_pool(LOCAL);
	assert(spine_permits_init(&available_threads, 1) == 0);
	assert(spine_permits_init(&available_scripts, 2) == 0);
	php_t server = {0};
	int payload = RESULTS_BUFFER - 2 < 400 ? RESULTS_BUFFER - 2 : 400;
	assert(payload >= 3);
	pid_t producer = start_output_server(&server, payload);
	php_processes = &server;
	assert(db_insert(mysql, LOCAL, "INSERT INTO host(id,hostname,availability_method,snmp_version,status_fail_date,status_rec_date) VALUES(901,'127.0.0.1',0,0,'2026-10-06 00:00:00','2026-10-06 00:00:00')"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_output(local_data_id,rrd_name,time,output) VALUES(930000,'sentinel',FROM_UNIXTIME(1791244800),'unchanged')"));
	assert(db_insert(mysql, LOCAL, "INSERT INTO poller_output_boost(local_data_id,rrd_name,time,output) VALUES(930000,'sentinel',FROM_UNIXTIME(1791244800),'unchanged')"));
	for (int scenario = 0; scenario < 4; scenario++) {
		run_output_failure_scenario(mysql, scenario, payload);
		assert(details == previous_details);
	}
	test_output_recollection(mysql);
	test_concurrent_output_failure(mysql);
	test_remote_output_destination(mysql);
	assert(close(server.php_write_fd) == 0);
	int status;
	assert(waitpid(producer, &status, 0) == producer);
	assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	assert(close(server.php_read_fd) == 0);
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_item WHERE host_id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM host WHERE id=901"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output WHERE local_data_id BETWEEN 930000 AND 939999"));
	assert(db_insert(mysql, LOCAL, "DELETE FROM poller_output_boost WHERE local_data_id BETWEEN 930000 AND 939999"));
	assert(spine_permits_destroy(&available_scripts) == 0);
	assert(spine_permits_destroy(&available_threads) == 0);
	db_close_connection_pool(LOCAL);
	db_pool_local = previous_pool;
	details = previous_details;
	php_processes = previous_servers;
	debug_devices = previous_debug;
	set = previous;
	puts("production output write failure and retry regressions passed");
}
