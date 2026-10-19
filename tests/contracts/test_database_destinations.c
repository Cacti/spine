/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal/common.h"
#include "app/spine.h"
#include "database/cacti_query.h"
#include "database/persistence.h"
#include "config/settings_internal.h"

static void stored(MYSQL *connection, const char *query, const char *expected) {
	MYSQL_RES *result = db_query(connection, LOCAL, query);
	MYSQL_ROW row;
	if (result == NULL || mysql_num_rows(result) != 1) fprintf(stderr, "destination fixture query did not return one row: %s\n", query);
	assert(result != NULL && mysql_num_rows(result) == 1);
	row = mysql_fetch_row(result);
	assert(row != NULL && row[0] != NULL && strcmp(row[0], expected) == 0);
	db_free_result(result);
}

static void sql_log_contract(MYSQL *connection) {
	FILE *capture = tmpfile();
	int saved_stdout;
	int destination = set.logging.log_destination;
	int level = set.logging.log_level;
	char contents[LRG_BUFSIZE];
	size_t bytes;

	assert(capture != NULL);
	fflush(stdout);
	saved_stdout = dup(STDOUT_FILENO);
	assert(saved_stdout >= 0);
	assert(dup2(fileno(capture), STDOUT_FILENO) >= 0);
	set.logging.log_destination = LOGDEST_STDOUT;
	set.logging.log_level = POLLER_VERBOSITY_DEVDBG;
	assert(db_query(connection, LOCAL, "SELECT fixture_sql_secret") == NULL);
	assert(db_insert(connection, LOCAL, "INSERT INTO settings(name,value) VALUES('sql_log_fixture','fixture_sql_secret')"));
	fflush(stdout);
	assert(dup2(saved_stdout, STDOUT_FILENO) >= 0);
	close(saved_stdout);
	set.logging.log_destination = destination;
	set.logging.log_level = level;
	rewind(capture);
	bytes = fread(contents, 1, sizeof(contents) - 1, capture);
	contents[bytes] = '\0';
	fclose(capture);
	assert(strstr(contents, "Database Error") != NULL);
	assert(strstr(contents, "fixture_sql_secret") == NULL);
	assert(db_insert(connection, LOCAL, "DELETE FROM settings WHERE name='sql_log_fixture'"));
}

static void output_contract(MYSQL *local, MYSQL *remote, int mode) {
	poller_queries_t queries;
	target_t item = {0};
	poll_output_buffers_t buffers;
	MYSQL *destination = mode == REMOTE_ONLINE ? remote : local;
	const char *values[] = {"42", "updated'\\value"};
	size_t i;
	sql_log_contract(destination);
	/* Settings writes must use this connection's vendor, even when the local
	 * server advertised a different upsert mode. */
	set.database.onupdate = mysql_get_server_version(destination) < 80019;
	assert(putsetting(destination, mode == REMOTE_ONLINE ? REMOTE : LOCAL, "destination_fixture", "first"));
	stored(destination, "SELECT value FROM settings WHERE name='destination_fixture'", "first");
	assert(putsetting(destination, mode == REMOTE_ONLINE ? REMOTE : LOCAL, "destination_fixture", "second"));
	stored(destination, "SELECT value FROM settings WHERE name='destination_fixture'", "second");
	set.poller.mode = mode;
	set.boost.boost_enabled = set.boost.boost_redirect = TRUE;
	poller_prepare_queries(&queries, 991, 1, 0);
	item.local_data_id = 991;
	strcpy(item.rrd_name, "value");
	assert(db_insert(destination, LOCAL, "DELETE FROM poller_output") == TRUE);
	assert(db_insert(destination, LOCAL, "DELETE FROM poller_output_boost") == TRUE);
	for (i = 0; i < 2; i++) {
		strcpy(item.result, values[i]);
		buffers = write_poll_results(local, remote, &queries, &item, 1, "1791676800");
		assert(!buffers.failed);
		free(buffers.output);
		free(buffers.boost);
		stored(destination, "SELECT output FROM poller_output WHERE local_data_id=991", values[i]);
		stored(destination, "SELECT output FROM poller_output_boost WHERE local_data_id=991", values[i]);
		stored(destination, "SELECT COUNT(*) FROM poller_output", "1");
	}
}

static void transfer_contract(MYSQL *source, MYSQL *destination) {
	assert(db_insert(source, LOCAL, "DELETE FROM host") == TRUE);
	assert(db_insert(source, LOCAL, "DELETE FROM poller_item") == TRUE);
	assert(db_insert(destination, REMOTE, "DELETE FROM host") == TRUE);
	assert(db_insert(destination, REMOTE, "DELETE FROM poller_item") == TRUE);
	assert(db_insert(source, LOCAL, "INSERT INTO host(id,hostname,poller_id,snmp_sysName) VALUES(991,'fixture',2,'first')") == TRUE);
	assert(db_insert(source, LOCAL, "INSERT INTO poller_item(local_data_id,host_id,rrd_name,poller_id,rrd_next_step) VALUES(991,991,'value',2,60)") == TRUE);
	assert(poller_transfer_status(source, destination));
	stored(destination, "SELECT snmp_sysName FROM host WHERE id=991", "first");
	stored(destination, "SELECT rrd_next_step FROM poller_item WHERE local_data_id=991", "60");
	assert(db_insert(source, LOCAL, "UPDATE host SET snmp_sysName='second' WHERE id=991") == TRUE);
	assert(db_insert(source, LOCAL, "UPDATE poller_item SET rrd_next_step=120 WHERE local_data_id=991") == TRUE);
	assert(poller_transfer_status(source, destination));
	stored(destination, "SELECT snmp_sysName FROM host WHERE id=991", "second");
	stored(destination, "SELECT rrd_next_step FROM poller_item WHERE local_data_id=991", "120");
	stored(destination, "SELECT COUNT(*) FROM host", "1");
}

int main(int argc, char *argv[]) {
	MYSQL local;
	MYSQL remote;
	char suffix[BUFSIZE];
	static const char *const updates[] = {"output"};
	assert(argc == 3);
	config_defaults();
	init_mutexes();
	set.poller.poller_id = 2;
	strncopy(set.database.host, argv[1], sizeof(set.database.host));
	strncopy(set.remote_database.host, argv[2], sizeof(set.remote_database.host));
	strcpy(set.database.database, "cacti");
	strcpy(set.remote_database.database, "cacti");
	strcpy(set.database.user, "spine");
	strcpy(set.remote_database.user, "spine");
	strcpy(set.database.password, "spine");
	strcpy(set.remote_database.password, "spine");
	assert(db_connect(LOCAL, &local) && db_connect(REMOTE, &remote));
	assert(db_set_session_mode(&local) && db_set_session_mode(&remote));
	assert(db_upsert_suffix(&remote, suffix, sizeof(suffix), updates, 1));
	assert((strstr(suffix, "spine_row.output") != NULL) ==
		(strstr(mysql_get_server_info(&remote), "MariaDB") == NULL && mysql_get_server_version(&remote) >= 80019));
	output_contract(&local, &remote, REMOTE_ONLINE);
	output_contract(&local, &remote, REMOTE_OFFLINE);
	transfer_contract(&local, &remote);
	db_disconnect(&remote);
	db_disconnect(&local);
	puts("destination-aware inserts, duplicate updates, Boost and status transfers passed");
	return 0;
}
