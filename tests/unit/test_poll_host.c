/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
/* Drives the shipped poll_host() without a database or an SNMP agent.
 *
 * GNU ld --wrap replaces the database and SNMP calls that poller.o makes into
 * sql.o, snmp.o and the client library with an in-memory fake, so the flush,
 * reindex and completion paths run in an unprivileged "make check".  The live
 * suites in tests/test_spine_*.c cover the same paths against real servers.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include "internal/common.h"
#include "app/spine.h"
#include "tests/support/child_run.h"
#include "config/settings_internal.h"

#define HOST_COLUMNS 37
#define REINDEX_COLUMNS 5
#define ITEM_COLUMNS 21
#define MAX_FAKE_ROWS 4
#define MAX_QUERIES 64

extern poller_thread_t **details;

typedef struct {
	char **rows[MAX_FAKE_ROWS];
	int count;
	int columns;
	int next;
} fake_result_t;

static struct {
	const char *host[HOST_COLUMNS];
	char reindex[MAX_FAKE_ROWS][REINDEX_COLUMNS][BUFSIZE];
	int reindex_count;
	const char *items[MAX_FAKE_ROWS][ITEM_COLUMNS];
	int item_count;
	const char *multi_value;
	const char *engine_uptime;
	const char *legacy_uptime;
	int session_opens;
	int session_timeouts[MAX_QUERIES];
	char session_hostnames[MAX_QUERIES][BUFSIZE];
	char *queries[MAX_QUERIES];
	int query_count;
	int completion_queries;
	int completion_queries_locked;
	int session_fail_at;
	bool multi_ignores_host;
	bool drop_leases;
	db_lease_t *leases[2];
	int lease_releases;
	int fail_poll_allocation;
	int poll_allocations_seen;
	bool poll_allocations_armed;
	size_t fail_calloc_size;
	const char *settings[2][2];
	int setting_count;
	size_t fail_calloc_rows;
	const char *fail_strdup_text;
	int fail_strdup_skip;
	const char *host_time;
} fake;

static pool_t fake_pool;
static int fake_session;

static void reset_fake(void) {
	for (int i = 0; i < fake.query_count; i++) free(fake.queries[i]);
	memset(&fake, 0, sizeof(fake));
}

static void capture(const char *query) {
	assert_true(fake.query_count < MAX_QUERIES);
	fake.queries[fake.query_count] = strdup(query);
	assert_non_null(fake.queries[fake.query_count]);
	fake.query_count++;
}

static int captured(const char *needle) {
	int found = 0;
	for (int i = 0; i < fake.query_count; i++) {
		if (strstr(fake.queries[i], needle) != NULL) found++;
	}
	return found;
}

static fake_result_t *make_result(int count, int columns, const char *(*cell)(int, int)) {
	fake_result_t *result = calloc(1, sizeof(*result));
	assert_non_null(result);
	result->count = count;
	result->columns = columns;
	for (int row = 0; row < count; row++) {
		result->rows[row] = calloc((size_t)columns, sizeof(char *));
		assert_non_null(result->rows[row]);
		for (int column = 0; column < columns; column++) {
			const char *value = cell(row, column);
			result->rows[row][column] = value == NULL ? NULL : strdup(value);
		}
	}
	return result;
}

static const char *host_cell(int row, int column) {
	(void) row;
	return fake.host[column];
}

static const char *reindex_cell(int row, int column) {
	return fake.reindex[row][column];
}

static const char *item_cell(int row, int column) {
	return fake.items[row][column];
}

static const char *setting_cell(int row, int column) {
	return fake.settings[row][column];
}

/* Persist the one write the next cycle reads back: the reindex baseline. */
static void apply_reindex_update(const char *query) {
	const char *prefix = "UPDATE poller_reindex SET assert_value='";
	if (strncmp(query, prefix, strlen(prefix)) != 0) return;
	const char *value = query + strlen(prefix);
	const char *end = strchr(value, '\'');
	assert_non_null(end);
	snprintf(fake.reindex[0][3], sizeof(fake.reindex[0][3]), "%.*s", (int)(end - value), value);
}

/* Device completion writes must not hold LOCK_THDET while they wait on the
 * server, whichever db_* call carries them. */
static void observe_completion(const char *query) {
	if (strncmp(query, "UPDATE poller_item SET rrd_next_step", 36) == 0 ||
		strncmp(query, "UPDATE host SET polling_time", 28) == 0 ||
		strncmp(query, "INSERT INTO host_errors", 23) == 0) {
		fake.completion_queries++;
		if (thread_mutex_trylock(LOCK_THDET) == 0) thread_mutex_unlock(LOCK_THDET);
		else fake.completion_queries_locked++;
	}
}

/* A lease can be lost while a device is polled; the cleanup then finds
 * nothing to release. */
static void lose_leases(void) {
	for (int i = 0; i < 2; i++) {
		if (fake.leases[i] != NULL) fake.leases[i]->connection = NULL;
	}
}

MYSQL_RES *__wrap_db_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	if (strstr(query, "FROM settings") != NULL) {
		return (MYSQL_RES *) make_result(fake.setting_count, 2, setting_cell);
	}
	if (strstr(query, "FROM host WHERE id") != NULL) {
		return (MYSQL_RES *) make_result(1, HOST_COLUMNS, host_cell);
	}
	if (strstr(query, "FROM poller_reindex") != NULL) {
		return (MYSQL_RES *) make_result(fake.reindex_count, REINDEX_COLUMNS, reindex_cell);
	}
	if (strstr(query, "SELECT SQL_NO_CACHE action") != NULL) {
		if (fake.drop_leases) lose_leases();
		return (MYSQL_RES *) make_result(fake.item_count, ITEM_COLUMNS, item_cell);
	}
	capture(query);
	observe_completion(query);
	return NULL;
}

int __wrap_db_insert(MYSQL *mysql, int type, const char *query) {
	(void) mysql;
	(void) type;
	capture(query);
	observe_completion(query);
	apply_reindex_update(query);
	return TRUE;
}

void __wrap_db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	(void) mysql;
	if (input == NULL || output == NULL || max_size <= 0) return;
	snprintf(output, (size_t) max_size, "%s", input);
}

bool __wrap_db_acquire_lease(int type, db_lease_t *lease) {
	lease->type = type;
	lease->connection = &fake_pool;
	if (fake.fail_poll_allocation != 0) fake.poll_allocations_armed = TRUE;
	if (type == LOCAL || type == REMOTE) fake.leases[type == LOCAL ? 0 : 1] = lease;
	return TRUE;
}

bool __wrap_db_release_lease(db_lease_t *lease) {
	fake.lease_releases++;
	lease->connection = NULL;
	return TRUE;
}

/* poll_host() allocates its host, ping and reindex records in that order.
 * An optimizing compiler turns malloc plus memset into calloc(1, size), so
 * both entry points count them, in either argument order, and only after the database lease is taken. */
static bool fail_this_poll_allocation(size_t size) {
	if (!fake.poll_allocations_armed) return FALSE;
	if (size != sizeof(host_t) && size != sizeof(ping_t) && size != sizeof(reindex_t)) return FALSE;
	return ++fake.poll_allocations_seen == fake.fail_poll_allocation;
}

extern void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size) {
	if (fail_this_poll_allocation(size)) return NULL;
	return __real_malloc(size);
}

extern void *__real_calloc(size_t count, size_t size);
void *__wrap_calloc(size_t count, size_t size) {
	/* the optimizer emits calloc(size, 1) as often as calloc(1, size) */
	size_t bytes = count == 1 ? size : (size == 1 ? count : 0);

	if (bytes != 0 && fail_this_poll_allocation(bytes)) return NULL;
	if (fake.fail_calloc_size != 0 && size == fake.fail_calloc_size) {
		fake.fail_calloc_size = 0;
		return NULL;
	}
	/* the settings cache allocates one name/value pair per row */
	if (fake.fail_calloc_rows != 0 && count == fake.fail_calloc_rows && size == 2 * sizeof(char *)) {
		fake.fail_calloc_rows = 0;
		return NULL;
	}
	return __real_calloc(count, size);
}

extern char *__real_strdup(const char *text);
char *__wrap_strdup(const char *text) {
	if (fake.fail_strdup_text != NULL && strcmp(text, fake.fail_strdup_text) == 0) {
		/* the fake result set copies the same text before the code under test does */
		if (fake.fail_strdup_skip-- > 0) return __real_strdup(text);
		fake.fail_strdup_text = NULL;
		return NULL;
	}
	return __real_strdup(text);
}

void __wrap_db_free_result(MYSQL_RES *opaque) {
	fake_result_t *result = (fake_result_t *) opaque;
	if (result == NULL) return;
	for (int row = 0; row < result->count; row++) {
		for (int column = 0; column < result->columns; column++) free(result->rows[row][column]);
		free(result->rows[row]);
	}
	free(result);
}

uint64_t __wrap_mysql_num_rows(MYSQL_RES *opaque) {
	return (uint64_t) ((fake_result_t *) opaque)->count;
}

MYSQL_ROW __wrap_mysql_fetch_row(MYSQL_RES *opaque) {
	fake_result_t *result = (fake_result_t *) opaque;
	if (result->next >= result->count) return NULL;
	return result->rows[result->next++];
}

void *__wrap_snmp_host_init(const snmp_connection_t *options) {
	assert_true(fake.session_opens < MAX_QUERIES);
	if (fake.session_fail_at == fake.session_opens + 1) {
		fake.session_opens++;
		return NULL;
	}
	fake.session_timeouts[fake.session_opens] = options->snmp_timeout;
	snprintf(fake.session_hostnames[fake.session_opens], BUFSIZE, "%s", options->hostname);
	fake.session_opens++;
	return &fake_session;
}

void __wrap_snmp_host_cleanup(void *session) {
	assert_ptr_equal(session, &fake_session);
}

/* Mirrors snmp_get_base(): a failure is "" when allowed and U otherwise. */
static char *fake_get(host_t *host, const char *oid, bool should_fail) {
	const char *value = NULL;
	if (strcmp(oid, ".1.3.6.1.6.3.10.2.1.3.0") == 0) value = fake.engine_uptime;
	else if (strcmp(oid, ".1.3.6.1.2.1.1.3.0") == 0) value = fake.legacy_uptime;
	else value = "fake-system-field";
	if (value == NULL) {
		if (should_fail) host->ignore_host = TRUE;
		value = should_fail ? "U" : "";
	}
	char *output = calloc(RESULTS_BUFFER, 1);
	assert_non_null(output);
	snprintf(output, RESULTS_BUFFER, "%s", value);
	return output;
}

char *__wrap_snmp_get_base(host_t *host, char *oid, bool should_fail) {
	return fake_get(host, oid, should_fail);
}

char *__wrap_snmp_get(host_t *host, char *oid) {
	return fake_get(host, oid, TRUE);
}

char *__wrap_snmp_get_allow_fail(host_t *host, char *oid) {
	return fake_get(host, oid, FALSE);
}

void __wrap_snmp_get_multi(host_t *host, const target_t *items, snmp_oids_t *oids, int count) {
	(void) items;
	if (fake.multi_ignores_host) host->ignore_host = TRUE;
	for (int i = 0; i < count; i++) {
		snprintf(oids[i].result, sizeof(oids[i].result), "%s", fake.multi_value);
	}
}

int __wrap_ping_host(host_t *host, ping_t *ping) {
	(void) host;
	(void) ping;
	return HOST_UP;
}

static void set_host(const char *community, const char *max_oids, int availability) {
	static char method[16];
	snprintf(method, sizeof(method), "%d", availability);
	fake.host[0] = "47";
	fake.host[1] = "127.0.0.1";
	fake.host[2] = community;
	fake.host[3] = "2";
	fake.host[11] = "161";
	fake.host[12] = "500";
	fake.host[13] = max_oids;
	fake.host[14] = method;
	fake.host[21] = "0";
	fake.host[22] = "0";
}

static void add_reindex(int action, const char *op, const char *assert_value, const char *arg1) {
	int row = fake.reindex_count++;
	snprintf(fake.reindex[row][0], BUFSIZE, "7");
	snprintf(fake.reindex[row][1], BUFSIZE, "%d", action);
	snprintf(fake.reindex[row][2], BUFSIZE, "%s", op);
	snprintf(fake.reindex[row][3], BUFSIZE, "%s", assert_value);
	snprintf(fake.reindex[row][4], BUFSIZE, "%s", arg1);
}

static void add_snmp_item(const char *local_data_id, const char *rrd_name, const char *community,
	const char *version, const char *regex) {
	const char **row = fake.items[fake.item_count++];
	row[0] = "0";
	row[1] = "127.0.0.1";
	row[2] = community;
	row[3] = version;
	row[6] = rrd_name;
	row[8] = ".1.3.6.1.2.1.1.3.0";
	row[11] = local_data_id;
	row[13] = "161";
	row[14] = "500";
	row[20] = regex;
}

static void add_script_item(const char *local_data_id, const char *rrd_name, const char *command) {
	const char **row = fake.items[fake.item_count++];
	row[0] = "1";
	row[6] = rrd_name;
	row[8] = command;
	row[11] = local_data_id;
}

static int run_poll(void) {
	poller_thread_t work = {0};
	poller_thread_t *device = &work;
	int errors = 0;
	work.host_id = 47;
	work.host_thread = 1;
	work.host_threads = 1;
	work.host_data_ids = 0;
	work.host_time_double = get_time_as_double();
	STRNCOPY(work.host_time, fake.host_time != NULL ? fake.host_time : "1791158400");
	details = &device;
	poll_host(&work, &errors);
	details = NULL;
	assert_true(work.complete);
	return errors;
}

static int setup(void **state) {
	(void) state;
	reset_fake();
	config_defaults();
	set.poller.poller_id = 1;
	set.poller.threads = 1;
	set.poller.active_profiles = 1;
	set.poller.mode = REMOTE_OFFLINE;
	set.php.script_timeout = 2;
	set.hosts.has_output_regex = TRUE;
	set.snmp.total_snmp_ports = 1;
	fake_pool.free = TRUE;
	return 0;
}

/* Each item leaves through a different flush. 601 goes out when the batch is
 * full (max_oids=1) or when 602's credentials differ; 602 is the final flush.
 * All three apply the same regex, to the normalized value, and spike kill. */
static void test_flush_paths_agree(void **state) {
	(void) state;
	for (int scenario = 0; scenario < 4; scenario++) {
		bool full_batch = (scenario & 1) != 0;
		bool spike = (scenario & 2) != 0;
		setup(NULL);
		set_host("regression", full_batch ? "1" : "5", AVAIL_NONE);
		add_snmp_item("601", "a", "regression", "2", "^[0-9][0-9]*");
		add_snmp_item("602", "b", "regression", full_batch ? "2" : "1", "^[0-9][0-9]*");
		if (spike) add_reindex(POLLER_ACTION_SCRIPT, "<", "124", "/usr/bin/printf 123");
		fake.multi_value = "00 00 01 0A";
		run_poll();
		const char *value = spike ? "'U')" : "'266')";
		char row[128];
		snprintf(row, sizeof(row), "(601, 'a', FROM_UNIXTIME(1791158400), %s", value);
		print_message("scenario %d full_batch=%d spike=%d\n", scenario, full_batch, spike);
		assert_int_equal(captured(row), 1);
		snprintf(row, sizeof(row), "(602, 'b', FROM_UNIXTIME(1791158400), %s", value);
		assert_int_equal(captured(row), 1);
	}
}

/* A community longer than the old 49-byte key must still batch. */
static void test_long_community_batches(void **state) {
	static const char community[] = "regression-community-wider-than-the-old-fifty-byte-batch-key";
	(void) state;
	set_host(community, "10", AVAIL_NONE);
	add_snmp_item("611", "a", community, "2", NULL);
	add_snmp_item("612", "b", community, "2", NULL);
	add_snmp_item("613", "c", community, "2", NULL);
	fake.multi_value = "42";
	assert_int_equal(run_poll(), 0);
	/* one session for the device checks, one for the single batch */
	assert_int_equal(fake.session_opens, 2);
	assert_int_equal(captured("'42')"), 1);
}

static void test_snmp_batches_on_hostname(void **state) {
	(void) state;
	set_host("regression", "10", AVAIL_NONE);
	add_snmp_item("621", "a", "regression", "2", NULL);
	add_snmp_item("622", "b", "regression", "2", NULL);
	fake.items[1][1] = "127.0.0.2";
	fake.multi_value = "42";
	assert_int_equal(run_poll(), 0);
	assert_int_equal(fake.session_opens, 3);
	assert_string_equal(fake.session_hostnames[1], "127.0.0.1");
	assert_string_equal(fake.session_hostnames[2], "127.0.0.2");
}

/* SNMPv3 items batch on every credential field; a different context
 * starts a new session. */
static void test_snmpv3_batches_on_profile(void **state) {
	(void) state;
	set_host("regression", "10", AVAIL_NONE);
	add_snmp_item("631", "a", "", "3", NULL);
	add_snmp_item("632", "b", "", "3", NULL);
	add_snmp_item("633", "c", "", "3", NULL);
	for (int i = 0; i < 3; i++) {
		fake.items[i][4] = "regression-user";
		fake.items[i][5] = "regression-pass";
		fake.items[i][15] = "SHA";
		fake.items[i][16] = "regression-priv";
		fake.items[i][17] = "AES";
		fake.items[i][19] = "80001f8880";
	}
	fake.items[0][18] = "one";
	fake.items[1][18] = "one";
	fake.items[2][18] = "two";
	fake.multi_value = "7";
	assert_int_equal(run_poll(), 0);
	/* device session, then one per distinct profile */
	assert_int_equal(fake.session_opens, 3);
	assert_int_equal(captured("(633, 'c', FROM_UNIXTIME(1791158400), '7')"), 1);
}

/* Otherwise identical items share a session only while their timeouts match. */
static void test_snmp_batches_on_timeout(void **state) {
	(void) state;
	set_host("regression", "10", AVAIL_NONE);
	add_snmp_item("641", "a", "regression", "2", NULL);
	add_snmp_item("642", "b", "regression", "2", NULL);
	add_snmp_item("643", "c", "regression", "2", NULL);
	fake.items[2][14] = "1500";
	fake.multi_value = "7";
	assert_int_equal(run_poll(), 0);
	assert_int_equal(fake.session_opens, 3);
	assert_int_equal(fake.session_timeouts[1], 500);
	assert_int_equal(fake.session_timeouts[2], 1500);
	assert_int_equal(captured("(643, 'c', FROM_UNIXTIME(1791158400), '7')"), 1);
}

/* Good baseline, unreadable cycle, reboot: the reboot must still fire. */
static void test_uptime_baseline_survives_unknown(void **state) {
	static const struct {
		const char *engine;
		const char *legacy;
		int commands;
		const char *stored;
	} cycles[] = {
		{"5", NULL, 0, "500"},
		{NULL, NULL, 0, "500"},
		/* a negative engine time is not an uptime; the legacy OID answers */
		{"-5", "600", 0, "600"},
		{"4096 Bytes", "600", 0, "600"},
		{"3.5", "600", 0, "600"},
		{"3e2", "600", 0, "600"},
		{"+3", "600", 0, "600"},
		{"", "4096 Bytes", 0, "600"},
		{"18446744073709551616", "600", 0, "600"},
		{"18446744073709551615", "600", 0, "600"},
		{" \t6\r\n", NULL, 0, "600"},
		{"1", NULL, 1, "100"},
	};
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_reindex(POLLER_ACTION_SNMP, "<", "0", ".1.3.6.1.2.1.1.3.0");
	for (size_t i = 0; i < sizeof(cycles) / sizeof(cycles[0]); i++) {
		for (int q = 0; q < fake.query_count; q++) free(fake.queries[q]);
		fake.query_count = 0;
		fake.engine_uptime = cycles[i].engine;
		fake.legacy_uptime = cycles[i].legacy;
		run_poll();
		print_message("cycle %zu stored=%s\n", i, fake.reindex[0][3]);
		assert_int_equal(captured("REPLACE INTO poller_command"), cycles[i].commands);
		assert_string_equal(fake.reindex[0][3], cycles[i].stored);
	}
}

/* Padded script output is trimmed, then freed through its own pointer; the
 * device's error list starts empty, and completion writes run unlocked. */
static void test_script_reindex_and_completion(void **state) {
	(void) state;
	set_host("", "5", AVAIL_NONE);
	set.logging.spine_log_level = 1;
	set.poller.active_profiles = 2;
	set.poller.poller_interval = 300;
	add_reindex(POLLER_ACTION_SCRIPT, "=", "122", "/usr/bin/printf ' 123'");
	add_script_item("621", "a", "/usr/bin/printf 123");
	assert_int_equal(run_poll(), 1);
	assert_int_equal(captured("REPLACE INTO poller_command"), 1);
	assert_string_equal(fake.reindex[0][3], "123");
	assert_int_equal(captured("VALUES(47, 1, 1, '')"), 1);
	assert_int_equal(fake.completion_queries, 3);
	assert_int_equal(fake.completion_queries_locked, 0);
}

/* sysUpTimeInstance takes the engine time in ticks when both OIDs read, and
 * ignores an uptime that is not a whole non-negative number. */
static void test_system_uptime(void **state) {
	static const struct {
		const char *legacy;
		const char *engine;
		const char *stored;
	} cases[] = {
		{"4200", "42", "snmp_sysUpTimeInstance='4200'"},
		{"4200", "-1", "snmp_sysUpTimeInstance='4200'"},
		{"-5", "42", "snmp_sysUpTimeInstance='0'"},
		{"4096 Bytes", "42", "snmp_sysUpTimeInstance='0'"},
		{"4200", "4096 Bytes", "snmp_sysUpTimeInstance='4200'"},
		{"4200", "18446744073709551615", "snmp_sysUpTimeInstance='4200'"},
		{"18446744073709551616", "42", "snmp_sysUpTimeInstance='0'"},
		{" \t4200\r\n", " \t42\r\n", "snmp_sysUpTimeInstance='4200'"},
	};
	(void) state;
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		setup(NULL);
		set.snmp.mibs = TRUE;
		set_host("regression", "5", AVAIL_SNMP);
		fake.legacy_uptime = cases[i].legacy;
		fake.engine_uptime = cases[i].engine;
		run_poll();
		print_message("case %zu\n", i);
		assert_int_equal(captured(cases[i].stored), 1);
	}
}

static void add_action_item(const char *action, const char *local_data_id, const char *rrd_name, const char *command) {
	const char **row = fake.items[fake.item_count++];
	row[0] = action;
	row[6] = rrd_name;
	row[8] = command;
	row[11] = local_data_id;
}

static int count_unknown_results(void) {
	return captured("'U')");
}

/* At the detailed log level an invalid SNMP value is reported with the
 * device, data source and OID, and is still counted and stored as unknown. */
static void test_invalid_snmp_value_is_reported_and_discarded(void **state) {
	(void) state;
	set.logging.spine_log_level = 2;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("651", "a", "regression", "2", NULL);
	fake.multi_value = "not a number";

	assert_int_equal(run_poll(), 1);
	assert_int_equal(captured("(651, 'a', FROM_UNIXTIME(1791158400), 'U')"), 1);
}

/* A batch that times out marks the device ignored; its values are unknown
 * whatever the agent state was before. */
static void test_values_of_an_ignored_device_are_unknown(void **state) {
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("661", "a", "regression", "2", NULL);
	add_snmp_item("662", "b", "regression", "2", NULL);
	fake.multi_value = "42";
	fake.multi_ignores_host = TRUE;

	run_poll();
	assert_int_equal(captured("(661, 'a', FROM_UNIXTIME(1791158400), 'U')"), 1);
	assert_int_equal(captured("(662, 'b', FROM_UNIXTIME(1791158400), 'U')"), 1);
}

static void test_empty_script_commands_are_skipped(void **state) {
	(void) state;
	set_host("", "5", AVAIL_NONE);
	add_action_item("1", "671", "a", "");
	add_action_item("2", "672", "b", "");

	assert_int_equal(run_poll(), 0);
	assert_int_equal(count_unknown_results(), 1);
	assert_int_equal(captured("(671, 'a', FROM_UNIXTIME(1791158400), 'U')"), 1);
	assert_int_equal(captured("(672, 'b', FROM_UNIXTIME(1791158400), 'U')"), 1);
}

static void test_unknown_poller_action_is_recorded_as_unknown(void **state) {
	(void) state;
	set_host("", "5", AVAIL_NONE);
	add_action_item("9", "681", "a", "unsupported-action-argument");

	assert_int_equal(run_poll(), 0);
	assert_int_equal(captured("(681, 'a', FROM_UNIXTIME(1791158400), 'U')"), 1);
}

static void test_failed_item_session_ignores_the_device(void **state) {
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("691", "a", "regression", "2", NULL);
	add_snmp_item("692", "b", "regression", "2", NULL);
	fake.multi_value = "42";
	/* the first open is the device check, the second is the item batch */
	fake.session_fail_at = 2;

	run_poll();
	assert_int_equal(fake.session_opens, 2);
	assert_int_equal(captured("'42')"), 0);
}

static void test_lost_leases_are_not_released_twice(void **state) {
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("701", "a", "regression", "2", NULL);
	fake.multi_value = "42";
	fake.drop_leases = TRUE;

	run_poll();
	assert_int_equal(fake.lease_releases, 0);

	reset_fake();
	set_host("regression", "5", AVAIL_NONE);
	set.poller.poller_id = 2;
	set.poller.mode = REMOTE_ONLINE;
	add_snmp_item("702", "a", "regression", "2", NULL);
	fake.multi_value = "42";
	fake.drop_leases = TRUE;

	run_poll();
	assert_int_equal(fake.lease_releases, 0);
}

static void poll_without_memory(void) {
	run_poll();
}

static void test_poll_structure_allocation_failures_are_fatal(void **state) {
	int record;

	(void) state;
	for (record = 1; record <= 3; record++) {
		setup(NULL);
		set_host("regression", "5", AVAIL_NONE);
		fake.fail_poll_allocation = record;
		print_message("record %d of 3\n", record);
		assert_int_equal(spine_test_run_child(poll_without_memory), EXIT_FAILURE);
	}
}

static void test_oid_table_allocation_failure_is_fatal(void **state) {
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("711", "a", "regression", "2", NULL);
	fake.fail_calloc_size = sizeof(snmp_oids_t);

	assert_int_equal(spine_test_run_child(poll_without_memory), EXIT_FAILURE);
}

/* The bulk settings load gives up quietly when memory runs out, and a
 * setting it could not copy reads as absent, not as a stale value. */
static void test_settings_cache_survives_allocation_failures(void **state) {
	MYSQL mysql;
	char *value;

	(void) state;
	memset(&mysql, 0, sizeof(mysql));
	fake.settings[0][0] = "alpha";
	fake.settings[0][1] = "1";
	fake.settings[1][0] = "beta";
	fake.settings[1][1] = "2";
	fake.setting_count = 2;

	fake.fail_calloc_rows = 2;
	settings_cache_load(&mysql, LOCAL);
	assert_int_equal(fake.fail_calloc_rows, 0);

	fake.fail_strdup_text = "alpha";
	fake.fail_strdup_skip = 1;
	settings_cache_load(&mysql, LOCAL);
	assert_null(fake.fail_strdup_text);
	assert_null(getsetting(&mysql, LOCAL, "alpha"));
	assert_null(getsetting(&mysql, LOCAL, "beta"));

	settings_cache_load(&mysql, LOCAL);
	value = getsetting(&mysql, LOCAL, "beta");
	assert_non_null(value);
	assert_string_equal(value, "2");
	free(value);
	settings_cache_free();
}

/* A cycle timestamp that is not a number cannot be written into the output
 * statement; the sample is skipped rather than the statement corrupted. */
static void test_output_with_a_malformed_timestamp_is_skipped(void **state) {
	(void) state;
	set_host("regression", "5", AVAIL_NONE);
	add_snmp_item("721", "a", "regression", "2", NULL);
	fake.multi_value = "42";
	fake.host_time = "1791158400); DROP TABLE host";

	assert_int_equal(run_poll(), 0);
	assert_int_equal(captured("(721,"), 0);
	assert_int_equal(captured("DROP TABLE"), 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_flush_paths_agree, setup),
		cmocka_unit_test_setup(test_long_community_batches, setup),
		cmocka_unit_test_setup(test_snmp_batches_on_hostname, setup),
		cmocka_unit_test_setup(test_snmpv3_batches_on_profile, setup),
		cmocka_unit_test_setup(test_snmp_batches_on_timeout, setup),
		cmocka_unit_test_setup(test_uptime_baseline_survives_unknown, setup),
		cmocka_unit_test_setup(test_script_reindex_and_completion, setup),
		cmocka_unit_test_setup(test_system_uptime, setup),
		cmocka_unit_test_setup(test_invalid_snmp_value_is_reported_and_discarded, setup),
		cmocka_unit_test_setup(test_values_of_an_ignored_device_are_unknown, setup),
		cmocka_unit_test_setup(test_empty_script_commands_are_skipped, setup),
		cmocka_unit_test_setup(test_unknown_poller_action_is_recorded_as_unknown, setup),
		cmocka_unit_test_setup(test_failed_item_session_ignores_the_device, setup),
		cmocka_unit_test_setup(test_lost_leases_are_not_released_twice, setup),
		cmocka_unit_test_setup(test_poll_structure_allocation_failures_are_fatal, setup),
		cmocka_unit_test_setup(test_oid_table_allocation_failure_is_fatal, setup),
		cmocka_unit_test_setup(test_settings_cache_survives_allocation_failures, setup),
		cmocka_unit_test_setup(test_output_with_a_malformed_timestamp_is_skipped, setup),
	};
	int failures;

	init_mutexes();
	assert(spine_permits_init(&available_scripts, 2) == 0);
	failures = cmocka_run_group_tests(tests, NULL, NULL);
	reset_fake();
	return failures;
}
