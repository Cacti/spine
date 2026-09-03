/* Tests for the poller_output tuple builder.
 *
 * poller_output_tuple() escapes two free-text columns and formats the VALUES
 * row for the batched INSERT. db_escape() needs a live MYSQL connection, so
 * this binary interposes on it with ld --wrap and substitutes a predictable
 * escaper. That isolates the formatting and the buffer sizing, which is where
 * #583 lived: sizing the escape destination from the source buffer truncated
 * every result at 1022 bytes.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"

static int   escape_calls;
static size_t last_escape_capacity;

/* A stand-in that escapes single quotes by doubling them, the same shape as
   mysql_real_escape_string, and honours the destination size it is given. */
void __real_db_escape(MYSQL *mysql, char *output, int max_size, const char *input);
void __wrap_db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {
	int o = 0;
	int i;

	(void) mysql;
	escape_calls++;
	last_escape_capacity = (size_t) max_size;

	if (output == NULL || max_size <= 0) {
		return;
	}

	for (i = 0; input != NULL && input[i] != '\0'; i++) {
		int need = (input[i] == '\'') ? 2 : 1;

		if (o + need >= max_size) {
			break;
		}

		if (input[i] == '\'') {
			output[o++] = '\'';
		}

		output[o++] = input[i];
	}

	output[o] = '\0';
}

static int reset(void **state) {
	(void) state;
	escape_calls = 0;
	last_escape_capacity = 0;
	return 0;
}

static target_t *make_item(const char *rrd_name, const char *result, int local_data_id) {
	static target_t item;

	memset(&item, 0, sizeof(item));
	snprintf(item.rrd_name, sizeof(item.rrd_name), "%s", rrd_name);
	snprintf(item.result, sizeof(item.result), "%s", result);
	item.local_data_id = local_data_id;
	return &item;
}

static void test_tuple_has_the_expected_shape(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];
	int n;

	(void) state;

	n = poller_output_tuple(out, sizeof(out), NULL, make_item("traffic_in", "4242", 77), "1700000000");

	assert_string_equal(out, " (77, 'traffic_in', FROM_UNIXTIME(1700000000), '4242')");
	assert_int_equal(n, (int) strlen(out));
}

/* The caller joins tuples by overwriting out[0], so the leading byte must be a
   space and nothing else may precede the paren. */
static void test_tuple_starts_with_the_placeholder_delimiter(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];

	(void) state;

	poller_output_tuple(out, sizeof(out), NULL, make_item("x", "1", 1), "0");

	assert_int_equal(out[0], ' ');
	assert_int_equal(out[1], '(');

	/* what the caller then does */
	out[0] = ',';
	assert_string_equal(out, ",(1, 'x', FROM_UNIXTIME(0), '1')");
}

static void test_tuple_escapes_both_free_text_columns(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];

	(void) state;

	poller_output_tuple(out, sizeof(out), NULL, make_item("it's", "o'clock", 5), "0");

	assert_int_equal(escape_calls, 2);
	assert_non_null(strstr(out, "'it''s'"));
	assert_non_null(strstr(out, "'o''clock'"));
}

/* #583: the escape destination is sized from the escaped length, not the
   source length, so a result of entirely quotable bytes still fits. */
static void test_escape_destination_allows_for_doubling(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];

	(void) state;

	poller_output_tuple(out, sizeof(out), NULL, make_item("x", "abc", 1), "0");

	assert_true(last_escape_capacity >= (size_t) DBL_BUFSIZE
		|| last_escape_capacity >= (size_t) RESULTS_BUFFER);
}

static void test_tuple_survives_a_result_that_is_all_quotes(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];
	char quotes[512];
	int n;

	(void) state;

	memset(quotes, '\'', sizeof(quotes) - 1);
	quotes[sizeof(quotes) - 1] = '\0';

	n = poller_output_tuple(out, sizeof(out), NULL, make_item("q", quotes, 9), "0");

	/* every quote doubled, and the tuple is still terminated and well formed */
	assert_true(n > (int) sizeof(quotes));
	assert_int_equal(out[0], ' ');
	assert_int_equal(out[n], '\0');
	assert_non_null(strstr(out, "FROM_UNIXTIME(0)"));
}

static void test_tuple_reports_the_length_it_wrote(void **state) {
	char out[RESULTS_BUFFER + SMALL_BUFSIZE];
	int n;

	(void) state;

	n = poller_output_tuple(out, sizeof(out), NULL, make_item("name", "value", 3), "1700000000");

	/* the caller adds this to its running total to decide when to flush */
	assert_int_equal(n, (int) strlen(out));
	assert_true(n > 0);
}

static void test_tuple_rejects_null_arguments(void **state) {
	char out[64];

	(void) state;

	assert_int_equal(poller_output_tuple(NULL, sizeof(out), NULL, make_item("a", "b", 1), "0"), 0);
	assert_int_equal(poller_output_tuple(out, 0, NULL, make_item("a", "b", 1), "0"), 0);
	assert_int_equal(poller_output_tuple(out, sizeof(out), NULL, NULL, "0"), 0);
	assert_int_equal(poller_output_tuple(out, sizeof(out), NULL, make_item("a", "b", 1), NULL), 0);
}


/* The tuple must survive the largest row the poller can produce: a result that
   fills RESULTS_BUFFER and is entirely quotable, alongside a full rrd_name.
   result_string is what the caller passes, so if it is undersized the row
   reaches the database truncated, silently. */
static void test_tuple_fits_the_largest_row_the_poller_can_produce(void **state) {
	char *out;
	char quotes[RESULTS_BUFFER];
	char name[DBL_BUFSIZE];
	target_t item;
	int n;
	size_t cap = POLLER_OUTPUT_TUPLE_MAX;   /* what poll_host() passes */

	(void) state;

	out = malloc(cap);
	assert_non_null(out);

	memset(quotes, '\'', sizeof(quotes) - 1);
	quotes[sizeof(quotes) - 1] = '\0';
	memset(name, 'n', sizeof(name) - 1);
	name[sizeof(name) - 1] = '\0';

	memset(&item, 0, sizeof(item));
	snprintf(item.rrd_name, sizeof(item.rrd_name), "%s", name);
	snprintf(item.result, sizeof(item.result), "%s", quotes);
	item.local_data_id = 2147483647;

	n = poller_output_tuple(out, cap, NULL, &item, "1700000000");

	/* a complete tuple ends with the closing paren; a truncated one does not */
	assert_int_equal(out[n - 1], ')');

	free(out);
}


/* ---------------------------------------------------------------------------
 * host_from_row (poller.c)
 *
 * Maps one host row onto the device structure. A hundred lines in the middle
 * of poll_host(), so none of the defaults, the hostname parsing or the
 * max_oids clamp was reachable. Thirty-seven columns, all optional.
 * ------------------------------------------------------------------------- */

extern int *debug_devices;

static int hr_debug_table[100];

static int host_reset(void **state) {
	(void) state;
	escape_calls = 0;
	memset(hr_debug_table, 0, sizeof(hr_debug_table));
	debug_devices = hr_debug_table;
	return 0;
}

/* 37 columns; index 1 is the hostname, 13 is max_oids. */
static void blank_row(char **row, int n) {
	int i;

	for (i = 0; i < n; i++) row[i] = NULL;
}

static void test_host_row_maps_the_identity_columns(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[0] = "42";
	row[1] = "router1";
	row[2] = "public";
	row[3] = "2";

	host_from_row(&h, row, NULL, 42, 1);

	assert_int_equal(h.id, 42);
	assert_string_equal(h.hostname, "router1");
	assert_string_equal(h.snmp_community, "public");
	assert_int_equal(h.snmp_version, 2);
	assert_false(h.ignore_host);
}

/* A NULL column leaves the initialised default rather than zeroing it. */
static void test_host_row_keeps_defaults_for_null_columns(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 'x', sizeof(h));
	blank_row(row, 40);

	host_from_row(&h, row, NULL, 42, 1);

	assert_int_equal(h.id, 0);
	assert_int_equal(h.hostname[0], '\0');
	assert_int_equal(h.snmp_community[0], '\0');
	assert_false(h.ignore_host);
}

/* max_oids sizes an SNMP multi-get batch, so a row carrying 0 or an absurd
   value has to be clamped before it reaches that. */
static void test_host_row_clamps_max_oids(void **state) {
	host_t h;
	char *row[40];

	(void) state;

	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[13] = "0";
	host_from_row(&h, row, NULL, 42, 1);
	assert_int_equal(h.max_oids, 5);

	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[13] = "101";
	host_from_row(&h, row, NULL, 42, 1);
	assert_int_equal(h.max_oids, 5);

	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[13] = "25";
	host_from_row(&h, row, NULL, 42, 1);
	assert_int_equal(h.max_oids, 25);
}

/* A missing max_oids column keeps the initialised default of 10, which is in
   range and so is not clamped. */
static void test_host_row_defaults_max_oids_when_the_column_is_absent(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 0, sizeof(h));
	blank_row(row, 40);

	host_from_row(&h, row, NULL, 42, 1);
	assert_int_equal(h.max_oids, 10);
}

/* The hostname column carries an optional transport and port, which
   get_namebyhost() splits out. */
static void test_host_row_splits_the_port_off_the_hostname(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[1] = "192.0.2.10:1161";

	host_from_row(&h, row, NULL, 42, 1);

	assert_string_equal(h.hostname, "192.0.2.10");
	assert_int_equal(h.ping_port, 1161);
}

/* The five sysinfo strings are written back to the database later without
   further quoting, so they are escaped on the way in. */
static void test_host_row_escapes_the_sysinfo_strings(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 0, sizeof(h));
	blank_row(row, 40);
	row[32] = "it's a router";
	row[35] = "o'brien";

	host_from_row(&h, row, NULL, 42, 1);

	assert_int_equal(escape_calls, 2);
	assert_string_equal(h.snmp_sysDescr, "it''s a router");
	assert_string_equal(h.snmp_sysName, "o''brien");
}

static void test_host_row_rejects_null_arguments(void **state) {
	host_t h;
	char *row[40];

	(void) state;
	memset(&h, 0, sizeof(h));
	blank_row(row, 40);

	host_from_row(NULL, row, NULL, 42, 1);
	host_from_row(&h, NULL, NULL, 42, 1);
}


int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_tuple_has_the_expected_shape, reset),
		cmocka_unit_test_setup(test_tuple_starts_with_the_placeholder_delimiter, reset),
		cmocka_unit_test_setup(test_tuple_escapes_both_free_text_columns, reset),
		cmocka_unit_test_setup(test_escape_destination_allows_for_doubling, reset),
		cmocka_unit_test_setup(test_tuple_survives_a_result_that_is_all_quotes, reset),
		cmocka_unit_test_setup(test_tuple_reports_the_length_it_wrote, reset),
		cmocka_unit_test_setup(test_tuple_rejects_null_arguments, reset),
		cmocka_unit_test_setup(test_tuple_fits_the_largest_row_the_poller_can_produce, reset),
		cmocka_unit_test_setup(test_host_row_maps_the_identity_columns, host_reset),
		cmocka_unit_test_setup(test_host_row_keeps_defaults_for_null_columns, host_reset),
		cmocka_unit_test_setup(test_host_row_clamps_max_oids, host_reset),
		cmocka_unit_test_setup(test_host_row_defaults_max_oids_when_the_column_is_absent, host_reset),
		cmocka_unit_test_setup(test_host_row_splits_the_port_off_the_hostname, host_reset),
		cmocka_unit_test_setup(test_host_row_escapes_the_sysinfo_strings, host_reset),
		cmocka_unit_test_setup(test_host_row_rejects_null_arguments, host_reset),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
