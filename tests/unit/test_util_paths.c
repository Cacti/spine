/*
 * Coverage for the util.c paths changed by #578: the cached log timestamp
 * format (issue#567), the bounded newline append in spine_log() (issue#565)
 * and the result-set release on the NULL-row branch of the settings helpers
 * (issue#566).
 *
 * Unlike the self-contained suites, this one includes util.c the way
 * test_util_strings.c does, so set_date_format() and get_date_format() are
 * the shipped functions rather than a copy.  That matters here: the point of
 * the change is that the format is built once and then handed out, and a
 * copied routine could not demonstrate the caching at all.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define UNIT_TESTING
#include "../../common.h"
#include "../../spine.h"

config_t set;
double start_time;
char config_paths[CONFIG_PATHS][BUFSIZE];
int *debug_devices = NULL;

/* Reachability for the NULL-row branch: db_query() hands back a non-NULL
 * handle and mysql_num_rows() reports a row, but mysql_fetch_row() yields
 * nothing.  That is the combination that used to leak the result set. */
static int   fake_result;
static MYSQL fake_mysql;
static int   rows_to_report;
static int   row_is_null;
static int   frees_seen;

my_ulonglong mysql_num_rows(MYSQL_RES *res) { (void) res; return (my_ulonglong) rows_to_report; }

MYSQL_ROW mysql_fetch_row(MYSQL_RES *res) {
	static char *cells[2];
	static char  v0[] = "value";
	static char  v1[] = "value";

	(void) res;

	if (row_is_null) {
		return NULL;
	}

	cells[0] = v0;
	cells[1] = v1;

	return cells;
}

void db_connect(int type, MYSQL *mysql) {}
void db_disconnect(MYSQL *mysql) {}
MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query) {
	(void) mysql; (void) type; (void) query;
	return (MYSQL_RES *) &fake_result;
}

void db_free_result(MYSQL_RES *result) { (void) result; frees_seen++; }
int db_insert(MYSQL *mysql, int type, const char *query) { return 0; }
void db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {}
int append_hostrange(char *obuf, size_t obuf_size, const char *colname) { return 0; }
int parse_logdest(const char *res, int default_dest) { return 0; }
const char *printable_logdest(int dest) { return ""; }
void php_close(int php_process) {}

#include "../../util.c"

static char *build(int sep_code, int fmt_code) {
	set.log_datetime_separator = sep_code;
	set.log_datetime_format    = fmt_code;
	set_date_format();

	return get_date_format();
}

/* Every format code must produce a distinct string.  This is the regression
 * guard for the missing-break bug: with the breaks gone every code fell
 * through to the default and they all collapsed to one value. */
static void test_each_format_code_is_distinct(void **state) {
	const int codes[] = { GD_MO_D_Y, GD_MN_D_Y, GD_D_MO_Y, GD_D_MN_Y, GD_Y_MO_D, GD_Y_MN_D };
	char seen[6][GD_FMT_SIZE];
	int i, j;

	(void) state;

	for (i = 0; i < 6; i++) {
		snprintf(seen[i], GD_FMT_SIZE, "%s", build(GDC_SLASH, codes[i]));
	}

	for (i = 0; i < 6; i++) {
		for (j = i + 1; j < 6; j++) {
			assert_string_not_equal(seen[i], seen[j]);
		}
	}
}

static void test_format_codes_produce_expected_strings(void **state) {
	(void) state;

	assert_string_equal(build(GDC_SLASH, GD_MO_D_Y), "%m/%d/%Y %H:%M:%S - ");
	assert_string_equal(build(GDC_SLASH, GD_MN_D_Y), "%b/%d/%Y %H:%M:%S - ");
	assert_string_equal(build(GDC_SLASH, GD_D_MO_Y), "%d/%m/%Y %H:%M:%S - ");
	assert_string_equal(build(GDC_SLASH, GD_D_MN_Y), "%d/%b/%Y %H:%M:%S - ");
	assert_string_equal(build(GDC_SLASH, GD_Y_MO_D), "%Y/%m/%d %H:%M:%S - ");
	assert_string_equal(build(GDC_SLASH, GD_Y_MN_D), "%Y/%b/%d %H:%M:%S - ");
}

static void test_every_separator_is_applied(void **state) {
	(void) state;

	assert_string_equal(build(GDC_SLASH,  GD_Y_MO_D), "%Y/%m/%d %H:%M:%S - ");
	assert_string_equal(build(GDC_DOT,    GD_Y_MO_D), "%Y.%m.%d %H:%M:%S - ");
	assert_string_equal(build(GDC_HYPHEN, GD_Y_MO_D), "%Y-%m-%d %H:%M:%S - ");
}

static void test_out_of_range_codes_clamp_to_defaults(void **state) {
	const char *from_default;
	char expected[GD_FMT_SIZE];

	(void) state;

	snprintf(expected, GD_FMT_SIZE, "%s", build(GDC_DEFAULT, GD_DEFAULT));

	from_default = build(GDC_MAX + 7, GD_MAX + 7);
	assert_string_equal(from_default, expected);
	assert_int_equal(set.log_datetime_separator, GDC_DEFAULT);
	assert_int_equal(set.log_datetime_format, GD_DEFAULT);

	from_default = build(GDC_MIN - 3, GD_MIN - 3);
	assert_string_equal(from_default, expected);
}

/* The caching contract: the same storage is handed out every time, and the
 * value survives repeated reads.  Before this change each call returned a
 * fresh malloc that the caller had to free. */
static void test_get_returns_the_same_storage(void **state) {
	char *first, *second;

	(void) state;

	first  = build(GDC_HYPHEN, GD_Y_MO_D);
	second = get_date_format();

	assert_ptr_equal(first, second);
	assert_ptr_equal(second, get_date_format());
	assert_string_equal(second, "%Y-%m-%d %H:%M:%S - ");
}

static void test_value_is_stable_until_rebuilt(void **state) {
	char *p;
	int i;

	(void) state;

	p = build(GDC_DOT, GD_D_MO_Y);

	for (i = 0; i < 100; i++) {
		assert_string_equal(get_date_format(), "%d.%m.%Y %H:%M:%S - ");
	}

	assert_ptr_equal(p, get_date_format());

	/* a later rebuild replaces the contents in place */
	build(GDC_SLASH, GD_MO_D_Y);
	assert_ptr_equal(p, get_date_format());
	assert_string_equal(get_date_format(), "%m/%d/%Y %H:%M:%S - ");
}

/* The default before read_config_options() runs, so early log lines still
 * have a usable format. */
static void test_initial_value_is_usable(void **state) {
	char out[64];
	time_t now = 0;
	struct tm tm_buf;

	(void) state;

	build(GDC_SLASH, GD_Y_MO_D);

	assert_true(gmtime_r(&now, &tm_buf) != NULL);
	assert_true(strftime(out, sizeof(out), get_date_format(), &tm_buf) > 0);
	assert_string_equal(out, "1970/01/01 00:00:00 - ");
}


/* ---- issue#566: the result set is released on the NULL-row branch ---- */

static void expect_freed(const char *what, int before) {
	if (frees_seen == before) {
		fail_msg("%s did not free the result set on the NULL-row branch", what);
	}
}

static void test_getsetting_frees_on_null_row(void **state) {
	char *r;
	int before;

	(void) state;

	rows_to_report = 1;
	row_is_null    = 1;
	before         = frees_seen;

	r = getsetting(&fake_mysql, LOCAL, "anything");
	expect_freed("getsetting()", before);
	free(r);
}

static void test_getpsetting_frees_on_null_row(void **state) {
	char *r;
	int before;

	(void) state;

	rows_to_report = 1;
	row_is_null    = 1;
	before         = frees_seen;

	r = getpsetting(&fake_mysql, LOCAL, "anything");
	expect_freed("getpsetting()", before);
	free(r);
}

static void test_getglobalvariable_frees_on_null_row(void **state) {
	char *r;
	int before;

	(void) state;

	rows_to_report = 1;
	row_is_null    = 1;
	before         = frees_seen;

	r = getglobalvariable(&fake_mysql, LOCAL, "anything");
	expect_freed("getglobalvariable()", before);
	free(r);
}

static void test_get_cacti_version_frees_on_null_row(void **state) {
	int before;

	(void) state;

	rows_to_report = 1;
	row_is_null    = 1;
	before         = frees_seen;

	assert_int_equal(get_cacti_version(&fake_mysql, LOCAL), 0);
	expect_freed("get_cacti_version()", before);
}

/* The success path still frees exactly once, so the new call did not double
 * up with the one that was already there. */
static void test_success_path_frees_once(void **state) {
	char *r;
	int before;

	(void) state;

	rows_to_report = 1;
	row_is_null    = 0;
	before         = frees_seen;

	r = getsetting(&fake_mysql, LOCAL, "anything");
	assert_int_equal(frees_seen - before, 1);
	free(r);
}


/* ---- issue#565: spine_log() appends the newline without overrunning ---- */

static char log_path[256];

static void route_log_to_a_file(void) {
	snprintf(log_path, sizeof(log_path), "/tmp/spine_log_test_%d.log", (int) getpid());
	unlink(log_path);

	set.log_destination  = LOGDEST_FILE;
	set.log_level        = POLLER_VERBOSITY_DEBUG;
	set.logfile_processed = TRUE;
	set.poller_id        = 1;
	snprintf(set.path_logfile, sizeof(set.path_logfile), "%s", log_path);
}

static char *read_log(size_t *len) {
	FILE *f = fopen(log_path, "r");
	static char buf[LOGSIZE * 2];
	size_t n;

	if (f == NULL) {
		*len = 0;
		return NULL;
	}

	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	*len = n;

	return buf;
}

static void test_spine_log_appends_a_newline(void **state) {
	char *out;
	size_t n;

	(void) state;

	route_log_to_a_file();
	spine_log("a short message");

	out = read_log(&n);
	assert_non_null(out);
	assert_true(n > 0);
	assert_int_equal(out[n - 1], '\n');
	assert_non_null(strstr(out, "a short message"));

	unlink(log_path);
}

/* The regression guard: a message long enough to fill flogmessage exactly.
 * Before the fix the unconditional strcat() wrote the terminator one byte
 * past the buffer, which ASan reports as a stack-buffer-overflow. */
static void test_spine_log_survives_a_full_line(void **state) {
	char *big;
	char *out;
	size_t n;

	(void) state;

	big = malloc(LOGSIZE);
	assert_non_null(big);
	memset(big, 'y', LOGSIZE - 1);
	big[LOGSIZE - 1] = '\0';

	route_log_to_a_file();
	spine_log("%s", big);

	out = read_log(&n);
	assert_non_null(out);
	assert_true(n > 0);
	assert_true(n <= LOGSIZE);

	free(big);
	unlink(log_path);
}

static void test_spine_log_does_not_double_an_existing_newline(void **state) {
	char *out;
	size_t n;

	(void) state;

	route_log_to_a_file();
	spine_log("ends with a newline\n");

	out = read_log(&n);
	assert_non_null(out);
	assert_true(n >= 2);
	assert_int_equal(out[n - 1], '\n');
	assert_int_not_equal(out[n - 2], '\n');

	unlink(log_path);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_each_format_code_is_distinct),
		cmocka_unit_test(test_format_codes_produce_expected_strings),
		cmocka_unit_test(test_every_separator_is_applied),
		cmocka_unit_test(test_out_of_range_codes_clamp_to_defaults),
		cmocka_unit_test(test_get_returns_the_same_storage),
		cmocka_unit_test(test_value_is_stable_until_rebuilt),
		cmocka_unit_test(test_initial_value_is_usable),
		cmocka_unit_test(test_getsetting_frees_on_null_row),
		cmocka_unit_test(test_getpsetting_frees_on_null_row),
		cmocka_unit_test(test_getglobalvariable_frees_on_null_row),
		cmocka_unit_test(test_get_cacti_version_frees_on_null_row),
		cmocka_unit_test(test_success_path_frees_once),
		cmocka_unit_test(test_spine_log_appends_a_newline),
		cmocka_unit_test(test_spine_log_survives_a_full_line),
		cmocka_unit_test(test_spine_log_does_not_double_an_existing_newline),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
