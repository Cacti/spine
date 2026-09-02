/* Unit tests that exercise the shipped objects.
 *
 * The other test binaries in this directory inline the function under test, or
 * replicate its predicate, so they compile standalone.  That keeps them cheap
 * but means a fix can land in util.c while the test still passes against the
 * old copy.  This binary links the real translation units instead, with
 * tests/fuzz/stubs.c supplying the globals that spine.c would otherwise define,
 * so what runs here is what ships.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "spine.h"
#include "util.h"
#include "ping.h"

/* provided by tests/fuzz/stubs.c, as spine.c would */
extern int *debug_devices;

/* --- strncopy(): issue#447, the off-by-one when src fills the destination -- */

static void test_strncopy_truncates_within_the_buffer(void **state) {
	struct { char dst[8]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strncopy(b.dst, "ABCDEFGHIJK", sizeof b.dst);

	assert_string_equal(b.dst, "ABCDEFG");
	assert_int_equal(strlen(b.dst), sizeof b.dst - 1);
	assert_int_equal(b.canary, 0xAA);
}

static void test_strncopy_copies_a_short_source_whole(void **state) {
	char dst[16];
	(void) state;

	memset(dst, 0xAA, sizeof dst);
	strncopy(dst, "abc", sizeof dst);
	assert_string_equal(dst, "abc");
}

static void test_strncopy_handles_a_zero_size(void **state) {
	char dst[4] = {'z', 'z', 'z', '\0'};
	(void) state;

	strncopy(dst, "abc", 0);
	assert_string_equal(dst, "zzz");
}

static void test_strncopy_terminates_an_exact_fit(void **state) {
	struct { char dst[4]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strncopy(b.dst, "abc", sizeof b.dst);

	assert_string_equal(b.dst, "abc");
	assert_int_equal(b.canary, 0xAA);
}

/* --- regex_replace(): returns the match, or the input when it cannot ------- */

static void test_regex_replace_returns_the_match(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[0-9][0-9]*", "load 42 avg"), "42");
}

static void test_regex_replace_passes_through_on_no_match(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[0-9][0-9]*", "no digits"), "no digits");
}

static void test_regex_replace_passes_through_on_bad_pattern(void **state) {
	(void) state;
	assert_string_equal(regex_replace("[unclosed", "value"), "value");
}


/* --- predicates ----------------------------------------------------------- */

static void test_all_digits(void **state) {
	(void) state;
	assert_int_equal(all_digits("12345"), TRUE);
	assert_int_equal(all_digits("0"), TRUE);
	assert_int_equal(all_digits(""), FALSE);          /* empty is not all digits */
	assert_int_equal(all_digits("12a45"), FALSE);
	assert_int_equal(all_digits("-12"), FALSE);       /* sign is not a digit */
	assert_int_equal(all_digits(" 12"), FALSE);
}

static void test_is_ipaddress(void **state) {
	(void) state;
	assert_int_equal(is_ipaddress("192.168.0.1"), TRUE);
	assert_int_equal(is_ipaddress("::1"), TRUE);
	assert_int_equal(is_ipaddress("2001:db8::1"), FALSE);  /* letters rejected */
	assert_int_equal(is_ipaddress("host.example"), FALSE);
	assert_int_equal(is_ipaddress(""), TRUE);              /* vacuously true */
}

static void test_is_numeric(void **state) {
	char i[16], d[16], neg[16], txt[16], mixed[16], empty[16];
	(void) state;

	strcpy(i, "42");        assert_int_equal(is_numeric(i), TRUE);
	strcpy(d, "3.14");      assert_int_equal(is_numeric(d), TRUE);
	strcpy(neg, "-7");      assert_int_equal(is_numeric(neg), TRUE);
	strcpy(txt, "abc");     assert_int_equal(is_numeric(txt), FALSE);
	strcpy(mixed, "12abc"); assert_int_equal(is_numeric(mixed), FALSE);
	strcpy(empty, "");      assert_int_equal(is_numeric(empty), FALSE);
}

static void test_is_hexadecimal(void **state) {
	(void) state;
	assert_int_equal(is_hexadecimal("AA BB CC", 0), TRUE);
	assert_int_equal(is_hexadecimal("zz", 0), FALSE);
	assert_int_equal(is_hexadecimal("", 0), FALSE);
}

/* --- string surgery ------------------------------------------------------- */

static void test_trim_family(void **state) {
	char a[32], b[32], c[32];
	(void) state;

	strcpy(a, "  padded  ");  assert_string_equal(trim(a), "padded");
	strcpy(b, "  left");      assert_string_equal(ltrim(b), "left");
	strcpy(c, "right  ");     assert_string_equal(rtrim(c), "right");
}

static void test_reverse(void **state) {
	char s[16], one[2], empty[1];
	(void) state;

	strcpy(s, "abcdef");  assert_string_equal(reverse(s), "fedcba");
	strcpy(one, "x");     assert_string_equal(reverse(one), "x");
	empty[0] = '\0';      assert_string_equal(reverse(empty), "");
}

static void test_strpos(void **state) {
	(void) state;
	assert_int_equal(strpos("hello world", "world"), 6);
	assert_int_equal(strpos("hello", "hello"), 0);
	assert_int_equal(strpos("hello", "zzz"), -1);
	assert_int_equal(strpos("hello", ""), 0);
}

static void test_char_count(void **state) {
	(void) state;
	assert_int_equal(char_count("a,b,c", ','), 2);
	assert_int_equal(char_count("none", ','), 0);
	assert_int_equal(char_count("", 'x'), 0);
	assert_int_equal(char_count("anything", '\0'), 1);   /* documented shortcut */
}

static void test_strip_alpha(void **state) {
	char a[32], b[32];
	(void) state;

	strcpy(a, "load42");    assert_string_equal(strip_alpha(a), "42");
	strcpy(b, "abc123def"); assert_string_equal(strip_alpha(b), "123");
}

static void test_add_slashes_doubles_a_backslash(void **state) {
	char in[32];
	char *out;
	(void) state;

	strcpy(in, "a\\b");
	out = add_slashes(in);

	assert_non_null(out);
	assert_string_equal(out, "a\\\\b");
	free(out);                       /* add_slashes() returns owned memory */
}

static void test_add_slashes_passes_plain_text_through(void **state) {
	char in[32];
	char *out;
	(void) state;

	strcpy(in, "plain");
	out = add_slashes(in);

	assert_non_null(out);
	assert_string_equal(out, "plain");
	free(out);
}

static void test_hex2dec(void **state) {
	char a[16], b[16];
	(void) state;

	strcpy(a, "FF");  assert_int_equal((int) hex2dec(a), 255);
	strcpy(b, "00");  assert_int_equal((int) hex2dec(b), 0);
}

/* --- misc ----------------------------------------------------------------- */

static void test_file_exists(void **state) {
	(void) state;
	assert_int_equal(file_exists("/etc/hostname") || file_exists("/etc/passwd"), TRUE);
	assert_int_equal(file_exists("/no/such/path/at/all"), FALSE);
}

static void test_get_time_as_double_advances(void **state) {
	double t1, t2;
	(void) state;

	t1 = get_time_as_double();
	assert_true(t1 > 0.0);
	t2 = get_time_as_double();
	assert_true(t2 >= t1);
}

static void test_get_checksum_is_stable(void **state) {
	unsigned char buf[16];
	unsigned short a, b;
	(void) state;

	memset(buf, 0x5A, sizeof buf);
	a = get_checksum(buf, sizeof buf);
	b = get_checksum(buf, sizeof buf);
	assert_int_equal(a, b);

	buf[0] = 0x00;
	assert_int_not_equal(get_checksum(buf, sizeof buf), a);
}

/* --- spine_icmp_classify_reply(): the real classifier --------------------- */

#define ICMP_TEST_BUFSIZE 64

static void build_ip_icmp(unsigned char *buf, size_t len, uint16_t id, uint16_t seq, int type) {
	struct ip   *iph;
	struct icmp *pkt;

	memset(buf, 0, len);

	iph = (struct ip *) buf;
	iph->ip_hl = sizeof(struct ip) / 4;
	iph->ip_v  = 4;

	pkt = (struct icmp *) (buf + sizeof(struct ip));
	pkt->icmp_type = type;
	pkt->icmp_id   = id;
	pkt->icmp_seq  = seq;
}

static void test_icmp_classify_accepts_our_reply(void **state) {
	unsigned char buf[ICMP_TEST_BUFSIZE];
	const struct icmp *out = NULL;
	(void) state;

	build_ip_icmp(buf, sizeof buf, 0x1234, 7, ICMP_ECHOREPLY);
	assert_int_equal(spine_icmp_classify_reply(buf, sizeof buf, 0x1234, 7, &out), SPINE_ICMP_REPLY_OK);
	assert_non_null(out);
}

static void test_icmp_classify_rejects_a_runt(void **state) {
	unsigned char buf[ICMP_TEST_BUFSIZE];
	const struct icmp *out = (const struct icmp *) 1;
	(void) state;

	build_ip_icmp(buf, sizeof buf, 1, 1, ICMP_ECHOREPLY);
	assert_int_equal(spine_icmp_classify_reply(buf, 4, 1, 1, &out), SPINE_ICMP_REPLY_TOO_SHORT);
	assert_null(out);
}

static void test_icmp_classify_rejects_a_bad_ihl(void **state) {
	unsigned char buf[ICMP_TEST_BUFSIZE];
	const struct icmp *out = NULL;
	(void) state;

	build_ip_icmp(buf, sizeof buf, 1, 1, ICMP_ECHOREPLY);
	((struct ip *) buf)->ip_hl = 2;      /* below sizeof(struct ip) */
	assert_int_equal(spine_icmp_classify_reply(buf, sizeof buf, 1, 1, &out), SPINE_ICMP_REPLY_BAD_HEADER);
}

static void test_icmp_classify_rejects_a_non_echo(void **state) {
	unsigned char buf[ICMP_TEST_BUFSIZE];
	const struct icmp *out = NULL;
	(void) state;

	build_ip_icmp(buf, sizeof buf, 1, 1, ICMP_DEST_UNREACH);
	assert_int_equal(spine_icmp_classify_reply(buf, sizeof buf, 1, 1, &out), SPINE_ICMP_REPLY_NOT_ECHO);
	assert_null(out);
}

static void test_icmp_classify_rejects_another_hosts_reply(void **state) {
	unsigned char buf[ICMP_TEST_BUFSIZE];
	const struct icmp *out = NULL;
	(void) state;

	build_ip_icmp(buf, sizeof buf, 0xBEEF, 9, ICMP_ECHOREPLY);
	assert_int_equal(spine_icmp_classify_reply(buf, sizeof buf, 0x1234, 9, &out), SPINE_ICMP_REPLY_NOT_OURS);
	assert_null(out);
}

static void test_icmp_classify_rejects_a_null_buffer(void **state) {
	const struct icmp *out = NULL;
	(void) state;
	assert_int_equal(spine_icmp_classify_reply(NULL, ICMP_TEST_BUFSIZE, 1, 1, &out), SPINE_ICMP_REPLY_TOO_SHORT);
}

/* --- get_namebyhost(): the real parser ------------------------------------ */

static void test_namebyhost_plain_hostname(void **state) {
	char host[64];
	name_t *n;
	(void) state;

	strcpy(host, "device.example.net");
	n = get_namebyhost(host, NULL);
	assert_non_null(n);
	assert_string_equal(n->hostname, "device.example.net");
	free(n);
}

static void test_namebyhost_is_reentrant_across_calls(void **state) {
	char a[64], b[64];
	name_t *na, *nb;
	(void) state;

	strcpy(a, "first.example.net");
	strcpy(b, "second.example.net");

	na = get_namebyhost(a, NULL);
	nb = get_namebyhost(b, NULL);

	assert_string_equal(na->hostname, "first.example.net");
	assert_string_equal(nb->hostname, "second.example.net");
	free(na);
	free(nb);
}


/* --- configuration: defaults, the file parser, and set_option() ----------- */

static void test_config_defaults_populates_the_set(void **state) {
	(void) state;

	memset(&set, 0, sizeof set);
	config_defaults();

	assert_int_equal(set.threads, DEFAULT_THREADS);
	assert_int_equal(set.db_port, DEFAULT_DB_PORT);
	assert_string_equal(set.db_host, DEFAULT_DB_HOST);
	assert_string_equal(set.db_db,   DEFAULT_DB_DB);
}

static void test_read_spine_config_rejects_a_missing_file(void **state) {
	(void) state;
	assert_int_equal(read_spine_config("/no/such/spine.conf"), -1);
}

static void test_read_spine_config_reads_settings(void **state) {
	const char *path = "/tmp/spine_test.conf";
	FILE *fp;
	(void) state;

	fp = fopen(path, "wb");
	assert_non_null(fp);
	fputs("DB_Host           testhost\n", fp);
	fputs("DB_Database       testdb\n", fp);
	fputs("DB_User           testuser\n", fp);
	fputs("DB_Port           3399\n", fp);
	fputs("Poller_Threads    7\n", fp);
	fputs("# a comment line\n", fp);
	fputs("\n", fp);
	fclose(fp);

	config_defaults();
	assert_int_equal(read_spine_config(path), 0);

	assert_string_equal(set.db_host, "testhost");
	assert_string_equal(set.db_db,   "testdb");
	assert_string_equal(set.db_user, "testuser");
	assert_int_equal(set.db_port, 3399);

	remove(path);
}

/* --- get_date_format(): every format and separator is owned by the caller -- */

static void test_get_date_format_returns_owned_memory(void **state) {
	char *fmt;
	(void) state;

	config_defaults();
	fmt = get_date_format();

	assert_non_null(fmt);
	assert_true(strlen(fmt) > 0);
	free(fmt);
}

static void test_get_date_format_clamps_an_out_of_range_format(void **state) {
	char *fmt;
	(void) state;

	config_defaults();
	set.log_datetime_format    = GD_MAX + 10;
	set.log_datetime_separator = GDC_MAX + 10;

	fmt = get_date_format();

	assert_non_null(fmt);
	assert_int_equal(set.log_datetime_format, GD_DEFAULT);
	assert_int_equal(set.log_datetime_separator, GDC_DEFAULT);
	free(fmt);
}

static void test_get_date_format_covers_each_supported_format(void **state) {
	int fmt_value;
	int sep_value;
	char *fmt;
	(void) state;

	config_defaults();

	for (fmt_value = GD_MIN; fmt_value <= GD_MAX; fmt_value++) {
		for (sep_value = GDC_MIN; sep_value <= GDC_MAX; sep_value++) {
			set.log_datetime_format    = fmt_value;
			set.log_datetime_separator = sep_value;

			fmt = get_date_format();
			assert_non_null(fmt);
			assert_true(strlen(fmt) > 0);
			free(fmt);
		}
	}
}

/* --- is_debug_device(): reads the global table stubs.c provides ----------- */

static void test_is_debug_device_matches_only_listed_ids(void **state) {
	int table[100];
	int *saved = debug_devices;
	(void) state;

	memset(table, 0, sizeof table);
	table[0] = 42;
	table[1] = 77;
	debug_devices = table;

	assert_int_equal(is_debug_device(42), TRUE);
	assert_int_equal(is_debug_device(77), TRUE);
	assert_int_equal(is_debug_device(1), FALSE);

	debug_devices = saved;
}


/* poll_host() built the same six queries twice, once for the main poller and
 * once for a remote one, differing only in how each query is scoped. A column
 * added to one copy would not have reached the other, and none of it was
 * reachable from a test. These two helpers hold the scoping rule.
 */
static void test_poller_item_scope_filters_deleted_on_the_main_poller(void **state) {
	char scope[64];
	(void) state;

	poller_item_scope(scope, sizeof scope, 0);
	assert_string_equal(scope, " AND deleted = ''");
}

static void test_poller_item_scope_filters_by_owner_on_a_remote_poller(void **state) {
	char scope[64];
	(void) state;

	poller_item_scope(scope, sizeof scope, 3);
	assert_string_equal(scope, " AND poller_id = 3");

	poller_item_scope(scope, sizeof scope, 1);
	assert_string_equal(scope, " AND poller_id = 1");
}

/* The main poller does not constrain the ownership queries at all, so the
 * fragment has to be empty rather than absent: the caller interpolates it
 * unconditionally. */
static void test_poller_owner_scope_is_empty_on_the_main_poller(void **state) {
	char scope[64];
	(void) state;

	memcpy(scope, "stale", 6);
	poller_owner_scope(scope, sizeof scope, 0);
	assert_string_equal(scope, "");
}

static void test_poller_owner_scope_names_the_remote_poller(void **state) {
	char scope[64];
	(void) state;

	poller_owner_scope(scope, sizeof scope, 7);
	assert_string_equal(scope, " AND poller_id = 7");
}

/* Both helpers are handed fixed stack buffers by poll_host(), so a degenerate
 * size must not write. */
static void test_poller_scopes_refuse_a_degenerate_buffer(void **state) {
	char scope[8];
	(void) state;

	memcpy(scope, "keep", 5);
	poller_item_scope(scope, 0, 0);
	assert_string_equal(scope, "keep");

	poller_owner_scope(scope, 0, 4);
	assert_string_equal(scope, "keep");

	poller_item_scope(NULL, sizeof scope, 0);
	poller_owner_scope(NULL, sizeof scope, 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_strncopy_truncates_within_the_buffer),
		cmocka_unit_test(test_strncopy_copies_a_short_source_whole),
		cmocka_unit_test(test_strncopy_handles_a_zero_size),
		cmocka_unit_test(test_strncopy_terminates_an_exact_fit),
		cmocka_unit_test(test_regex_replace_returns_the_match),
		cmocka_unit_test(test_regex_replace_passes_through_on_no_match),
		cmocka_unit_test(test_regex_replace_passes_through_on_bad_pattern),
		cmocka_unit_test(test_all_digits),
		cmocka_unit_test(test_is_ipaddress),
		cmocka_unit_test(test_is_numeric),
		cmocka_unit_test(test_is_hexadecimal),
		cmocka_unit_test(test_trim_family),
		cmocka_unit_test(test_reverse),
		cmocka_unit_test(test_strpos),
		cmocka_unit_test(test_char_count),
		cmocka_unit_test(test_strip_alpha),
		cmocka_unit_test(test_add_slashes_doubles_a_backslash),
		cmocka_unit_test(test_add_slashes_passes_plain_text_through),
		cmocka_unit_test(test_hex2dec),
		cmocka_unit_test(test_file_exists),
		cmocka_unit_test(test_get_time_as_double_advances),
		cmocka_unit_test(test_get_checksum_is_stable),
		cmocka_unit_test(test_icmp_classify_accepts_our_reply),
		cmocka_unit_test(test_icmp_classify_rejects_a_runt),
		cmocka_unit_test(test_icmp_classify_rejects_a_bad_ihl),
		cmocka_unit_test(test_icmp_classify_rejects_a_non_echo),
		cmocka_unit_test(test_icmp_classify_rejects_another_hosts_reply),
		cmocka_unit_test(test_icmp_classify_rejects_a_null_buffer),
		cmocka_unit_test(test_namebyhost_plain_hostname),
		cmocka_unit_test(test_namebyhost_is_reentrant_across_calls),
		cmocka_unit_test(test_config_defaults_populates_the_set),
		cmocka_unit_test(test_read_spine_config_rejects_a_missing_file),
		cmocka_unit_test(test_read_spine_config_reads_settings),
		cmocka_unit_test(test_get_date_format_returns_owned_memory),
		cmocka_unit_test(test_get_date_format_clamps_an_out_of_range_format),
		cmocka_unit_test(test_get_date_format_covers_each_supported_format),
		cmocka_unit_test(test_is_debug_device_matches_only_listed_ids),
		cmocka_unit_test(test_poller_item_scope_filters_deleted_on_the_main_poller),
		cmocka_unit_test(test_poller_item_scope_filters_by_owner_on_a_remote_poller),
		cmocka_unit_test(test_poller_owner_scope_is_empty_on_the_main_poller),
		cmocka_unit_test(test_poller_owner_scope_names_the_remote_poller),
		cmocka_unit_test(test_poller_scopes_refuse_a_degenerate_buffer),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
