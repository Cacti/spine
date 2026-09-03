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
#include "nft_popen.h"

#include <wchar.h>
#include <locale.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <dirent.h>
#include <poll.h>
#include <sys/resource.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

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

			set_date_format();
			fmt = get_date_format();
			assert_non_null(fmt);
			assert_true(strlen(fmt) > 0);
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

static void test_cloexec_is_set_on_both_pipe_ends(void **state) {
	int pdes[2];
	int i;

	(void) state;

	assert_true(spine_open_pipe_cloexec(pdes));

	for (i = 0; i < 2; i++) {
		int flags = fcntl(pdes[i], F_GETFD);

		assert_true(flags >= 0);
		assert_true((flags & FD_CLOEXEC) != 0);
	}

	close(pdes[0]);
	close(pdes[1]);
}

static void test_cloexec_pipe_is_a_working_pipe(void **state) {
	int pdes[2];
	char buf[8];

	(void) state;

	assert_true(spine_open_pipe_cloexec(pdes));
	assert_int_equal(write(pdes[1], "ok", 2), 2);
	assert_int_equal(read(pdes[0], buf, sizeof(buf)), 2);
	assert_memory_equal(buf, "ok", 2);

	close(pdes[0]);
	close(pdes[1]);
}

static void test_pipe_is_not_inherited_across_exec(void **state) {
	int pdes[2];
	int status;
	pid_t pid;
	char fdarg[32];

	(void) state;

	assert_true(spine_open_pipe_cloexec(pdes));

	/* Asserting the descriptor is absent from /proc/self/fd would also pass
	   where /proc does not exist, which is the wrong reason. Check /proc is
	   usable first, and skip rather than pass vacuously. */
	if (access("/proc/self/fd", R_OK) != 0) {
		close(pdes[0]);
		close(pdes[1]);
		print_message("no /proc/self/fd here; cannot observe the child's table\n");
		return;
	}

	snprintf(fdarg, sizeof(fdarg), "/proc/self/fd/%d", pdes[1]);

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		/* 0 when the descriptor survived exec, 1 when it did not, and the
		   parent has already confirmed /proc answers */
		execl("/bin/sh", "sh", "-c", "test -e \"$0\"", fdarg, (char *) NULL);
		_exit(127);
	}

	assert_int_equal(waitpid(pid, &status, 0), pid);
	assert_true(WIFEXITED(status));
	assert_int_equal(WEXITSTATUS(status), 1);

	close(pdes[0]);
	close(pdes[1]);
}

static void test_reap_returns_still_running_rather_than_blocking(void **state) {
	int pstat = 0;
	int status;
	pid_t pid;

	(void) state;

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		pause();
		_exit(0);
	}

	/* the shipped code blocked here forever; two attempts must come back */
	assert_int_equal(spine_reap_child_bounded(pid, &pstat, 2), 1);

	assert_int_equal(kill(pid, SIGKILL), 0);
	assert_int_equal(waitpid(pid, &status, 0), pid);
}

static void test_reap_collects_an_exited_child(void **state) {
	int pstat = 0;
	pid_t pid;

	(void) state;

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		_exit(3);
	}

	assert_int_equal(spine_reap_child_bounded(pid, &pstat, 20), 0);
	assert_true(WIFEXITED(pstat));
	assert_int_equal(WEXITSTATUS(pstat), 3);
}

static void test_reap_reports_an_already_reaped_child(void **state) {
	int pstat = 99;
	int status;
	pid_t pid;

	(void) state;

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		_exit(0);
	}

	assert_int_equal(waitpid(pid, &status, 0), pid);

	/* ECHILD: someone else took the status, which is success with none */
	assert_int_equal(spine_reap_child_bounded(pid, &pstat, 2), 0);
	assert_int_equal(pstat, 0);
}

static void test_get_date_format_returns_cached_storage(void **state) {
	char *fmt;
	(void) state;

	config_defaults();
	set_date_format();
	fmt = get_date_format();

	assert_non_null(fmt);
	assert_true(strlen(fmt) > 0);

	/* the buffer belongs to util.c and is handed out, not owned by us */
	assert_ptr_equal(fmt, get_date_format());
}

static void test_set_date_format_clamps_an_out_of_range_format(void **state) {
	char *fmt;
	(void) state;

	config_defaults();
	set.log_datetime_format    = GD_MAX + 10;
	set.log_datetime_separator = GDC_MAX + 10;

	set_date_format();
	fmt = get_date_format();

	assert_non_null(fmt);
	assert_int_equal(set.log_datetime_format, GD_DEFAULT);
	assert_int_equal(set.log_datetime_separator, GDC_DEFAULT);
}

/* db_escape() stands between a device-supplied poller result and the SQL text
 * spine builds: it escapes the metacharacters and must never write past the
 * destination. It used to stage the input through a fixed DBL_BUFSIZE buffer,
 * which capped every caller at 1022 input bytes no matter how large a
 * destination it passed, so poller results were silently truncated.
 */
static MYSQL *escape_handle(void) {
	static MYSQL *handle = NULL;

	if (handle == NULL) {
		handle = mysql_init(NULL);
	}

	return handle;
}

static void test_db_escape_escapes_sql_metacharacters(void **state) {
	char out[64];
	(void) state;

	db_escape(escape_handle(), out, sizeof out, "a'b");
	assert_string_equal(out, "a\\'b");

	db_escape(escape_handle(), out, sizeof out, "back\\slash");
	assert_string_equal(out, "back\\\\slash");

	db_escape(escape_handle(), out, sizeof out, "plain value");
	assert_string_equal(out, "plain value");
}

static void test_db_escape_ignores_a_null_input(void **state) {
	char out[16];
	(void) state;

	memcpy(out, "untouched", 10);
	db_escape(escape_handle(), out, sizeof out, NULL);
	assert_string_equal(out, "untouched");
}

/* A result the size of the poller's own buffer has to survive when the
 * destination is sized 2N+1 for it. This is the case that regressed. */
static void test_db_escape_keeps_a_full_results_buffer(void **state) {
	char input[RESULTS_BUFFER];
	char out[(RESULTS_BUFFER * 2) + 1];
	(void) state;

	memset(input, 'x', sizeof input - 1);
	input[sizeof input - 1] = '\0';

	db_escape(escape_handle(), out, sizeof out, input);

	assert_int_equal((int) strlen(out), (int) (sizeof input - 1));
	assert_string_equal(out, input);
}

/* Walk across the old staging boundary to prove the cut is gone. */
static void test_db_escape_survives_the_old_staging_boundary(void **state) {
	const int sizes[] = { 1022, 1023, 1024, 1100, 2047 };
	char      input[2048];
	char      out[(2048 * 2) + 1];
	size_t    i;
	(void) state;

	for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
		memset(input, 'y', (size_t) sizes[i]);
		input[sizes[i]] = '\0';

		db_escape(escape_handle(), out, sizeof out, input);

		assert_int_equal((int) strlen(out), sizes[i]);
	}
}

/* When the destination genuinely cannot hold the escaped form the result is
 * truncated rather than overflowing, and stays NUL terminated. */
static void test_db_escape_truncates_into_a_small_destination(void **state) {
	char out[11];
	(void) state;

	db_escape(escape_handle(), out, sizeof out, "0123456789abcdef");

	/* (11 - 1) / 2 == 5 input bytes may be represented */
	assert_int_equal((int) strlen(out), 5);
	assert_string_equal(out, "01234");
}

static void test_db_escape_handles_a_degenerate_destination(void **state) {
	char out[4];
	(void) state;

	memcpy(out, "abc", 4);
	db_escape(escape_handle(), out, 1, "anything");
	assert_string_equal(out, "");

	memcpy(out, "abc", 4);
	db_escape(escape_handle(), out, 0, "anything");
	assert_string_equal(out, "abc");
}

/* Cacti stores the literal "[None]" when no SNMPv3 protocol is selected, and an
 * empty string for an absent passphrase. Treating either as an error made two
 * of the three security levels unusable: noAuthNoPriv was refused before the
 * session opened, and authNoPriv authenticated with a key that was never
 * derived. cmd.php accepts both, so a device that polls under the PHP poller
 * has to poll under spine.
 */
static void test_snmpv3_value_is_set_treats_none_as_unset(void **state) {
	(void) state;

	assert_int_equal(spine_snmpv3_value_is_set(NULL), FALSE);
	assert_int_equal(spine_snmpv3_value_is_set(""), FALSE);
	assert_int_equal(spine_snmpv3_value_is_set("[None]"), FALSE);

	assert_int_equal(spine_snmpv3_value_is_set("SHA"), TRUE);
	assert_int_equal(spine_snmpv3_value_is_set("secret"), TRUE);
	/* only the exact sentinel is unset */
	assert_int_equal(spine_snmpv3_value_is_set("[None] "), TRUE);
	assert_int_equal(spine_snmpv3_value_is_set("none"), TRUE);
}

static void test_snmpv3_level_is_noauth_without_a_protocol(void **state) {
	(void) state;

	assert_int_equal(spine_snmpv3_security_level("[None]", "", "[None]", ""),
		SNMP_SEC_LEVEL_NOAUTH);
	assert_int_equal(spine_snmpv3_security_level(NULL, NULL, NULL, NULL),
		SNMP_SEC_LEVEL_NOAUTH);
	/* a protocol with no password cannot authenticate */
	assert_int_equal(spine_snmpv3_security_level("SHA", "", "[None]", ""),
		SNMP_SEC_LEVEL_NOAUTH);
	/* nor a password with no protocol */
	assert_int_equal(spine_snmpv3_security_level("[None]", "secret", "[None]", ""),
		SNMP_SEC_LEVEL_NOAUTH);
}

static void test_snmpv3_level_is_authnopriv_without_privacy(void **state) {
	(void) state;

	assert_int_equal(spine_snmpv3_security_level("SHA", "secret", "[None]", ""),
		SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_int_equal(spine_snmpv3_security_level("MD5", "secret", "", ""),
		SNMP_SEC_LEVEL_AUTHNOPRIV);
	assert_int_equal(spine_snmpv3_security_level("SHA-512", "secret", NULL, NULL),
		SNMP_SEC_LEVEL_AUTHNOPRIV);
	/* a privacy protocol without its passphrase is not privacy */
	assert_int_equal(spine_snmpv3_security_level("SHA", "secret", "AES", ""),
		SNMP_SEC_LEVEL_AUTHNOPRIV);
}

static void test_snmpv3_level_is_authpriv_when_both_are_set(void **state) {
	(void) state;

	assert_int_equal(spine_snmpv3_security_level("SHA", "secret", "AES", "privpass"),
		SNMP_SEC_LEVEL_AUTHPRIV);
	assert_int_equal(spine_snmpv3_security_level("SHA-256", "secret", "AES-192", "privpass"),
		SNMP_SEC_LEVEL_AUTHPRIV);
}

/* Privacy without authentication is not a level SNMPv3 offers, so a privacy
 * selection alone must not raise the level above noAuthNoPriv. */
static void test_snmpv3_privacy_alone_does_not_raise_the_level(void **state) {
	(void) state;

	assert_int_equal(spine_snmpv3_security_level("[None]", "", "AES", "privpass"),
		SNMP_SEC_LEVEL_NOAUTH);
	assert_int_equal(spine_snmpv3_security_level("SHA", "", "AES", "privpass"),
		SNMP_SEC_LEVEL_NOAUTH);
}

struct guarded_buf {
	char body[32];
	char canary[8];
};

static void guarded_init(struct guarded_buf *g) {
	memset(g->body, 0, sizeof(g->body));
	memset(g->canary, 0x7e, sizeof(g->canary));
}

static void guarded_check(struct guarded_buf *g) {
	size_t i;

	for (i = 0; i < sizeof(g->canary); i++) {
		assert_int_equal((unsigned char) g->canary[i], 0x7e);
	}
}

static void test_appendf_writes_and_advances(void **state) {
	struct guarded_buf g;
	char *p;
	size_t remaining;

	(void) state;
	guarded_init(&g);
	p = g.body;
	remaining = sizeof(g.body);

	assert_true(spine_appendf(&p, &remaining, "abc"));
	assert_int_equal(p - g.body, 3);
	assert_int_equal(remaining, sizeof(g.body) - 3);
	assert_string_equal(g.body, "abc");
	guarded_check(&g);
}

static void test_appendf_accumulates(void **state) {
	struct guarded_buf g;
	char *p;
	size_t remaining;

	(void) state;
	guarded_init(&g);
	p = g.body;
	remaining = sizeof(g.body);

	assert_true(spine_appendf(&p, &remaining, "SELECT %d", 7));
	assert_true(spine_appendf(&p, &remaining, " FROM %s", "t"));
	assert_string_equal(g.body, "SELECT 7 FROM t");
	assert_int_equal(remaining, sizeof(g.body) - strlen("SELECT 7 FROM t"));
	guarded_check(&g);
}

/* The case the old idiom got wrong. */
static void test_appendf_reports_truncation_and_stays_in_bounds(void **state) {
	struct guarded_buf g;
	char *p;
	size_t remaining;

	(void) state;
	guarded_init(&g);
	p = g.body;
	remaining = sizeof(g.body);

	assert_false(spine_appendf(&p, &remaining, "%s", "0123456789012345678901234567890123456789"));

	/* cursor lands on the terminator, not past the end */
	assert_true(p >= g.body);
	assert_true(p < g.body + sizeof(g.body));
	assert_int_equal(*p, '\0');
	assert_int_equal(remaining, 1);
	assert_int_equal(strlen(g.body), sizeof(g.body) - 1);
	guarded_check(&g);
}

static void test_appendf_after_truncation_keeps_failing(void **state) {
	struct guarded_buf g;
	char *p;
	size_t remaining;
	char full[sizeof(g.body)];

	(void) state;
	guarded_init(&g);
	p = g.body;
	remaining = sizeof(g.body);

	assert_false(spine_appendf(&p, &remaining, "%s", "0123456789012345678901234567890123456789"));
	memcpy(full, g.body, sizeof(full));

	/* a second append must not write anything, anywhere */
	assert_false(spine_appendf(&p, &remaining, " AND poller_id=%d", 3));
	assert_memory_equal(g.body, full, sizeof(full));
	guarded_check(&g);
}

static void test_appendf_rejects_null_arguments(void **state) {
	char buf[8] = "";
	char *p = buf;
	size_t remaining = sizeof(buf);
	char *nullp = NULL;

	(void) state;

	assert_false(spine_appendf(NULL, &remaining, "x"));
	assert_false(spine_appendf(&nullp, &remaining, "x"));
	assert_false(spine_appendf(&p, NULL, "x"));
}

static void test_appendf_rejects_an_exhausted_buffer(void **state) {
	char buf[8] = "";
	char *p = buf;
	size_t remaining = 0;

	(void) state;

	assert_false(spine_appendf(&p, &remaining, "x"));
	assert_ptr_equal(p, buf);
	assert_int_equal(buf[0], '\0');
}

static void test_old_idiom_overshoots_where_appendf_does_not(void **state) {
	char buf[32];
	char *p = buf;
	ptrdiff_t old_offset;
	char *q;
	size_t remaining;
	char longer[41];

	(void) state;

	/* built at run time: a literal here lets the compiler prove the truncation
	   and warn about a case the test exists to demonstrate */
	memset(longer, '7', sizeof(longer) - 1);
	longer[sizeof(longer) - 1] = '\0';

	p += snprintf(p, sizeof(buf), "%s", longer);
	old_offset = p - buf;
	assert_true(old_offset > (ptrdiff_t) sizeof(buf));
	assert_true((ptrdiff_t) (sizeof(buf) - old_offset) < 0);

	q = buf;
	remaining = sizeof(buf);
	assert_false(spine_appendf(&q, &remaining, "%s", longer));
	assert_true(q - buf < (ptrdiff_t) sizeof(buf));
}

/* poller.c decides here whether a polled value is stored at all. A result that
 * validate_result() rejects is discarded, so a mistake in either predicate
 * silently drops data or accepts a malformed multi-value string. poller.c is
 * the most frequently changed file in the tree and had no coverage of either.
 */
static void test_validate_result_accepts_numeric_forms(void **state) {
	char integer[]  = "42";
	char negative[] = "-17";
	char decimal[]  = "3.14159";
	char zero[]     = "0";
	(void) state;

	assert_int_equal(validate_result(integer), TRUE);
	assert_int_equal(validate_result(negative), TRUE);
	assert_int_equal(validate_result(decimal), TRUE);
	assert_int_equal(validate_result(zero), TRUE);
}

static void test_validate_result_rejects_a_null_and_junk(void **state) {
	char junk[]  = "not a value";
	char empty[] = "";
	(void) state;

	assert_int_equal(validate_result(NULL), FALSE);
	assert_int_equal(validate_result(junk), FALSE);
	assert_int_equal(validate_result(empty), FALSE);
}

static void test_validate_result_accepts_multipart_output(void **state) {
	char one[]  = "field:1";
	char many[] = "in:100 out:200 errors:0";
	(void) state;

	assert_int_equal(validate_result(one), TRUE);
	assert_int_equal(validate_result(many), TRUE);
}

/* trim() is asymmetric and the caller needs to know it. rtrim() writes a NUL
 * over the trailing run, so it mutates the caller's buffer; ltrim() only walks
 * a pointer forward and leaves the leading run in place. validate_result()
 * therefore edits the buffer it is handed, but not into the string the
 * predicate actually saw. Its trim set is also wider than whitespace: it
 * includes quotes and a backslash.
 */
static void test_validate_result_trims_the_buffer_asymmetrically(void **state) {
	char padded[] = "  field:1  ";
	char quoted[] = "\"field:1\"";
	(void) state;

	assert_int_equal(validate_result(padded), TRUE);
	/* rtrim removed the trailing run in place, ltrim did not touch the front */
	assert_string_equal(padded, "  field:1");

	assert_int_equal(validate_result(quoted), TRUE);
	assert_string_equal(quoted, "\"field:1");
}

static void test_is_multipart_output_requires_a_delimiter(void **state) {
	char colon[]    = "a:1";
	char bang[]     = "a!1";
	char no_delim[] = "abc";
	(void) state;

	assert_int_equal(is_multipart_output(colon), TRUE);
	assert_int_equal(is_multipart_output(bang), TRUE);
	assert_int_equal(is_multipart_output(no_delim), FALSE);
	assert_int_equal(is_multipart_output(NULL), FALSE);
}

/* With spaces present the pair count has to line up: one more delimiter than
 * spaces. That is what separates "a:1 b:2" from a value that merely contains
 * a colon somewhere in free text.
 */
static void test_is_multipart_output_balances_spaces_against_delimiters(void **state) {
	char balanced[]   = "a:1 b:2 c:3";
	char unbalanced[] = "a:1 b:2 c";
	char prose[]      = "time is 12:30 today";
	(void) state;

	assert_int_equal(is_multipart_output(balanced), TRUE);
	assert_int_equal(is_multipart_output(unbalanced), FALSE);
	assert_int_equal(is_multipart_output(prose), FALSE);
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

static void build_profiles(poll_host_queries_t *q, int poller_id, int ports, int dbonupdate, int profiles) {
	set.poller_id        = poller_id;
	set.total_snmp_ports = ports;
	set.dbonupdate       = dbonupdate;
	set.poller_interval  = 60;
	set.active_profiles  = profiles;

	memset(q, 0, sizeof(*q));
	poll_host_build_queries(q, 42, ", 'RE' AS re", "LIMIT 0,100");
}

static void build_with(poll_host_queries_t *q, int poller_id, int ports, int dbonupdate) {
	set.poller_id        = poller_id;
	set.total_snmp_ports = ports;
	set.dbonupdate       = dbonupdate;
	set.poller_interval  = 60;
	set.active_profiles  = 1;

	memset(q, 0, sizeof(*q));
	poll_host_build_queries(q, 42, ", 'RE' AS re", "LIMIT 0,100");
}

static void test_build_queries_scopes_the_main_poller_by_deleted(void **state) {
	poll_host_queries_t q;

	(void) state;
	build_with(&q, 0, 1, 0);

	assert_non_null(strstr(q.query1, " AND deleted = ''"));
	assert_null(strstr(q.query1, "poller_id"));
	/* the ownership filter is absent, not defaulted to some poller */
	assert_null(strstr(q.query5, "poller_id"));
	assert_null(strstr(q.query9, "poller_id"));
}

static void test_build_queries_scopes_a_remote_poller_by_owner(void **state) {
	poll_host_queries_t q;

	(void) state;
	build_with(&q, 7, 1, 0);

	assert_non_null(strstr(q.query1, " AND poller_id = 7"));
	assert_null(strstr(q.query1, "deleted"));
	assert_non_null(strstr(q.query5, " AND poller_id = 7"));
	assert_non_null(strstr(q.query9, " AND poller_id = 7"));
	assert_non_null(strstr(q.query10, " AND poller_id = 7"));

	/* the host row is filtered by deleted on both, never by owner */
	assert_non_null(strstr(q.query2, " AND deleted = ''"));
	assert_null(strstr(q.query2, "poller_id"));
}

static void test_build_queries_orders_by_port_only_for_multiple_ports(void **state) {
	poll_host_queries_t q;

	(void) state;
	build_with(&q, 0, 1, 0);
	assert_null(strstr(q.query1, "ORDER BY snmp_port"));

	build_with(&q, 0, 2, 0);
	assert_non_null(strstr(q.query1, "ORDER BY snmp_port"));
}

/* The upsert suffix follows the server the INSERT is sent to, not the one the
   version was read from. set.dbonupdate describes the LOCAL connection, and a
   main poller writes poller_output there, so the flag applies. */
static void test_build_queries_upsert_follows_the_local_server(void **state) {
	poll_host_queries_t q;

	(void) state;

	build_with(&q, 0, 1, 0);
	assert_string_equal(q.posuffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)");
	build_with(&q, 0, 1, 1);
	assert_string_equal(q.posuffix, " AS rs ON DUPLICATE KEY UPDATE output=rs.output");
}

/* A remote poller sends this INSERT to the main server over mysqlr, which may
   be a different vendor from its own. MariaDB rejects the row-alias form, so a
   MySQL 8 remote poller writing to a MariaDB main server would lose every
   batch. It keeps the portable form regardless of its own version. */
static void test_build_queries_remote_poller_keeps_the_portable_upsert(void **state) {
	poll_host_queries_t q;
	int saved_mode = set.mode;

	(void) state;

	set.mode = REMOTE_ONLINE;

	build_with(&q, 7, 1, 1);
	assert_string_equal(q.posuffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)");
	build_with(&q, 7, 1, 0);
	assert_string_equal(q.posuffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)");

	set.mode = saved_mode;
}

static void test_build_queries_caches_the_lengths_the_result_loop_uses(void **state) {
	poll_host_queries_t q;

	(void) state;
	build_with(&q, 0, 1, 0);

	assert_int_equal(q.query8_len, (int) strlen(q.query8));
	assert_int_equal(q.query11_len, (int) strlen(q.query11));
	assert_int_equal(q.posuffix_len, (int) strlen(q.posuffix));
}

static void test_build_queries_fills_every_buffer(void **state) {
	poll_host_queries_t q;

	(void) state;
	build_with(&q, 0, 1, 0);

	assert_true(strlen(q.query1) > 0);
	assert_true(strlen(q.query2) > 0);
	assert_true(strlen(q.query4) > 0);
	assert_true(strlen(q.query5) > 0);
	assert_true(strlen(q.query6) > 0);
	assert_true(strlen(q.query8) > 0);
	assert_true(strlen(q.query9) > 0);
	assert_true(strlen(q.query10) > 0);
	assert_true(strlen(q.query11) > 0);
	assert_true(strlen(q.posuffix) > 0);
}

static void emit_one(FILE *f, const char *tag, poll_host_queries_t *q) {
	fprintf(f, "### %s query1\n%s\n", tag, q->query1);
	fprintf(f, "### %s query2\n%s\n", tag, q->query2);
	fprintf(f, "### %s query4\n%s\n", tag, q->query4);
	fprintf(f, "### %s query5\n%s\n", tag, q->query5);
	fprintf(f, "### %s query6\n%s\n", tag, q->query6);
	fprintf(f, "### %s query8\n%s\n", tag, q->query8);
	fprintf(f, "### %s query9\n%s\n", tag, q->query9);
	fprintf(f, "### %s query10\n%s\n", tag, q->query10);
	fprintf(f, "### %s posuffix\n%s\n", tag, q->posuffix);
}

static void write_all(FILE *f) {
	poll_host_queries_t q;
	int saved_mode;
	int ports[2] = {1, 2};
	int onupd[2] = {0, 1};
	int pid[2]   = {3, 7};
	int i, j;

	for (i = 0; i < 2; i++) {
		for (j = 0; j < 2; j++) {
			build_with(&q, 0, ports[i], onupd[j]);
			fprintf(f, "== MAIN ports=%d onupd=%d ==\n", ports[i], onupd[j]);
			emit_one(f, "main", &q);
		}
	}
	/* A remote poller is poller_id > 1 AND mode REMOTE_ONLINE; the second half
	   is what routes poller_output to the main server, and the upsert suffix
	   depends on it. Setting only the id modelled a poller that writes
	   locally, which is not the case this fixture exists to pin. */
	saved_mode = set.mode;
	set.mode = REMOTE_ONLINE;

	for (i = 0; i < 2; i++) {
		for (j = 0; j < 2; j++) {
			build_with(&q, pid[j], ports[i], onupd[j]);
			fprintf(f, "== REMOTE ports=%d onupd=%d pid=%d ==\n", ports[i], onupd[j], pid[j]);
			emit_one(f, "remote", &q);
		}
	}

	set.mode = saved_mode;
}

static void test_build_queries_matches_the_golden_capture(void **state) {
	const char *path = getenv("SPINE_GOLDEN");
	char fallback[512];
	char actual[] = "/tmp/spine_golden_actual.XXXXXX";
	FILE *f;
	FILE *g;
	int fd;
	int line = 0;
	char a[BIG_BUFSIZE];
	char b[BIG_BUFSIZE];

	(void) state;

	if (path == NULL) {
		/* automake runs from the build directory, which is not the source
		   directory under `make distcheck` */
		const char *dir = getenv("srcdir");

		snprintf(fallback, sizeof(fallback), "%s/tests/golden/poll_host_queries.golden",
			dir != NULL ? dir : ".");
		path = fallback;
	}

	/* Regenerate rather than compare. Documented in tests/golden/README.md;
	   read the diff before committing what it produces. */
	if (getenv("SPINE_WRITE_GOLDEN") != NULL) {
		FILE *w = fopen(path, "w");

		if (w == NULL) {
			fail_msg("cannot write the golden fixture to %s", path);
		}

		write_all(w);
		fclose(w);
		print_message("wrote %s\n", path);
		return;
	}

	g = fopen(path, "r");
	if (g == NULL) {
		fail_msg("golden fixture %s is not readable; this test must run, not skip", path);
	}

	fd = mkstemp(actual);
	assert_true(fd >= 0);
	f = fdopen(fd, "w+");
	assert_non_null(f);

	write_all(f);
	fflush(f);
	rewind(f);

	while (fgets(a, sizeof(a), g) != NULL) {
		line++;
		if (fgets(b, sizeof(b), f) == NULL) {
			fclose(g);
			fclose(f);
			unlink(actual);
			fail_msg("golden has more lines than produced, first missing at %d", line);
		}
		if (strcmp(a, b) != 0) {
			print_message("line %d\n  golden: %s  actual: %s", line, a, b);
			fclose(g);
			fclose(f);
			unlink(actual);
			fail_msg("query construction diverged from the golden capture at line %d", line);
		}
	}

	assert_null(fgets(b, sizeof(b), f));

	fclose(g);
	fclose(f);
	unlink(actual);
}

static void test_assert_equal_compares_as_text(void **state) {
	(void) state;

	assert_false(reindex_assert_failed("=", "eth0", "eth0"));
	assert_true(reindex_assert_failed("=", "eth0", "eth1"));

	/* '=' is a string compare, so these differ even though atoll() agrees */
	assert_true(reindex_assert_failed("=", "007", "7"));
}

static void test_assert_greater_compares_as_numbers(void **state) {
	(void) state;

	/* the assert is assert_value > poll_result; it fails when that is false */
	assert_false(reindex_assert_failed(">", "100", "50"));
	assert_true(reindex_assert_failed(">", "50", "100"));

	/* unlike '=', these are numerically equal and so do not fail */
	assert_false(reindex_assert_failed(">", "007", "7"));
}

static void test_assert_less_compares_as_numbers(void **state) {
	(void) state;

	assert_false(reindex_assert_failed("<", "50", "100"));
	assert_true(reindex_assert_failed("<", "100", "50"));
}

/* Equality is not a violation of either ordering operator. */
static void test_assert_equal_values_do_not_fail_an_ordering_assert(void **state) {
	(void) state;

	assert_false(reindex_assert_failed(">", "100", "100"));
	assert_false(reindex_assert_failed("<", "100", "100"));
}

static void test_assert_zero_never_fails_a_less_than(void **state) {
	(void) state;

	assert_false(reindex_assert_failed("<", "0", "0"));
	assert_false(reindex_assert_failed("<", "0", "999999"));

	/* the guard is specific to '<'; it does not cover the other operators */
	assert_true(reindex_assert_failed("=", "0", "1"));
}

static void test_assert_holds_when_the_device_gave_nothing_usable(void **state) {
	(void) state;

	/* 'U' is spine's undefined marker */
	assert_false(reindex_assert_failed("=", "eth0", "U"));
	assert_false(reindex_assert_failed(">", "100", "U"));
	assert_false(reindex_assert_failed("<", "100", "U"));

	/* SNMP says the instance is gone; that is a reindex trigger elsewhere,
	   not an assert failure here */
	assert_false(reindex_assert_failed("=", "eth0", "No Such Instance"));
	assert_false(reindex_assert_failed("=", "eth0", "no such instance"));
}

static void test_assert_ignores_an_unknown_operator(void **state) {
	(void) state;

	assert_false(reindex_assert_failed(">=", "100", "50"));
	assert_false(reindex_assert_failed("", "100", "50"));
	assert_false(reindex_assert_failed("!=", "eth0", "eth1"));
}

static void test_assert_rejects_null_arguments(void **state) {
	(void) state;

	assert_false(reindex_assert_failed(NULL, "100", "50"));
	assert_false(reindex_assert_failed("=", NULL, "50"));
	assert_false(reindex_assert_failed("=", "100", NULL));
}

static void test_assert_handles_values_beyond_32_bits(void **state) {
	(void) state;

	assert_true(reindex_assert_failed("<", "4294967296", "4294967295"));
	assert_false(reindex_assert_failed("<", "4294967295", "4294967296"));
}

static void test_build_queries_gates_on_rrd_next_step_for_multiple_profiles(void **state) {
	poll_host_queries_t q;

	(void) state;

	build_profiles(&q, 0, 1, 0, 1);
	assert_null(strstr(q.query5, "rrd_next_step"));
	assert_null(strstr(q.query10, "rrd_next_step"));

	build_profiles(&q, 0, 1, 0, 2);
	assert_non_null(strstr(q.query5, " AND rrd_next_step <= 0"));
	assert_non_null(strstr(q.query10, " AND rrd_next_step <= 0"));

	/* the guard is the profile count alone; poller_id does not change it */
	build_profiles(&q, 2, 1, 0, 1);
	assert_null(strstr(q.query5, "rrd_next_step"));
	build_profiles(&q, 2, 1, 0, 3);
	assert_non_null(strstr(q.query5, "rrd_next_step"));
}

static void test_build_queries_multiple_profiles_scope_a_remote_poller(void **state) {
	poll_host_queries_t q;

	(void) state;

	build_profiles(&q, 9, 1, 0, 2);
	assert_non_null(strstr(q.query5, " AND poller_id = 9"));
	assert_non_null(strstr(q.query10, " AND poller_id = 9"));

	/* and the port ordering still keys off total_snmp_ports, not profiles */
	build_profiles(&q, 9, 2, 0, 2);
	assert_non_null(strstr(q.query5, "ORDER BY snmp_port"));
}


/* ---------------------------------------------------------------------------
 * poller_item_from_row (poller.c)
 *
 * Maps one poller_item row onto a target. It was 62 lines in the middle of
 * poll_host()'s result loop, so none of the defaults or the NULL handling was
 * reachable. MYSQL_ROW is char **, so the rows here are ordinary arrays.
 * ------------------------------------------------------------------------- */

static char *full_row[] = {
	"2",                    /*  0 action              */
	"router1",              /*  1 hostname            */
	"public",               /*  2 snmp_community      */
	"3",                    /*  3 snmp_version        */
	"snmpuser",             /*  4 snmp_username       */
	"snmppass",             /*  5 snmp_password       */
	"traffic_in",           /*  6 rrd_name            */
	"/var/lib/rrd/1.rrd",   /*  7 rrd_path            */
	"argument one",         /*  8 arg1                */
	"argument two",         /*  9 arg2                */
	"argument three",       /* 10 arg3                */
	"77",                   /* 11 local_data_id       */
	"4",                    /* 12 rrd_num             */
	"1161",                 /* 13 snmp_port           */
	"900",                  /* 14 snmp_timeout        */
	"MD5",                  /* 15 snmp_auth_protocol  */
	"privpass",             /* 16 snmp_priv_passphrase*/
	"AES128",               /* 17 snmp_priv_protocol  */
	"ctx",                  /* 18 snmp_context        */
	"0x8000",               /* 19 snmp_engine_id      */
	"^[0-9]+$"              /* 20 output_regex        */
};

static void test_item_from_row_maps_every_column(void **state) {
	target_t item;

	(void) state;
	set.has_output_regex = TRUE;
	poller_item_from_row(&item, full_row);

	assert_int_equal(item.action, 2);
	assert_string_equal(item.hostname, "router1");
	assert_string_equal(item.snmp_community, "public");
	assert_int_equal(item.snmp_version, 3);
	assert_string_equal(item.snmp_username, "snmpuser");
	assert_string_equal(item.snmp_password, "snmppass");
	assert_string_equal(item.rrd_name, "traffic_in");
	assert_string_equal(item.rrd_path, "/var/lib/rrd/1.rrd");
	assert_string_equal(item.arg1, "argument one");
	assert_string_equal(item.arg2, "argument two");
	assert_string_equal(item.arg3, "argument three");
	assert_int_equal(item.local_data_id, 77);
	assert_int_equal(item.rrd_num, 4);
	assert_int_equal(item.snmp_port, 1161);
	assert_int_equal(item.snmp_timeout, 900);
	assert_string_equal(item.snmp_auth_protocol, "MD5");
	assert_string_equal(item.snmp_priv_passphrase, "privpass");
	assert_string_equal(item.snmp_priv_protocol, "AES128");
	assert_string_equal(item.snmp_context, "ctx");
	assert_string_equal(item.snmp_engine_id, "0x8000");
	assert_string_equal(item.output_regex, "^[0-9]+$");
}

/* A NULL column must leave the default in place. A device whose row is missing
   snmp_port has to poll on 161, not 0. */
static void test_item_from_row_keeps_defaults_for_null_columns(void **state) {
	target_t item;
	char *empty[21];
	int i;

	(void) state;
	for (i = 0; i < 21; i++) empty[i] = NULL;
	set.has_output_regex = TRUE;

	poller_item_from_row(&item, empty);

	assert_int_equal(item.action, -1);
	assert_int_equal(item.snmp_version, 1);
	assert_int_equal(item.snmp_port, 161);
	assert_int_equal(item.snmp_timeout, 500);
	assert_int_equal(item.local_data_id, 0);
	assert_int_equal(item.rrd_num, 0);
	assert_int_equal(item.hostname[0], '\0');
	assert_int_equal(item.rrd_path[0], '\0');
	assert_int_equal(item.output_regex[0], '\0');
}

/* output_regex arrived in Cacti 1.3.1. On an older schema the column is not in
   the select, so the mapper must not read row[20] at all. */
static void test_item_from_row_ignores_output_regex_on_an_old_schema(void **state) {
	target_t item;

	(void) state;

	set.has_output_regex = FALSE;
	poller_item_from_row(&item, full_row);
	assert_int_equal(item.output_regex[0], '\0');

	set.has_output_regex = TRUE;
	poller_item_from_row(&item, full_row);
	assert_string_equal(item.output_regex, "^[0-9]+$");
}

/* Every target starts undefined, so a data source that never answers reports
   U rather than a stale value from the previous item in the array. */
static void test_item_from_row_starts_the_result_undefined(void **state) {
	target_t item;

	(void) state;
	memset(&item, 'x', sizeof(item));
	set.has_output_regex = TRUE;

	poller_item_from_row(&item, full_row);

	assert_true(IS_UNDEFINED(item.result));
}

/* Reusing one target across rows must not leak the previous row's strings. */
static void test_item_from_row_does_not_carry_state_between_rows(void **state) {
	target_t item;
	char *sparse[21];
	int i;

	(void) state;
	set.has_output_regex = TRUE;

	poller_item_from_row(&item, full_row);
	assert_string_equal(item.hostname, "router1");

	for (i = 0; i < 21; i++) sparse[i] = NULL;
	poller_item_from_row(&item, sparse);

	assert_int_equal(item.hostname[0], '\0');
	assert_int_equal(item.snmp_community[0], '\0');
	assert_int_equal(item.arg1[0], '\0');
	assert_int_equal(item.snmp_port, 161);
}

static void test_item_from_row_rejects_null_arguments(void **state) {
	target_t item;

	(void) state;

	poller_item_from_row(NULL, full_row);
	poller_item_from_row(&item, NULL);
}


/* ---------------------------------------------------------------------------
 * poller_store_result (poller.c)
 *
 * Decides what a polled value means and what gets stored. The same thirty-three
 * lines ran after exec_poll() and after php_cmd(); they were identical, which is
 * the only reason the script and script-server paths still agreed on what a
 * valid result is.
 * ------------------------------------------------------------------------- */

static target_t sr_item;
static char     sr_errstr[DBL_BUFSIZE];
static int      sr_bufsize;
static int      sr_buferrors;

static int store_reset(void **state) {
	(void) state;
	memset(&sr_item, 0, sizeof(sr_item));
	memset(sr_errstr, 0, sizeof(sr_errstr));
	sr_bufsize = 0;
	sr_buferrors = 0;
	set.spine_log_level = 0;
	sr_item.local_data_id = 42;
	snprintf(sr_item.arg1, sizeof(sr_item.arg1), "%s", "/usr/bin/probe");
	return 0;
}

static int store(char *value) {
	return poller_store_result(&sr_item, value, sr_errstr, &sr_bufsize, &sr_buferrors, 7, 1);
}

static void test_store_keeps_a_numeric_result(void **state) {
	char v[] = "4242";

	(void) state;
	assert_false(store(v));
	assert_string_equal(sr_item.result, "4242");
}

static void test_store_keeps_a_negative_and_a_float(void **state) {
	char neg[] = "-17";
	char flt[] = "3.14159";

	(void) state;
	assert_false(store(neg));
	assert_string_equal(sr_item.result, "-17");
	assert_false(store(flt));
	assert_string_equal(sr_item.result, "3.14159");
}

/* 'U' is the poller reporting it got nothing usable. */
static void test_store_reports_an_undefined_result_as_an_error(void **state) {
	char v[] = "U";

	(void) state;
	assert_true(store(v));
	assert_true(IS_UNDEFINED(sr_item.result));
}

/* is_hexadecimal() wants a delimited octet string, at least three characters
   long. Dashes and spaces reach it; a colon does not, because Cacti's own
   multi-part "name:value" format is checked first and claims it. */
static void test_store_converts_a_delimited_octet_string(void **state) {
	char dashes[] = "de-ad-be-ef";
	char spaces[] = "DE AD BE EF";

	(void) state;

	assert_false(store(spaces));
	assert_string_equal(sr_item.result, "3735928559");

	assert_false(store(dashes));
	assert_string_equal(sr_item.result, "3735928559");
}

/* The colon form is multi-part output, not hex, and is stored as it arrived. */
static void test_store_treats_colon_separated_hex_as_multipart(void **state) {
	char colons[] = "DE:AD:BE:EF";

	(void) state;
	assert_false(store(colons));
	assert_string_equal(sr_item.result, "DE:AD:BE:EF");
}

/* Undelimited hex is not an octet string, so it falls through to the strip and
   validate path and is rejected rather than silently misread as decimal. */
static void test_store_rejects_undelimited_hex(void **state) {
	char v[] = "deadbeef";

	(void) state;
	assert_true(store(v));
	assert_true(IS_UNDEFINED(sr_item.result));
}

/* A 0x prefix is claimed earlier, by is_numeric(): strtod() accepts C99
   hex-float literals, so "0x1F" parses whole and is stored as it arrived. */
static void test_store_keeps_0x_prefixed_hex_as_text(void **state) {
	char v[] = "0x1F";

	(void) state;
	assert_false(store(v));
	assert_string_equal(sr_item.result, "0x1F");
}

/* A multi-part line is name:value pairs and is stored verbatim for the caller
   to split later. */
static void test_store_keeps_multipart_output_verbatim(void **state) {
	char v[] = "in:1000 out:2000";

	(void) state;
	assert_false(store(v));
	assert_string_equal(sr_item.result, "in:1000 out:2000");
}

/* Anything else is stripped to its numeric part rather than rejected outright,
   which is what lets a device answering "42 packets" still record 42. */
static void test_store_strips_a_value_wearing_units(void **state) {
	char v[] = "42 packets";

	(void) state;
	assert_false(store(v));
	assert_string_equal(sr_item.result, "42");
}

/* And a value with nothing numeric in it becomes undefined and counts. */
static void test_store_rejects_a_value_with_no_number_in_it(void **state) {
	char v[] = "connection refused";

	(void) state;
	assert_true(store(v));
	assert_true(IS_UNDEFINED(sr_item.result));
}

static void test_store_rejects_an_empty_result(void **state) {
	char v[] = "";

	(void) state;
	assert_true(store(v));
	assert_true(IS_UNDEFINED(sr_item.result));
}

static void test_store_rejects_null_arguments(void **state) {
	char v[] = "1";

	(void) state;
	assert_false(poller_store_result(NULL, v, sr_errstr, &sr_bufsize, &sr_buferrors, 7, 1));
	assert_false(poller_store_result(&sr_item, NULL, sr_errstr, &sr_bufsize, &sr_buferrors, 7, 1));
}


/* ---------------------------------------------------------------------------
 * poller_process_snmp_results (poller.c)
 *
 * One multi-get batch of SNMP results normalised onto their targets. The same
 * seventy-six lines ran in both places poll_host() flushes a batch: when it
 * fills mid-loop, and for the remainder at the end. They differed only in
 * indentation.
 * ------------------------------------------------------------------------- */

static host_t       sn_host;
static target_t     sn_items[4];
static snmp_oids_t  sn_oids[4];
static char         sn_errstr[DBL_BUFSIZE];
static int          sn_bufsize;
static int          sn_buferrors;

static int sn_debug_table[100];

static int snmp_reset(void **state) {
	int k;

	(void) state;
	/* is_debug_device() walks this global unguarded, and the batch loop calls
	   it for every result */
	memset(sn_debug_table, 0, sizeof(sn_debug_table));
	debug_devices = sn_debug_table;
	memset(&sn_host, 0, sizeof(sn_host));
	memset(sn_items, 0, sizeof(sn_items));
	memset(sn_oids, 0, sizeof(sn_oids));
	memset(sn_errstr, 0, sizeof(sn_errstr));
	sn_bufsize = 0;
	sn_buferrors = 0;
	set.spine_log_level = 0;
	sn_host.snmp_version = 2;
	snprintf(sn_host.hostname, sizeof(sn_host.hostname), "%s", "router1");

	for (k = 0; k < 4; k++) {
		sn_items[k].local_data_id = 100 + k;
		sn_oids[k].array_position = k;
	}
	return 0;
}

static int run_batch(int n, int spike_kill) {
	return poller_process_snmp_results(&sn_host, sn_items, sn_oids, n,
		sn_errstr, &sn_bufsize, &sn_buferrors, 7, 1, 0.0, spike_kill);
}

static void set_oid(int k, const char *value) {
	snprintf(sn_oids[k].result, RESULTS_BUFFER, "%s", value);
}

static void test_snmp_batch_copies_numeric_results_to_their_targets(void **state) {
	(void) state;
	set_oid(0, "1000");
	set_oid(1, "2000");

	assert_int_equal(run_batch(2, FALSE), 0);
	assert_string_equal(sn_items[0].result, "1000");
	assert_string_equal(sn_items[1].result, "2000");
}

/* array_position is what maps an OID back to its data source; the batch order
   is not the target order. */
static void test_snmp_batch_honours_array_position(void **state) {
	(void) state;
	sn_oids[0].array_position = 2;
	sn_oids[1].array_position = 0;
	set_oid(0, "111");
	set_oid(1, "222");

	assert_int_equal(run_batch(2, FALSE), 0);
	assert_string_equal(sn_items[2].result, "111");
	assert_string_equal(sn_items[0].result, "222");
}

static void test_snmp_batch_counts_undefined_results_as_rejected(void **state) {
	(void) state;
	set_oid(0, "1000");
	set_oid(1, "U");
	set_oid(2, "Nan");

	assert_int_equal(run_batch(3, FALSE), 2);
	assert_string_equal(sn_items[0].result, "1000");
}

/* An ignored host blanks the whole batch without counting errors: the device
   is already known bad and each OID is not a separate failure. */
static void test_snmp_batch_blanks_everything_for_an_ignored_host(void **state) {
	(void) state;
	sn_host.ignore_host = TRUE;
	set_oid(0, "1000");
	set_oid(1, "2000");

	assert_int_equal(run_batch(2, FALSE), 0);
	assert_true(IS_UNDEFINED(sn_oids[0].result));
	assert_true(IS_UNDEFINED(sn_oids[1].result));
}

static void test_snmp_batch_converts_a_delimited_octet_string(void **state) {
	(void) state;
	set_oid(0, "DE AD BE EF");

	assert_int_equal(run_batch(1, FALSE), 0);
	assert_string_equal(sn_items[0].result, "3735928559");
}

/* A data source with an output_regex has it applied after normalisation. */
static void test_snmp_batch_applies_the_data_source_output_regex(void **state) {
	(void) state;
	snprintf(sn_items[0].output_regex, sizeof(sn_items[0].output_regex), "%s", "[0-9]+");
	set_oid(0, "value=4242 units");

	assert_int_equal(run_batch(1, FALSE), 0);
	assert_string_equal(sn_items[0].result, "4242");
}

/* spike_kill blanks a value when the agent has restarted, but leaves
   multi-part output alone because a colon means it is not a single counter. */
static void test_snmp_batch_spike_kill_blanks_a_scalar_but_not_multipart(void **state) {
	(void) state;
	set_oid(0, "1000");
	set_oid(1, "in:1 out:2");

	assert_int_equal(run_batch(2, TRUE), 0);
	assert_true(IS_UNDEFINED(sn_items[0].result));
	assert_string_equal(sn_items[1].result, "in:1 out:2");
}

static void test_snmp_batch_handles_an_empty_batch(void **state) {
	(void) state;
	assert_int_equal(run_batch(0, FALSE), 0);
}

static void test_snmp_batch_rejects_null_arguments(void **state) {
	(void) state;
	assert_int_equal(poller_process_snmp_results(NULL, sn_items, sn_oids, 1,
		sn_errstr, &sn_bufsize, &sn_buferrors, 7, 1, 0.0, FALSE), 0);
	assert_int_equal(poller_process_snmp_results(&sn_host, NULL, sn_oids, 1,
		sn_errstr, &sn_bufsize, &sn_buferrors, 7, 1, 0.0, FALSE), 0);
	assert_int_equal(poller_process_snmp_results(&sn_host, sn_items, NULL, 1,
		sn_errstr, &sn_bufsize, &sn_buferrors, 7, 1, 0.0, FALSE), 0);
}


/* A value that survives stripping but still does not validate is the branch
   that turns a plausible-looking response into an explicit failure. */
static void test_snmp_batch_rejects_a_value_that_fails_validation(void **state) {
	(void) state;
	set_oid(0, "no such object");

	assert_int_equal(run_batch(1, FALSE), 1);
	assert_true(IS_UNDEFINED(sn_oids[0].result));
}

/* At log level 2 every rejection is logged individually. The logging is the
   only thing that changes; the outcome must not. */
static void test_snmp_batch_outcome_is_the_same_at_log_level_two(void **state) {
	(void) state;
	set.spine_log_level = 2;
	set_oid(0, "U");
	set_oid(1, "Nan");
	set_oid(2, "no such object");
	set_oid(3, "1000");

	assert_int_equal(run_batch(4, FALSE), 3);
	assert_string_equal(sn_items[3].result, "1000");
}

/* A device on the debug list takes the louder logging path. */
static void test_snmp_batch_outcome_is_the_same_for_a_debug_device(void **state) {
	(void) state;
	sn_debug_table[0] = 7;
	set_oid(0, "1000");

	assert_int_equal(run_batch(1, FALSE), 0);
	assert_string_equal(sn_items[0].result, "1000");
}

/* Same for the script path: level 2 logs each rejection, nothing else moves. */
static void test_store_outcome_is_the_same_at_log_level_two(void **state) {
	char undef[] = "U";
	char junk[]  = "connection refused";
	char good[]  = "42";

	(void) state;
	set.spine_log_level = 2;

	assert_true(store(undef));
	assert_true(IS_UNDEFINED(sr_item.result));
	assert_true(store(junk));
	assert_true(IS_UNDEFINED(sr_item.result));
	assert_false(store(good));
	assert_string_equal(sr_item.result, "42");
}


/* The remaining branch: vsnprintf reporting a formatting error rather than
   truncation. In the C locale a wide character above ASCII cannot be converted,
   so %ls returns -1 with EILSEQ. Probed at run time first, because a libc that
   converts it anyway would otherwise fail this for the wrong reason. */
static void test_appendf_reports_a_formatting_error(void **state) {
	char buf[32];
	char probe[8];
	char *p = buf;
	size_t remaining = sizeof(buf);
	wchar_t wide[2];

	(void) state;

	wide[0] = 0x00E9;
	wide[1] = 0;
	setlocale(LC_ALL, "C");

	if (snprintf(probe, sizeof(probe), "%ls", wide) >= 0) {
		print_message("this libc converts %%ls in the C locale; branch not exercised\n");
		return;
	}

	memset(buf, 'x', sizeof(buf));
	p = buf;
	remaining = sizeof(buf);

	assert_false(spine_appendf(&p, &remaining, "%ls", wide));

	/* the contract on failure: the buffer is left a valid string */
	assert_int_equal(*p, '\0');
	assert_true(p >= buf && p < buf + sizeof(buf));
}


/* ---------------------------------------------------------------------------
 * Differential check for reindex_assert_failed().
 *
 * That function replaced an if/else-if chain rather than moving it, so the
 * tests above were written against the new shape and could have pinned a
 * boundary I got wrong. This reproduces the original chain verbatim from
 * before the change and compares the two over every combination that matters.
 *
 * The reference is deliberately a transcription, not a tidy version: the same
 * order, the same operators, the same "0" guard sitting in the final else-if.
 * ------------------------------------------------------------------------- */

static int reference_assert_failed(const char *op, const char *assert_value, const char *poll_result) {
	int assert_fail = FALSE;      /* the loop reset this per row */

	if (poll_result == NULL || (IS_UNDEFINED(poll_result)) || (STRIMATCH(poll_result, "No Such Instance"))) {
		assert_fail = FALSE;
	} else if ((!strcmp(op, "=")) && (strcmp(assert_value, poll_result))) {
		assert_fail = TRUE;
	} else if ((!strcmp(op, ">")) && (atoll(assert_value) < atoll(poll_result))) {
		assert_fail = TRUE;
	} else if (strcmp(assert_value, "0")) {
		if ((!strcmp(op, "<")) && (atoll(assert_value) > atoll(poll_result))) {
			assert_fail = TRUE;
		}
	}

	return assert_fail;
}

static void test_assert_matches_the_chain_it_replaced(void **state) {
	static const char *ops[]    = { "=", ">", "<", ">=", "!=", "" };
	static const char *values[] = {
		"0", "1", "100", "007", "7", "-1", "4294967295", "4294967296",
		"eth0", "", "U", "No Such Instance", "no such instance"
	};
	size_t o, a, p;
	int checked = 0;

	(void) state;

	for (o = 0; o < sizeof(ops) / sizeof(ops[0]); o++) {
		for (a = 0; a < sizeof(values) / sizeof(values[0]); a++) {
			for (p = 0; p < sizeof(values) / sizeof(values[0]); p++) {
				int want = reference_assert_failed(ops[o], values[a], values[p]);
				int got  = reindex_assert_failed(ops[o], values[a], values[p]);

				if (want != got) {
					fail_msg("op '%s' assert '%s' result '%s': chain said %d, function said %d",
						ops[o], values[a], values[p], want, got);
				}

				checked++;
			}
		}
	}

	assert_int_equal(checked, 6 * 13 * 13);
}


/* ---------------------------------------------------------------------------
 * Differential check for poller_store_result().
 *
 * Also a restructure rather than a move: the if/else-if chain became a series
 * of early returns. This reproduces the original chain and compares both the
 * error verdict and the value written to the target.
 *
 * Every call gets a fresh copy of the input, because trim(), strip_alpha() and
 * hex2dec() all modify the string in place. Reusing one buffer would compare
 * the function against a reference that saw different input.
 * ------------------------------------------------------------------------- */

static int reference_store_result(target_t *item, char *poll_result,
	char *error_string, int *buf_size, int *buf_errors, int host_id, int host_thread) {
	char temp_result[RESULTS_BUFFER];
	int  failed = FALSE;

	if (IS_UNDEFINED(poll_result)) {
		SET_UNDEFINED(item->result);
		buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, item->local_data_id, false);
		failed = TRUE;
	} else if ((is_numeric(poll_result)) || (is_multipart_output(trim(poll_result)))) {
		snprintf(item->result, RESULTS_BUFFER, "%s", poll_result);
	} else if (is_hexadecimal(poll_result, TRUE)) {
		snprintf(item->result, RESULTS_BUFFER, "%llu", hex2dec(poll_result));
	} else {
		snprintf(temp_result, RESULTS_BUFFER, "%s", regex_replace(REGEX_NUMBER, strip_alpha(poll_result)));
		snprintf(item->result, RESULTS_BUFFER, "%s", temp_result);

		if (!validate_result(item->result)) {
			buffer_output_errors(error_string, buf_size, buf_errors, host_id, host_thread, item->local_data_id, false);
			failed = TRUE;
			SET_UNDEFINED(item->result);
		}
	}

	return failed;
}

static void test_store_matches_the_chain_it_replaced(void **state) {
	static const char *inputs[] = {
		"4242", "-17", "3.14159", "0", "007", "U", "",
		"in:1000 out:2000", "DE:AD:BE:EF", "de-ad-be-ef", "DE AD BE EF",
		"deadbeef", "0x1F", "42 packets", "connection refused",
		"  7  ", "No Such Instance", "1e5", "4294967296"
	};
	char a[RESULTS_BUFFER], b[RESULTS_BUFFER];
	target_t ia, ib;
	char errs[DBL_BUFSIZE];
	int bs, be;
	size_t k;

	(void) state;

	for (k = 0; k < sizeof(inputs) / sizeof(inputs[0]); k++) {
		int want, got;

		memset(&ia, 0, sizeof(ia)); memset(&ib, 0, sizeof(ib));
		ia.local_data_id = ib.local_data_id = 5;
		memset(errs, 0, sizeof(errs)); bs = 0; be = 0;

		snprintf(a, sizeof(a), "%s", inputs[k]);
		want = reference_store_result(&ia, a, errs, &bs, &be, 7, 1);

		memset(errs, 0, sizeof(errs)); bs = 0; be = 0;
		snprintf(b, sizeof(b), "%s", inputs[k]);
		got = poller_store_result(&ib, b, errs, &bs, &be, 7, 1);

		if (want != got) {
			fail_msg("input '%s': chain said %d, function said %d", inputs[k], want, got);
		}

		if (strcmp(ia.result, ib.result) != 0) {
			fail_msg("input '%s': chain stored '%s', function stored '%s'",
				inputs[k], ia.result, ib.result);
		}
	}
}


/* The failure path: a descriptor that cannot carry the flag must be reported,
   not silently accepted. A pipe whose reader is inheritable is worse than no
   pipe, so the helper refuses rather than continuing. */
static void test_cloexec_rejects_a_bad_descriptor(void **state) {
	(void) state;

	assert_int_equal(spine_set_cloexec(-1), -1);
}

static void test_cloexec_rejects_a_closed_descriptor(void **state) {
	int pdes[2];

	(void) state;

	assert_true(spine_open_pipe_cloexec(pdes));
	close(pdes[0]);
	close(pdes[1]);

	/* both ends are gone, so fcntl cannot read their flags */
	assert_int_equal(spine_set_cloexec(pdes[0]), -1);
}


static void test_build_queries_rejects_null_arguments(void **state) {
	poll_host_queries_t q;

	(void) state;
	memset(&q, 0, sizeof(q));

	poll_host_build_queries(NULL, 42, "", "");
	poll_host_build_queries(&q, 42, NULL, "");
	poll_host_build_queries(&q, 42, "", NULL);

	/* nothing was written on any of those */
	assert_int_equal(q.query1[0], '\0');
	assert_int_equal(q.posuffix[0], '\0');
}


/* hex2dec() accepts '-', ':' and space as separators, matching what
   is_hexadecimal() lets through. The colon form cannot arrive via
   poller_store_result(), because is_multipart_output() claims anything with a
   colon and no space first, so it is only reachable by calling directly. That
   is exactly why it is worth a test: nothing else exercises it. */
static void test_hex2dec_accepts_every_separator_is_hexadecimal_allows(void **state) {
	char dashes[] = "de-ad-be-ef";
	char colons[] = "de:ad:be:ef";
	char spaces[] = "de ad be ef";
	char mixed[]  = "DE-AD BE:EF";

	(void) state;

	assert_int_equal(hex2dec(dashes), 3735928559ULL);
	assert_int_equal(hex2dec(colons), 3735928559ULL);
	assert_int_equal(hex2dec(spaces), 3735928559ULL);
	assert_int_equal(hex2dec(mixed),  3735928559ULL);
}

/* A separator it does not know still returns 0 rather than a partial value,
   which is what keeps a malformed octet string out of the database. */
static void test_hex2dec_rejects_an_unknown_separator(void **state) {
	char slashes[] = "de/ad/be/ef";

	(void) state;
	assert_int_equal(hex2dec(slashes), 0);
}


/* nft_popen() sets close-on-exec on both pipe ends so a concurrent spawn
   cannot inherit them. When the write end lands on the descriptor it is
   destined for, there is no dup2 to clear the flag, and the child execs with
   stdout closed: every script data source records U, silently.
   That happens whenever stdout was closed before the call, which for a daemon
   is not exotic. */
static void test_nft_popen_reads_a_script_with_stdout_closed(void **state) {
	int saved_stdin;
	int saved_stdout;
	int fd;
	char buf[64];
	ssize_t n;

	(void) state;

	saved_stdin  = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0 && saved_stdout >= 0);

	/* Both, deliberately: pipe() hands out the lowest free descriptors, so the
	   write end only lands on fd 1 when fd 0 is free as well. Closing stdout
	   alone puts the read end there instead and the collision never happens. */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	fd = nft_popen("echo spine-cloexec-probe", "r");

	if (fd < 0) {
		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
		close(saved_stdin);
		close(saved_stdout);
		fail_msg("nft_popen failed with stdin and stdout closed");
	}

	memset(buf, 0, sizeof(buf));
	n = read(fd, buf, sizeof(buf) - 1);
	nft_pclose(fd);

	dup2(saved_stdin, STDIN_FILENO);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdin);
	close(saved_stdout);

	assert_true(n > 0);
	assert_non_null(strstr(buf, "spine-cloexec-probe"));
}


static int open_fd_count(void) {
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;
	int n = 0;

	if (d == NULL) {
		return -1;
	}

	while ((e = readdir(d)) != NULL) {
		if (e->d_name[0] != '.') n++;
	}

	closedir(d);
	return n;
}

/* Reading to EOF is the assertion that catches a write end still held by the
   parent. A single read() returns the data and tells you nothing: the pipe
   only fails to close when you ask for the next byte. exec_poll() waits for
   that EOF, so a held copy stalls it to script_timeout on a script that
   already answered. */
static void test_nft_popen_reaches_eof_with_stdio_closed(void **state) {
	int saved_stdin, saved_stdout, fd;
	char buf[64];
	ssize_t n, total = 0;

	(void) state;

	saved_stdin  = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0 && saved_stdout >= 0);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	fd = nft_popen("echo spine-eof-probe", "r");

	n = -1;

	if (fd >= 0) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;

		/* poll rather than block: a write end still held by the parent means
		   this never becomes readable again, and a test that hangs is a worse
		   signal than one that fails. */
		for (;;) {
			int ready = poll(&pfd, 1, 5000);

			if (ready <= 0) {
				n = -1;   /* timed out: EOF never arrived */
				break;
			}

			n = read(fd, buf, sizeof(buf));

			if (n <= 0) {
				break;
			}

			total += n;
		}

		nft_pclose(fd);
	}

	dup2(saved_stdin, STDIN_FILENO);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdin);
	close(saved_stdout);

	assert_true(fd >= 0);
	if (n != 0) {
		fail_msg("the pipe never reached EOF; the parent is still holding the write end");
	}
	assert_true(total > 0);
}

/* One descriptor per call would exhaust the process. The collision branch is
   the one that dup()s, so it is the one that can leak. */
static void test_nft_popen_does_not_leak_descriptors_in_the_collision_case(void **state) {
	int saved_stdin, saved_stdout;
	int before, after;
	char buf[64];
	int i;

	(void) state;

	saved_stdin  = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0 && saved_stdout >= 0);

	before = open_fd_count();

	for (i = 0; i < 12; i++) {
		int fd;

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		fd = nft_popen("echo x", "r");

		if (fd >= 0) {
			struct pollfd pfd;

			pfd.fd = fd;
			pfd.events = POLLIN;

			/* bounded, for the same reason as the EOF test above */
			while (poll(&pfd, 1, 5000) > 0 && read(fd, buf, sizeof(buf)) > 0) { }

			nft_pclose(fd);
		}

		dup2(saved_stdin, STDIN_FILENO);
		dup2(saved_stdout, STDOUT_FILENO);
	}

	after = open_fd_count();

	close(saved_stdin);
	close(saved_stdout);

	if (before < 0 || after < 0) {
		print_message("no /proc/self/fd here; skipping the count\n");
		skip();
	}

	assert_true(after <= before);
}



static sigjmp_buf nft_lock_timeout;

static void nft_lock_alarm(int sig) {
	(void) sig;
	siglongjmp(nft_lock_timeout, 1);
}

/* The dup() failure path inside nft_popen(). Reaching it needs a precise state:
   the table full except for exactly two descriptors, and those two being 0 and
   1 so the pipe lands there and the collision branch runs, leaving the dup()
   with nothing to take.

   Order matters. Filling the table first and only then closing stdin and stdout
   is what leaves 0 and 1 as the two free slots; closing them first just means
   the filler takes them and the collision never happens. An earlier version of
   this test did that and passed against a deliberately reintroduced bug.

   The assertion that matters is the second nft_popen(). A failure path that
   returns still holding ListMutex leaves every later caller blocked forever,
   and that mutex is process-global, so the daemon stops collecting script data
   until it is restarted. */
static void test_nft_popen_releases_the_lock_when_dup_fails(void **state) {
	struct rlimit saved_limit, tight;
	int saved_stdin, saved_stdout;
	int held[512];
	int count = 0;
	int first, second;
	char buf[64];

	(void) state;

	if (getrlimit(RLIMIT_NOFILE, &saved_limit) != 0) {
		print_message("cannot read RLIMIT_NOFILE; skipping\n");
		skip();
	}

	saved_stdin  = dup(STDIN_FILENO);
	saved_stdout = dup(STDOUT_FILENO);
	assert_true(saved_stdin >= 0 && saved_stdout >= 0);

	tight = saved_limit;
	tight.rlim_cur = (rlim_t) (saved_stdout + 24);

	if (setrlimit(RLIMIT_NOFILE, &tight) != 0) {
		close(saved_stdin);
		close(saved_stdout);
		print_message("cannot lower RLIMIT_NOFILE; skipping\n");
		skip();
	}

	/* fill first, with 0 and 1 still occupied by stdin and stdout */
	while (count < 512) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0) {
			break;
		}

		held[count++] = fd;
	}

	/* now the only free descriptors are 0 and 1 */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	first = nft_popen("echo unreachable", "r");

	if (first >= 0) {
		nft_pclose(first);
	}

	while (count > 0) {
		close(held[--count]);
	}

	setrlimit(RLIMIT_NOFILE, &saved_limit);
	dup2(saved_stdin, STDIN_FILENO);
	dup2(saved_stdout, STDOUT_FILENO);
	close(saved_stdin);
	close(saved_stdout);

	/* the setup must actually have defeated it, or this proves nothing */
	if (first >= 0) {
		fail_msg("nft_popen succeeded with the descriptor table full; the dup failure path was not exercised");
	}

	/* A leaked ListMutex blocks here rather than returning, and a hung suite
	   is a worse signal than a failing one: it looks like a stuck CI job
	   instead of a defect. Convert the hang into a failure. */
	if (sigsetjmp(nft_lock_timeout, 1) != 0) {
		fail_msg("nft_popen blocked after a failed dup; ListMutex was not released");
	}

	signal(SIGALRM, nft_lock_alarm);
	alarm(10);

	second = nft_popen("echo lock-still-usable", "r");

	alarm(0);
	signal(SIGALRM, SIG_DFL);

	assert_true(second >= 0);

	memset(buf, 0, sizeof(buf));
	read(second, buf, sizeof(buf) - 1);
	nft_pclose(second);

	assert_non_null(strstr(buf, "lock-still-usable"));
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
		cmocka_unit_test(test_hex2dec_accepts_every_separator_is_hexadecimal_allows),
		cmocka_unit_test(test_hex2dec_rejects_an_unknown_separator),
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
		cmocka_unit_test(test_get_date_format_covers_each_supported_format),
		cmocka_unit_test(test_is_debug_device_matches_only_listed_ids),
		cmocka_unit_test(test_cloexec_is_set_on_both_pipe_ends),
		cmocka_unit_test(test_cloexec_pipe_is_a_working_pipe),
		cmocka_unit_test(test_cloexec_rejects_a_bad_descriptor),
		cmocka_unit_test(test_cloexec_rejects_a_closed_descriptor),
		cmocka_unit_test(test_nft_popen_reads_a_script_with_stdout_closed),
		cmocka_unit_test(test_nft_popen_reaches_eof_with_stdio_closed),
		cmocka_unit_test(test_nft_popen_does_not_leak_descriptors_in_the_collision_case),
		cmocka_unit_test(test_nft_popen_releases_the_lock_when_dup_fails),
		cmocka_unit_test(test_pipe_is_not_inherited_across_exec),
		cmocka_unit_test(test_reap_returns_still_running_rather_than_blocking),
		cmocka_unit_test(test_reap_collects_an_exited_child),
		cmocka_unit_test(test_reap_reports_an_already_reaped_child),
		cmocka_unit_test(test_get_date_format_returns_cached_storage),
		cmocka_unit_test(test_set_date_format_clamps_an_out_of_range_format),
		cmocka_unit_test(test_db_escape_escapes_sql_metacharacters),
		cmocka_unit_test(test_db_escape_ignores_a_null_input),
		cmocka_unit_test(test_db_escape_keeps_a_full_results_buffer),
		cmocka_unit_test(test_db_escape_survives_the_old_staging_boundary),
		cmocka_unit_test(test_db_escape_truncates_into_a_small_destination),
		cmocka_unit_test(test_db_escape_handles_a_degenerate_destination),
		cmocka_unit_test(test_snmpv3_value_is_set_treats_none_as_unset),
		cmocka_unit_test(test_snmpv3_level_is_noauth_without_a_protocol),
		cmocka_unit_test(test_snmpv3_level_is_authnopriv_without_privacy),
		cmocka_unit_test(test_snmpv3_level_is_authpriv_when_both_are_set),
		cmocka_unit_test(test_snmpv3_privacy_alone_does_not_raise_the_level),
		cmocka_unit_test(test_appendf_writes_and_advances),
		cmocka_unit_test(test_appendf_accumulates),
		cmocka_unit_test(test_appendf_reports_truncation_and_stays_in_bounds),
		cmocka_unit_test(test_appendf_after_truncation_keeps_failing),
		cmocka_unit_test(test_appendf_rejects_null_arguments),
		cmocka_unit_test(test_appendf_rejects_an_exhausted_buffer),
		cmocka_unit_test(test_old_idiom_overshoots_where_appendf_does_not),
		cmocka_unit_test(test_appendf_reports_a_formatting_error),
		cmocka_unit_test(test_validate_result_accepts_numeric_forms),
		cmocka_unit_test(test_validate_result_rejects_a_null_and_junk),
		cmocka_unit_test(test_validate_result_accepts_multipart_output),
		cmocka_unit_test(test_validate_result_trims_the_buffer_asymmetrically),
		cmocka_unit_test(test_is_multipart_output_requires_a_delimiter),
		cmocka_unit_test(test_is_multipart_output_balances_spaces_against_delimiters),
		cmocka_unit_test(test_poller_item_scope_filters_deleted_on_the_main_poller),
		cmocka_unit_test(test_poller_item_scope_filters_by_owner_on_a_remote_poller),
		cmocka_unit_test(test_poller_owner_scope_is_empty_on_the_main_poller),
		cmocka_unit_test(test_poller_owner_scope_names_the_remote_poller),
		cmocka_unit_test(test_poller_scopes_refuse_a_degenerate_buffer),
		cmocka_unit_test(test_build_queries_scopes_the_main_poller_by_deleted),
		cmocka_unit_test(test_build_queries_scopes_a_remote_poller_by_owner),
		cmocka_unit_test(test_build_queries_orders_by_port_only_for_multiple_ports),
		cmocka_unit_test(test_build_queries_upsert_follows_the_local_server),
		cmocka_unit_test(test_build_queries_remote_poller_keeps_the_portable_upsert),
		cmocka_unit_test(test_build_queries_caches_the_lengths_the_result_loop_uses),
		cmocka_unit_test(test_build_queries_fills_every_buffer),
		cmocka_unit_test(test_build_queries_matches_the_golden_capture),
		cmocka_unit_test(test_build_queries_rejects_null_arguments),
		cmocka_unit_test(test_assert_equal_compares_as_text),
		cmocka_unit_test(test_assert_greater_compares_as_numbers),
		cmocka_unit_test(test_assert_less_compares_as_numbers),
		cmocka_unit_test(test_assert_equal_values_do_not_fail_an_ordering_assert),
		cmocka_unit_test(test_assert_zero_never_fails_a_less_than),
		cmocka_unit_test(test_assert_holds_when_the_device_gave_nothing_usable),
		cmocka_unit_test(test_assert_ignores_an_unknown_operator),
		cmocka_unit_test(test_assert_rejects_null_arguments),
		cmocka_unit_test(test_assert_handles_values_beyond_32_bits),
		cmocka_unit_test(test_assert_matches_the_chain_it_replaced),
		cmocka_unit_test(test_item_from_row_maps_every_column),
		cmocka_unit_test(test_item_from_row_keeps_defaults_for_null_columns),
		cmocka_unit_test(test_item_from_row_ignores_output_regex_on_an_old_schema),
		cmocka_unit_test(test_item_from_row_starts_the_result_undefined),
		cmocka_unit_test(test_item_from_row_does_not_carry_state_between_rows),
		cmocka_unit_test(test_item_from_row_rejects_null_arguments),
		cmocka_unit_test_setup(test_store_keeps_a_numeric_result, store_reset),
		cmocka_unit_test_setup(test_store_keeps_a_negative_and_a_float, store_reset),
		cmocka_unit_test_setup(test_store_reports_an_undefined_result_as_an_error, store_reset),
		cmocka_unit_test_setup(test_store_converts_a_delimited_octet_string, store_reset),
		cmocka_unit_test_setup(test_store_treats_colon_separated_hex_as_multipart, store_reset),
		cmocka_unit_test_setup(test_store_rejects_undelimited_hex, store_reset),
		cmocka_unit_test_setup(test_store_keeps_0x_prefixed_hex_as_text, store_reset),
		cmocka_unit_test_setup(test_store_keeps_multipart_output_verbatim, store_reset),
		cmocka_unit_test_setup(test_store_strips_a_value_wearing_units, store_reset),
		cmocka_unit_test_setup(test_store_rejects_a_value_with_no_number_in_it, store_reset),
		cmocka_unit_test_setup(test_store_rejects_an_empty_result, store_reset),
		cmocka_unit_test_setup(test_store_rejects_null_arguments, store_reset),
		cmocka_unit_test_setup(test_store_matches_the_chain_it_replaced, store_reset),
		cmocka_unit_test_setup(test_snmp_batch_copies_numeric_results_to_their_targets, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_honours_array_position, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_counts_undefined_results_as_rejected, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_blanks_everything_for_an_ignored_host, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_converts_a_delimited_octet_string, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_applies_the_data_source_output_regex, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_spike_kill_blanks_a_scalar_but_not_multipart, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_handles_an_empty_batch, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_rejects_null_arguments, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_rejects_a_value_that_fails_validation, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_outcome_is_the_same_at_log_level_two, snmp_reset),
		cmocka_unit_test_setup(test_snmp_batch_outcome_is_the_same_for_a_debug_device, snmp_reset),
		cmocka_unit_test_setup(test_store_outcome_is_the_same_at_log_level_two, store_reset),
		cmocka_unit_test(test_build_queries_gates_on_rrd_next_step_for_multiple_profiles),
		cmocka_unit_test(test_build_queries_multiple_profiles_scope_a_remote_poller),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
