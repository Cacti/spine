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

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stddef.h>

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

/* --- get_date_format(): cached storage, rebuilt by set_date_format() ------ */

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

/* ---------------------------------------------------------------------------
 * Child process hardening (nft_popen.c)
 *
 * PR #542 removed the close-on-exec and bounded-reap code PR #557 had just
 * added, and nothing failed, because the only guard was a shell script that
 * grepped the source and was deleted in the same commit. These exercise the
 * behaviour against the shipped object instead.
 * ------------------------------------------------------------------------- */

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

/* The descriptor must not survive an exec. A child that inherits the write end
   keeps the pipe open, so the polling thread never sees EOF and blocks to
   script_timeout for a data source that already answered. */
static void test_pipe_is_not_inherited_across_exec(void **state) {
	int pdes[2];
	int status;
	pid_t pid;
	char fdarg[32];

	(void) state;

	assert_true(spine_open_pipe_cloexec(pdes));
	snprintf(fdarg, sizeof(fdarg), "/proc/self/fd/%d", pdes[1]);

	pid = fork();
	assert_true(pid >= 0);

	if (pid == 0) {
		/* exits 0 when the descriptor survived exec, 1 when it did not */
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

/* ---------------------------------------------------------------------------
 * spine_appendf (util.c)
 *
 * Replaces `p += snprintf(p, remaining, ...)`, which advances by the length
 * snprintf *would* have written, so the first truncation puts the cursor past
 * the end and the next `remaining` underflows to a huge size_t.
 * ------------------------------------------------------------------------- */

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

/* Documents the defect: the same sequence with the old idiom leaves the cursor
   outside the buffer, so the next remainder is negative. */
static void test_old_idiom_overshoots_where_appendf_does_not(void **state) {
	char buf[32];
	char *p = buf;
	ptrdiff_t old_offset;
	char *q;
	size_t remaining;

	(void) state;

	p += snprintf(p, sizeof(buf), "%s", "0123456789012345678901234567890123456789");
	old_offset = p - buf;
	assert_true(old_offset > (ptrdiff_t) sizeof(buf));
	assert_true((ptrdiff_t) (sizeof(buf) - old_offset) < 0);

	q = buf;
	remaining = sizeof(buf);
	assert_false(spine_appendf(&q, &remaining, "%s", "0123456789012345678901234567890123456789"));
	assert_true(q - buf < (ptrdiff_t) sizeof(buf));

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


/* ---------------------------------------------------------------------------
 * poll_host_build_queries()
 *
 * poll_host() is 1,600+ lines and builds its SQL inline, so none of this was
 * reachable from a test. The construction now lives in its own function, and
 * these pin what it emits across every input it branches on, against the
 * fixture in tests/golden/poll_host_queries.golden.
 * ------------------------------------------------------------------------- */

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

/* The defect the extraction exposed: the remote branch had its own copy of
   this suffix and never picked up the version check. */
static void test_build_queries_applies_dbonupdate_on_both_poller_types(void **state) {
	poll_host_queries_t q;

	(void) state;

	build_with(&q, 0, 1, 0);
	assert_string_equal(q.posuffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)");
	build_with(&q, 0, 1, 1);
	assert_string_equal(q.posuffix, " AS rs ON DUPLICATE KEY UPDATE output=rs.output");

	build_with(&q, 7, 1, 0);
	assert_string_equal(q.posuffix, " ON DUPLICATE KEY UPDATE output=VALUES(output)");
	build_with(&q, 7, 1, 1);
	assert_string_equal(q.posuffix, " AS rs ON DUPLICATE KEY UPDATE output=rs.output");
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

/* The golden fixture, executed rather than documented. Regenerate it with
   SPINE_WRITE_GOLDEN=1 and read the diff before committing the result. */
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
	for (i = 0; i < 2; i++) {
		for (j = 0; j < 2; j++) {
			build_with(&q, pid[j], ports[i], onupd[j]);
			fprintf(f, "== REMOTE ports=%d onupd=%d pid=%d ==\n", ports[i], onupd[j], pid[j]);
			emit_one(f, "remote", &q);
		}
	}
}

static void test_build_queries_matches_the_golden_capture(void **state) {
	const char *path = getenv("SPINE_GOLDEN");
	char actual[] = "/tmp/spine_golden_actual.XXXXXX";
	FILE *f;
	FILE *g;
	int fd;
	int line = 0;
	char a[BIG_BUFSIZE];
	char b[BIG_BUFSIZE];

	(void) state;

	if (path == NULL) {
		path = "tests/golden/poll_host_queries.golden";
	}

	g = fopen(path, "r");
	if (g == NULL) {
		print_message("golden fixture %s not readable, skipping\n", path);
		return;
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


/* ---------------------------------------------------------------------------
 * reindex_assert_failed (poller.c)
 *
 * The data query reindex assert, which decides whether Cacti re-runs a data
 * query. It was written out three times inside poll_host(), once per operator,
 * with about twenty-four identical lines of logging and queueing around each.
 * ------------------------------------------------------------------------- */

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

/* The uptime case: a device with no uptime recorded yet must not look like it
   rebooted, so a stored "0" never fails a '<' assert. */
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

/* Large uptimes overflow a 32-bit compare; sysUpTime is centiseconds and wraps
   past INT_MAX in under a year. */
static void test_assert_handles_values_beyond_32_bits(void **state) {
	(void) state;

	assert_true(reindex_assert_failed("<", "4294967296", "4294967295"));
	assert_false(reindex_assert_failed("<", "4294967295", "4294967296"));
}


/* With more than one polling profile active, query5 and query10 additionally
   filter on rrd_next_step so only items due this tick are polled. Both queries
   are built either way; only the filter differs. */
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
		cmocka_unit_test(test_get_date_format_returns_cached_storage),
		cmocka_unit_test(test_set_date_format_clamps_an_out_of_range_format),
		cmocka_unit_test(test_get_date_format_covers_each_supported_format),
		cmocka_unit_test(test_is_debug_device_matches_only_listed_ids),
		cmocka_unit_test(test_cloexec_is_set_on_both_pipe_ends),
		cmocka_unit_test(test_cloexec_pipe_is_a_working_pipe),
		cmocka_unit_test(test_pipe_is_not_inherited_across_exec),
		cmocka_unit_test(test_reap_returns_still_running_rather_than_blocking),
		cmocka_unit_test(test_reap_collects_an_exited_child),
		cmocka_unit_test(test_reap_reports_an_already_reaped_child),
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
		cmocka_unit_test(test_build_queries_applies_dbonupdate_on_both_poller_types),
		cmocka_unit_test(test_build_queries_caches_the_lengths_the_result_loop_uses),
		cmocka_unit_test(test_build_queries_fills_every_buffer),
		cmocka_unit_test(test_build_queries_matches_the_golden_capture),
		cmocka_unit_test(test_assert_equal_compares_as_text),
		cmocka_unit_test(test_assert_greater_compares_as_numbers),
		cmocka_unit_test(test_assert_less_compares_as_numbers),
		cmocka_unit_test(test_assert_equal_values_do_not_fail_an_ordering_assert),
		cmocka_unit_test(test_assert_zero_never_fails_a_less_than),
		cmocka_unit_test(test_assert_holds_when_the_device_gave_nothing_usable),
		cmocka_unit_test(test_assert_ignores_an_unknown_operator),
		cmocka_unit_test(test_assert_rejects_null_arguments),
		cmocka_unit_test(test_assert_handles_values_beyond_32_bits),
		cmocka_unit_test(test_build_queries_gates_on_rrd_next_step_for_multiple_profiles),
		cmocka_unit_test(test_build_queries_multiple_profiles_scope_a_remote_poller),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
