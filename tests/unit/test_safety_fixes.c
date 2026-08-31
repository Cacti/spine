/*
 * Unit tests for the spine safety fixes on fix/spine-c-bugfixes.
 *
 * Each test is a regression guard for a specific commit on this branch:
 *   - get_date_format(): missing `break` in the format switch (every value
 *     fell through to the default).            -- util.c
 *   - get_namebyhost(): strncasecmp() result tested for truth instead of == 0,
 *     and the wrong buffer/length passed.       -- ping.c
 *   - ping_icmp(): ICMP reply length validated before dereferencing headers.
 *                                               -- ping.c
 *   - set_option(): override table bounded before write.   -- util.c
 *   - php_readpipe(): read bounded to RESULTS_BUFFER-1.     -- php.c
 *
 * Like test_build_fixes.c, the functions under test are inlined (or their
 * exact predicate replicated) so this translation unit compiles standalone
 * without linking util.o/ping.o/php.o and dragging in MySQL/SNMP.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/* -------------------------------------------------------------------------
 * Constants copied from spine.h so the file is self-contained (test_build_fixes.c
 * does the same for BUFSIZE et al).  Values match spine.h on this branch.
 * ------------------------------------------------------------------------- */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

#define BUFSIZE       1024	/* spine.h:137 */
#define SMALL_BUFSIZE 256	/* spine.h:135 */

/* date format / separator codes (spine.h:250-267) */
#define GDC_MIN     0
#define GDC_HYPHEN  0
#define GDC_SLASH   1
#define GDC_DOT     2
#define GDC_MAX     2
#define GDC_DEFAULT 1

#define GD_FMT_SIZE 21
#define GD_MIN      0
#define GD_MO_D_Y   0
#define GD_MN_D_Y   1
#define GD_D_MO_Y   2
#define GD_D_MN_Y   3
#define GD_Y_MO_D   4
#define GD_Y_MN_D   5
#define GD_MAX      5
#define GD_DEFAULT  5

#define ICMP_HDR_SIZE 8

/* configure default; --with-results-buffer overrides it (configure.ac:394) */
#define RESULTS_BUFFER 2048

/* name_t from spine.h:599-604 */
typedef struct {
	char hostname[BUFSIZE];
	int  method;
	int  port;
} name_t;

/* -------------------------------------------------------------------------
 * 1. get_date_format() -- regression guard for the missing-`break` fix.
 *
 * Verbatim copy of util.c:1239-1292 with the two switch fields promoted to
 * function arguments instead of the global `set`.  The malloc()/die() path is
 * dropped (irrelevant to the bug); everything else is unchanged.
 * ------------------------------------------------------------------------- */
static void get_date_format_impl(char *log_fmt, int sep_code, int fmt_code) {
	char log_sep = '/';

	if (sep_code < GDC_MIN || sep_code > GDC_MAX) {
		sep_code = GDC_DEFAULT;
	}
	if (fmt_code < GD_MIN || fmt_code > GD_MAX) {
		fmt_code = GD_DEFAULT;
	}

	switch (sep_code) {
		case GDC_DOT:    log_sep = '.'; break;
		case GDC_HYPHEN: log_sep = '-'; break;
		default:         log_sep = '/'; break;
	}

	switch (fmt_code) {
		case GD_MO_D_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%m%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_MN_D_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%b%c%%d%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MO_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%d%c%%m%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_D_MN_Y:
			snprintf(log_fmt, GD_FMT_SIZE, "%%d%c%%b%c%%Y %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MO_D:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		case GD_Y_MN_D:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%b%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
		default:
			snprintf(log_fmt, GD_FMT_SIZE, "%%Y%c%%m%c%%d %%H:%%M:%%S - ", log_sep, log_sep);
			break;
	}
}

static void test_date_format_each_code_differs(void **state) {
	(void)state;

	char fmt[GD_MAX + 1][GD_FMT_SIZE];
	const int codes[] = {
		GD_MO_D_Y, GD_MN_D_Y, GD_D_MO_Y, GD_D_MN_Y, GD_Y_MO_D, GD_Y_MN_D
	};

	for (size_t i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		get_date_format_impl(fmt[i], GDC_SLASH, codes[i]);
	}

	/* The bug: without the `break`s every code fell through to GD_Y_MN_D's
	 * body (and then the default), so all strings were identical.  Demand the
	 * month-leading vs day-leading vs year-leading orderings actually differ. */
	assert_string_equal(fmt[GD_MO_D_Y], "%m/%d/%Y %H:%M:%S - ");
	assert_string_equal(fmt[GD_MN_D_Y], "%b/%d/%Y %H:%M:%S - ");
	assert_string_equal(fmt[GD_D_MO_Y], "%d/%m/%Y %H:%M:%S - ");
	assert_string_equal(fmt[GD_D_MN_Y], "%d/%b/%Y %H:%M:%S - ");
	assert_string_equal(fmt[GD_Y_MO_D], "%Y/%m/%d %H:%M:%S - ");
	assert_string_equal(fmt[GD_Y_MN_D], "%Y/%b/%d %H:%M:%S - ");

	/* Two representative pairs must be distinct (the fall-through bug made
	 * MO_D_Y produce the same string as the default Y_MN_D). */
	assert_string_not_equal(fmt[GD_MO_D_Y], fmt[GD_Y_MN_D]);
	assert_string_not_equal(fmt[GD_D_MO_Y], fmt[GD_Y_MO_D]);
}

static void test_date_format_separator_applied(void **state) {
	(void)state;

	char dot[GD_FMT_SIZE], hyphen[GD_FMT_SIZE];
	get_date_format_impl(dot, GDC_DOT, GD_Y_MO_D);
	get_date_format_impl(hyphen, GDC_HYPHEN, GD_Y_MO_D);

	assert_string_equal(dot, "%Y.%m.%d %H:%M:%S - ");
	assert_string_equal(hyphen, "%Y-%m-%d %H:%M:%S - ");
}

static void test_date_format_out_of_range_falls_to_default(void **state) {
	(void)state;

	char fmt[GD_FMT_SIZE];
	get_date_format_impl(fmt, GDC_SLASH, GD_MAX + 99);
	assert_string_equal(fmt, "%Y/%b/%d %H:%M:%S - ");   /* GD_DEFAULT == GD_Y_MN_D */
}

/* -------------------------------------------------------------------------
 * 2. get_namebyhost() -- regression guard for the strncasecmp `== 0` fix and
 * the strncopy off-by-one that truncated the tokenizer buffer by one byte.
 *
 * The original code wrote `if (strncasecmp(token, "TCP", 3))`, which is true
 * for *non*-matches, so "TCP:host:80" never set method=1, while a bare "host"
 * (where strncasecmp != 0) accidentally took the TCP branch.  It also called
 * `strncopy(stack, hostname, strlen(hostname))`: strncopy treats the third
 * arg as the buffer size *including* the NUL, so that dropped the final char
 * of the source.  We mirror the fixed source exactly -- heap stack sized to
 * strlen(hostname)+1 and strncopy() passed that full size -- so a regression
 * to the one-short copy reproduces here and fails the assertions below.
 * ------------------------------------------------------------------------- */

/* Mirror of util.c strncopy(): obuf includes the terminating NUL. */
static char *strncopy_local(char *dst, const char *src, size_t obuf) {
	size_t copy_len;

	if (obuf == 0) return dst;

	copy_len = strnlen(src, obuf - 1);
	if (copy_len) {
		strncpy(dst, src, copy_len);
	}
	dst[copy_len] = '\0';
	return dst;
}

static void parse_host_impl(const char *hostname, name_t *name) {
	memset(name, 0, sizeof(*name));

	char *stack = malloc(strlen(hostname) + 1);
	assert_non_null(stack);
	memset(stack, '\0', strlen(hostname) + 1);
	strncopy_local(stack, hostname, strlen(hostname) + 1);

	int tokens = 0;
	char *save = NULL;
	char *token = strtok_r(stack, ":", &save);

	if (token == NULL) {
		strncopy_local(name->hostname, hostname, SMALL_BUFSIZE);
		free(stack);
		return;
	}

	while (token != NULL && tokens <= 3) {
		tokens++;
		if (tokens == 1) {
			if (strlen(token) && token[0] == '[') {
				strncpy(name->hostname, hostname, sizeof(name->hostname) - 1);
				break;
			} else if (strlen(token) == 3) {
				if (strncasecmp(token, "TCP", 3) == 0) {
					name->method = 1;
				} else if (strncasecmp(token, "UDP", 3) == 0) {
					name->method = 2;
				} else {
					tokens++;   /* no method; this token is the host */
				}
			} else if (strlen(token) == 4) {
				if (strncasecmp(token, "TCP6", 4) == 0) {
					name->method = 3;
				} else if (strncasecmp(token, "UDP6", 4) == 0) {
					name->method = 4;
				} else {
					tokens++;
				}
			} else {
				tokens++;
			}
		}

		if (tokens == 2) {
			strncpy(name->hostname, token, sizeof(name->hostname) - 1);
			name->hostname[strlen(token)] = '\0';
		}

		if (tokens == 3 && strlen(token)) {
			name->port = atoi(token);
		}

		token = strtok_r(NULL, ":", &save);
	}

	free(stack);
}

static void test_host_tcp(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("TCP:host:80", &n);
	assert_int_equal(n.method, 1);
	assert_string_equal(n.hostname, "host");
	/* The off-by-one copy dropped the final byte of the tokenizer buffer,
	 * turning "80" into "8"; assert the full port survives. */
	assert_int_equal(n.port, 80);
}

static void test_host_udp(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("UDP:host:53", &n);
	assert_int_equal(n.method, 2);
	assert_string_equal(n.hostname, "host");
	assert_int_equal(n.port, 53);
}

static void test_host_tcp6(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("TCP6:host:80", &n);
	assert_int_equal(n.method, 3);
	assert_string_equal(n.hostname, "host");
	assert_int_equal(n.port, 80);
}

static void test_host_udp6(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("UDP6:host:53", &n);
	assert_int_equal(n.method, 4);
	assert_string_equal(n.hostname, "host");
	assert_int_equal(n.port, 53);
}

static void test_host_bare(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("host", &n);
	/* No method prefix: a bare host must NOT be classified as TCP. */
	assert_int_equal(n.method, 0);
	assert_string_equal(n.hostname, "host");
	assert_int_equal(n.port, 0);
}

/* Full-hostname round-trips: each must keep its final byte.  Under the
 * one-short copy "snmpd" parsed as "snmp", "127.0.0.1" lost its trailing
 * "1", and the method-prefixed host without a port lost its last char. */
static void test_host_bare_full(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("snmpd", &n);
	assert_int_equal(n.method, 0);
	assert_string_equal(n.hostname, "snmpd");
	assert_int_equal(n.port, 0);
}

static void test_host_ipv4_full(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("127.0.0.1", &n);
	assert_int_equal(n.method, 0);
	assert_string_equal(n.hostname, "127.0.0.1");
	assert_int_equal(n.port, 0);
}

static void test_host_tcp_noport_full(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("TCP:server", &n);
	assert_int_equal(n.method, 1);
	assert_string_equal(n.hostname, "server");
	assert_int_equal(n.port, 0);
}

static void test_host_udp_port_full(void **state) {
	(void)state;
	name_t n;
	parse_host_impl("UDP:router1:161", &n);
	assert_int_equal(n.method, 2);
	assert_string_equal(n.hostname, "router1");
	assert_int_equal(n.port, 161);
}

/* -------------------------------------------------------------------------
 * 3. ICMP reply length validation -- guard for the ping.c length check.
 *
 * Replicates the exact predicate added in ping_icmp() (ping.c:443-457):
 * accept the reply only when it can hold the IP header, a sane ihl, and the
 * ICMP header after the IP options.  Returns TRUE for accept, FALSE for reject.
 * ------------------------------------------------------------------------- */
static int icmp_len_ok(const unsigned char *socket_reply, ssize_t return_code) {
	int ihl;
	const struct ip *ip;

	if (return_code < (ssize_t)sizeof(struct ip)) {
		return FALSE;
	}

	ip  = (const struct ip *) socket_reply;
	ihl = ip->ip_hl << 2;

	if (ihl < (int)sizeof(struct ip) || return_code < (ssize_t)(ihl + ICMP_HDR_SIZE)) {
		return FALSE;
	}

	return TRUE;
}

/* Build a reply buffer with a given ip_hl (in 32-bit words) and total length. */
static void make_reply(unsigned char *buf, size_t buf_size, int ihl_words) {
	struct ip iph;
	memset(&iph, 0, sizeof(iph));
	iph.ip_hl = ihl_words & 0x0f;
	iph.ip_v  = 4;
	memset(buf, 0, buf_size);
	memcpy(buf, &iph, sizeof(iph));
}

static void test_icmp_runt_below_ip_header(void **state) {
	(void)state;
	unsigned char buf[64];
	make_reply(buf, sizeof(buf), 5);
	/* fewer bytes than a bare IP header */
	assert_int_equal(icmp_len_ok(buf, (ssize_t)sizeof(struct ip) - 1), FALSE);
}

static void test_icmp_short_ihl_rejected(void **state) {
	(void)state;
	unsigned char buf[64];
	/* ip_hl claims 1 word (4 bytes) -- smaller than a real IP header */
	make_reply(buf, sizeof(buf), 1);
	assert_int_equal(icmp_len_ok(buf, 40), FALSE);
}

static void test_icmp_len_below_ihl_plus_icmp(void **state) {
	(void)state;
	unsigned char buf[64];
	make_reply(buf, sizeof(buf), 5);   /* ihl = 20 */
	/* one byte short of ihl + ICMP header */
	assert_int_equal(icmp_len_ok(buf, 20 + ICMP_HDR_SIZE - 1), FALSE);
}

static void test_icmp_valid_reply_accepted(void **state) {
	(void)state;
	unsigned char buf[64];
	make_reply(buf, sizeof(buf), 5);   /* ihl = 20 */
	assert_int_equal(icmp_len_ok(buf, 20 + ICMP_HDR_SIZE), TRUE);
	assert_int_equal(icmp_len_ok(buf, 28 + 16), TRUE);   /* extra payload */
}

static void test_icmp_valid_with_ip_options(void **state) {
	(void)state;
	unsigned char buf[64];
	make_reply(buf, sizeof(buf), 6);   /* ihl = 24 (one options word) */
	assert_int_equal(icmp_len_ok(buf, 24 + ICMP_HDR_SIZE - 1), FALSE);
	assert_int_equal(icmp_len_ok(buf, 24 + ICMP_HDR_SIZE), TRUE);
}

/* -------------------------------------------------------------------------
 * 4. set_option() override-table bound -- guard for the nopts >= size check.
 *
 * set_option() calls die() (which exit()s) when the table is full, so the
 * overflow path is exercised in a forked child.  We reproduce the real array
 * (256 entries) and the exact bound expression.
 * ------------------------------------------------------------------------- */
static struct {
	const char *opt;
	const char *val;
} opttable[256];
static int nopts;

static void set_option_bounded(const char *option, const char *value) {
	if (nopts >= (int)(sizeof(opttable) / sizeof(opttable[0]))) {
		_exit(2);   /* stands in for die() -- non-zero exit in the child */
	}
	opttable[nopts  ].opt = option;
	opttable[nopts++].val = value;
}

/* Push `count` options in a forked child; return the child's exit status. */
static int run_set_option_child(int count) {
	pid_t pid = fork();
	assert_int_not_equal(pid, -1);

	if (pid == 0) {
		nopts = 0;
		memset(opttable, 0, sizeof(opttable));
		for (int i = 0; i < count; i++) {
			set_option_bounded("opt", "val");
		}
		_exit(0);
	}

	int status = 0;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
		;
	}
	return status;
}

static void test_set_option_fits_exactly(void **state) {
	(void)state;
	int cap = (int)(sizeof(opttable) / sizeof(opttable[0]));
	int status = run_set_option_child(cap);   /* exactly fill the table */
	assert_true(WIFEXITED(status));
	assert_int_equal(WEXITSTATUS(status), 0);
}

static void test_set_option_overflow_dies(void **state) {
	(void)state;
	int cap = (int)(sizeof(opttable) / sizeof(opttable[0]));
	int status = run_set_option_child(cap + 1);   /* one past the end */
	assert_true(WIFEXITED(status));
	assert_int_not_equal(WEXITSTATUS(status), 0);
}

/* -------------------------------------------------------------------------
 * 5. php_readpipe() bounded read -- guard for the RESULTS_BUFFER-1 fix.
 *
 * Drives a real pipe(2): the writer floods more than RESULTS_BUFFER bytes with
 * no newline; the reader mirrors the fixed loop (space = RESULTS_BUFFER-1-off,
 * NUL written at bptr, break when space exhausted).  A canary byte after the
 * buffer must survive, and the result must be NUL-terminated within bounds.
 * ------------------------------------------------------------------------- */
static void test_php_readpipe_bounded(void **state) {
	(void)state;

	/* result_string is RESULTS_BUFFER; canary follows immediately. */
	struct {
		char result[RESULTS_BUFFER];
		char canary;
	} mem;
	mem.canary = (char)0xA5;
	memset(mem.result, 0, sizeof(mem.result));

	int fds[2];
	assert_int_equal(pipe(fds), 0);

	/* Flood the pipe with no newline so the consumer hits the size bound. */
	const size_t flood = RESULTS_BUFFER * 2;
	char *chunk = malloc(flood);
	assert_non_null(chunk);
	memset(chunk, 'x', flood);

	size_t written = 0;
	while (written < flood) {
		ssize_t w = write(fds[1], chunk + written, flood - written);
		if (w <= 0) break;
		written += (size_t)w;
	}
	close(fds[1]);   /* EOF once drained */

	/* Consumer loop mirroring php.c:261-290. */
	char *bptr = mem.result;
	int terminated_within_bounds = 0;
	while (1) {
		size_t used = (size_t)(bptr - mem.result);
		if (used >= RESULTS_BUFFER - 1) {
			break;
		}

		size_t space = (size_t)RESULTS_BUFFER - 1 - used;
		ssize_t i = read(fds[0], bptr, space);
		if (i <= 0) {
			break;
		}

		bptr += i;
		*bptr = '\0';   /* must stay inside result[] */
		terminated_within_bounds = (bptr < mem.result + RESULTS_BUFFER);

		if (strstr(mem.result, "\n") != 0) {
			break;
		}

		if (bptr >= mem.result + RESULTS_BUFFER - 1) {
			break;
		}
	}
	close(fds[0]);
	free(chunk);

	/* The terminating NUL must land at result[RESULTS_BUFFER-1] at the latest. */
	assert_true(terminated_within_bounds);
	assert_int_equal(mem.canary, (char)0xA5);   /* no write past the buffer */
	assert_int_equal(mem.result[RESULTS_BUFFER - 1], '\0');
	assert_true(strlen(mem.result) <= RESULTS_BUFFER - 1);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------
 * spine_log(): the newline must not be written past flogmessage
 *
 * The strncat() calls above the append are allowed to fill the buffer
 * exactly, after which strcat() wrote the newline at LOGSIZE-1 and its
 * terminator at LOGSIZE.  A canary byte follows the buffer here so the
 * overflow is observable rather than merely undefined.  issue#565
 * ---------------------------------------------------------------------- */

#define TEST_LOGSIZE 16

static void append_newline(char *flogmessage, size_t logsize) {
	if (!strstr(flogmessage, "\n")) {
		size_t flog_used = strlen(flogmessage);

		if (flog_used < logsize - 1) {
			flogmessage[flog_used]     = '\n';
			flogmessage[flog_used + 1] = '\0';
		} else {
			flogmessage[logsize - 2] = '\n';
			flogmessage[logsize - 1] = '\0';
		}
	}
}

static void test_log_newline_fits_when_room_remains(void **state) {
	struct { char buf[TEST_LOGSIZE]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strcpy(b.buf, "short");
	append_newline(b.buf, TEST_LOGSIZE);

	assert_string_equal(b.buf, "short\n");
	assert_int_equal(b.canary, 0xAA);
}

static void test_log_newline_does_not_overflow_a_full_buffer(void **state) {
	struct { char buf[TEST_LOGSIZE]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	/* fill the buffer exactly: 15 characters plus the terminator */
	memset(b.buf, 'x', TEST_LOGSIZE - 1);
	b.buf[TEST_LOGSIZE - 1] = '\0';

	append_newline(b.buf, TEST_LOGSIZE);

	assert_int_equal(b.canary, 0xAA);
	assert_int_equal(strlen(b.buf), TEST_LOGSIZE - 1);
	assert_int_equal(b.buf[TEST_LOGSIZE - 2], '\n');
}

static void test_log_newline_left_alone_when_already_present(void **state) {
	struct { char buf[TEST_LOGSIZE]; unsigned char canary; } b;
	(void) state;

	memset(&b, 0xAA, sizeof b);
	strcpy(b.buf, "has\nnewline");
	append_newline(b.buf, TEST_LOGSIZE);

	assert_string_equal(b.buf, "has\nnewline");
	assert_int_equal(b.canary, 0xAA);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_log_newline_fits_when_room_remains),
		cmocka_unit_test(test_log_newline_does_not_overflow_a_full_buffer),
		cmocka_unit_test(test_log_newline_left_alone_when_already_present),
		/* date format (missing break) */
		cmocka_unit_test(test_date_format_each_code_differs),
		cmocka_unit_test(test_date_format_separator_applied),
		cmocka_unit_test(test_date_format_out_of_range_falls_to_default),

		/* host method parsing (strncasecmp == 0) */
		cmocka_unit_test(test_host_tcp),
		cmocka_unit_test(test_host_udp),
		cmocka_unit_test(test_host_tcp6),
		cmocka_unit_test(test_host_udp6),
		cmocka_unit_test(test_host_bare),
		cmocka_unit_test(test_host_bare_full),
		cmocka_unit_test(test_host_ipv4_full),
		cmocka_unit_test(test_host_tcp_noport_full),
		cmocka_unit_test(test_host_udp_port_full),

		/* icmp reply length validation */
		cmocka_unit_test(test_icmp_runt_below_ip_header),
		cmocka_unit_test(test_icmp_short_ihl_rejected),
		cmocka_unit_test(test_icmp_len_below_ihl_plus_icmp),
		cmocka_unit_test(test_icmp_valid_reply_accepted),
		cmocka_unit_test(test_icmp_valid_with_ip_options),

		/* set_option override-table bound */
		cmocka_unit_test(test_set_option_fits_exactly),
		cmocka_unit_test(test_set_option_overflow_dies),

		/* php_readpipe bounded read */
		cmocka_unit_test(test_php_readpipe_bounded),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
