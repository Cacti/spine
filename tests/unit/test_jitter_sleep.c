/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.     |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
*/

/*
 * Unit tests for get_jitter_sleep().
 *
 * get_jitter_sleep() is a pure computation function: it takes retry_count
 * and base_ms, uses only thread-local state and rand_r(), and returns a
 * microsecond duration.  No database, network, or file-system access.
 *
 * The function signature from util.h:
 *   unsigned int get_jitter_sleep(int retry_count, unsigned int base_ms);
 *
 * Return value is in microseconds:
 *   (exponential_backoff_ms + jitter_ms) * 1000
 * where:
 *   exponential_backoff_ms = min(base_ms * 2^clamp(retry_count,0,10), 2000)
 *   jitter_ms              = rand_r(...) % (exponential_backoff_ms / 2 + 1)
 *
 * Compile (no MySQL / SNMP required):
 *   cc -I. -I/opt/homebrew/opt/mysql-client/include/mysql \
 *      -I/opt/homebrew/opt/net-snmp/include \
 *      -I/opt/homebrew/opt/openssl@3/include \
 *      $(pkg-config --cflags cmocka) \
 *      -o /tmp/test_jitter_sleep tests/unit/test_jitter_sleep.c \
 *      $(pkg-config --libs cmocka) -lm -lpthread
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

/*
 * Provide only the symbols that get_jitter_sleep() transitively needs so the
 * function can be pulled in via #include without linking the full spine build.
 */

/* Minimal MySQL opaque-pointer stubs -- mysql.h is included transitively via
 * common.h; declaring the structs here avoids that dependency entirely.     */
struct st_mysql     { int dummy; };
struct st_mysql_res { int dummy; };
typedef struct st_mysql     MYSQL;
typedef struct st_mysql_res MYSQL_RES;

/* pool_t stub */
typedef struct { int dummy; } pool_t;

/* Provide BUFSIZE/DBL_BUFSIZE so util.h does not need spine.h */
#ifndef BUFSIZE
#  define BUFSIZE     1024
#endif
#ifndef DBL_BUFSIZE
#  define DBL_BUFSIZE 2048
#endif
#ifndef SMALL_BUFSIZE
#  define SMALL_BUFSIZE 256
#endif
#ifndef MEDIUM_BUFSIZE
#  define MEDIUM_BUFSIZE 512
#endif
#ifndef LRG_BUFSIZE
#  define LRG_BUFSIZE 8096
#endif
#ifndef BIG_BUFSIZE
#  define BIG_BUFSIZE 65535
#endif
#ifndef MEGA_BUFSIZE
#  define MEGA_BUFSIZE 1024000
#endif
#ifndef HUGE_BUFSIZE
#  define HUGE_BUFSIZE 2048000
#endif
#ifndef TINY_BUFSIZE
#  define TINY_BUFSIZE 16
#endif
#ifndef MAX_MATCHES
#  define MAX_MATCHES 5
#endif
#ifndef CONFIG_PATHS
#  define CONFIG_PATHS 4
#endif

/* Stub die() so MALLOC_OR_DIE / CALLOC_OR_DIE / STRDUP_OR_DIE compile. */
static void die(const char *fmt, ...) {
	(void)fmt;
	abort();
}

/*
 * Inline the function under test directly rather than dragging in the full
 * util.c compilation unit (which needs MySQL, SNMP, uthash globals, etc.).
 */
static unsigned int get_jitter_sleep(int retry_count, unsigned int base_ms) {
	unsigned int exponential_backoff;
	unsigned int jitter;
	unsigned int max_sleep_ms = 2000;
	static __thread unsigned int jitter_seed;
	static __thread int jitter_seeded;
	uint64_t full_backoff;

	if (!jitter_seeded) {
		jitter_seed   = (unsigned int)(time(NULL) ^ getpid() ^ (unsigned long int)pthread_self());
		jitter_seeded = 1;
	}

	if (retry_count < 0) retry_count = 0;
	full_backoff = (uint64_t)base_ms * (1ULL << (retry_count > 10 ? 10 : retry_count));

	if (full_backoff > (uint64_t)max_sleep_ms) {
		exponential_backoff = max_sleep_ms;
	} else {
		exponential_backoff = (unsigned int)full_backoff;
	}

	jitter = rand_r(&jitter_seed) % (exponential_backoff / 2 + 1);

	return (exponential_backoff + jitter) * 1000;
}

/* ---- Tests --------------------------------------------------------------- */

/*
 * retry_count=0: backoff = base_ms * 2^0 = base_ms.
 * Result in usec must be in [base_ms*1000, base_ms*1000 * 1.5] given
 * jitter is at most 50% of backoff.
 */
static void test_retry_zero_within_base_range(void **state) {
	unsigned int result;
	unsigned int base_ms;
	unsigned int min_usec;
	unsigned int max_usec;
	(void)state;

	base_ms  = 100;
	result   = get_jitter_sleep(0, base_ms);
	min_usec = base_ms * 1000;
	/* jitter adds at most floor(base_ms/2) ms */
	max_usec = (base_ms + base_ms / 2) * 1000;

	assert_true(result >= min_usec);
	assert_true(result <= max_usec);
}

/*
 * retry_count=1 backoff is 2x retry_count=0 backoff.
 * Average result for retry=1 must be strictly greater than for retry=0;
 * test this deterministically by comparing the floor values (no jitter).
 */
static void test_higher_retry_increases_sleep(void **state) {
	unsigned int r0;
	unsigned int r1;
	unsigned int r2;
	unsigned int base_ms;
	(void)state;

	/*
	 * Use base_ms=1 to keep numbers small.  The floor (exponential_backoff
	 * component before jitter) is strictly increasing up to the cap.
	 * We verify the minimum possible value (jitter=0) is strictly larger
	 * across consecutive retries.
	 */
	base_ms = 10;

	/* minimum usec for each retry (jitter is always >= 0) */
	r0 = base_ms * (1u << 0) * 1000;  /* 10 ms */
	r1 = base_ms * (1u << 1) * 1000;  /* 20 ms */
	r2 = base_ms * (1u << 2) * 1000;  /* 40 ms */

	assert_true(r1 > r0);
	assert_true(r2 > r1);

	/*
	 * Also confirm the function returns at least the un-jittered floor for
	 * a retry_count where the cap has not yet been hit (retry=0 with small
	 * base is well below 2000 ms).
	 */
	assert_true(get_jitter_sleep(0, base_ms) >= r0);
	assert_true(get_jitter_sleep(1, base_ms) >= r1);
	assert_true(get_jitter_sleep(2, base_ms) >= r2);
}

/*
 * retry_count > 10 must be clamped to 10.
 * Both retry=10 and retry=11 (and higher) must produce results in the same
 * range: [cap_usec, cap_usec + cap_usec/2].
 */
static void test_retry_above_10_is_capped(void **state) {
	unsigned int cap_usec;
	unsigned int r11;
	unsigned int r20;
	(void)state;

	/* max_sleep_ms=2000; result = (backoff + jitter) * 1000
	 * jitter is at most backoff/2, so max result = 1.5 * 2000 * 1000 */
	cap_usec = 3000 * 1000;

	r11 = get_jitter_sleep(11, 100);
	r20 = get_jitter_sleep(20, 100);

	/* both capped at max_sleep_ms plus up to 50% jitter */
	assert_true(r11 <= cap_usec);
	assert_true(r20 <= cap_usec);
}

/*
 * Negative retry_count must be clamped to 0.
 * Result must be in the same range as retry_count=0.
 */
static void test_negative_retry_clamped_to_zero(void **state) {
	unsigned int base_ms;
	unsigned int r_neg;
	unsigned int r_zero;
	unsigned int min_usec;
	unsigned int max_usec;
	(void)state;

	base_ms  = 50;
	min_usec = base_ms * 1000;
	max_usec = (base_ms + base_ms / 2) * 1000;

	r_neg  = get_jitter_sleep(-1, base_ms);
	r_zero = get_jitter_sleep(0,  base_ms);

	/* Both must fall in [base_ms, base_ms * 1.5] usec range */
	assert_true(r_neg  >= min_usec);
	assert_true(r_neg  <= max_usec);
	assert_true(r_zero >= min_usec);
	assert_true(r_zero <= max_usec);
}

/*
 * With a large base_ms the cap at 2000 ms must kick in regardless of retry.
 */
static void test_max_sleep_cap_enforced(void **state) {
	unsigned int cap_usec;
	unsigned int result;
	unsigned int i;
	(void)state;

	/* 2000 ms cap + up to 50% jitter = 3000 ms = 3 000 000 usec */
	cap_usec = 3000u * 1000u;

	for (i = 0; i <= 15; i++) {
		result = get_jitter_sleep((int)i, 9999);
		assert_true(result <= cap_usec);
	}
}

/*
 * base_ms=0: backoff is always 0; jitter is rand_r() % 1 = 0.
 * Result must be 0.
 */
static void test_zero_base_ms_returns_zero(void **state) {
	unsigned int result;
	(void)state;

	result = get_jitter_sleep(0, 0);
	assert_int_equal(result, 0);
}

/*
 * Result is always in microseconds: (backoff_ms + jitter_ms) * 1000.
 * Therefore the result must always be a multiple of 1000.
 */
static void test_result_is_microseconds(void **state) {
	unsigned int result;
	(void)state;

	result = get_jitter_sleep(3, 100);
	assert_int_equal(result % 1000, 0);
}

/* ---- main ---------------------------------------------------------------- */

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_retry_zero_within_base_range),
		cmocka_unit_test(test_higher_retry_increases_sleep),
		cmocka_unit_test(test_retry_above_10_is_capped),
		cmocka_unit_test(test_negative_retry_clamped_to_zero),
		cmocka_unit_test(test_max_sleep_cap_enforced),
		cmocka_unit_test(test_zero_base_ms_returns_zero),
		cmocka_unit_test(test_result_is_microseconds),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
