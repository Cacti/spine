/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Regression for the OOB write in get_namebyhost() where strncpy() was
 | followed by name->hostname[strlen(token)] = '\\0'. For tokens >=
 | sizeof(hostname) the poke wrote one-past-the-buffer, or further. The
 | fix funnels both branches through strncopy(), which truncates at the
 | buffer bound and always NUL-terminates. This suite validates that
 | property against a surrogate buffer matched to the production size.
 +-------------------------------------------------------------------------+
*/

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test_platform_helpers.h"

/* Provided by src/util.c. */
extern char *strncopy(char *dst, const char *src, size_t obuf);

/* Mirrors the production layout: the hostname buffer is flanked on
 * both sides by canary bytes so a stray write past either end shows up
 * as a corrupted canary. Structure layout matches get_namebyhost's
 * usage of name_t.hostname. */
#define HOSTNAME_BUF 1024

struct probe {
	uint64_t canary_lo;
	char     hostname[HOSTNAME_BUF];
	uint64_t canary_hi;
};

#define CANARY_LO 0x1111111122222222ULL
#define CANARY_HI 0x3333333344444444ULL

static void reset_probe(struct probe *p) {
	p->canary_lo = CANARY_LO;
	p->canary_hi = CANARY_HI;
	memset(p->hostname, 0xAA, HOSTNAME_BUF);
}

static void assert_canaries_intact(const struct probe *p) {
	ASSERT_TRUE(p->canary_lo == CANARY_LO);
	ASSERT_TRUE(p->canary_hi == CANARY_HI);
}

static void test_short_hostname_is_preserved(void) {
	struct probe p;
	reset_probe(&p);
	strncopy(p.hostname, "host.example.com", sizeof(p.hostname));
	ASSERT_TRUE(strcmp(p.hostname, "host.example.com") == 0);
	assert_canaries_intact(&p);
}

static void test_hostname_exactly_at_bound_is_nul_terminated(void) {
	struct probe p;
	reset_probe(&p);
	char filler[HOSTNAME_BUF];
	memset(filler, 'a', sizeof(filler) - 1);
	filler[sizeof(filler) - 1] = '\0';
	strncopy(p.hostname, filler, sizeof(p.hostname));
	ASSERT_TRUE(p.hostname[sizeof(p.hostname) - 1] == '\0');
	assert_canaries_intact(&p);
}

static void test_overlong_hostname_does_not_walk_past_bound(void) {
	struct probe p;
	reset_probe(&p);
	/* 2x the buffer size: the old strncpy + hostname[strlen(token)] = 0
	 * poke wrote at offset HOSTNAME_BUF (one past end). */
	char overlong[HOSTNAME_BUF * 2];
	memset(overlong, 'z', sizeof(overlong) - 1);
	overlong[sizeof(overlong) - 1] = '\0';

	strncopy(p.hostname, overlong, sizeof(p.hostname));

	ASSERT_TRUE(p.hostname[sizeof(p.hostname) - 1] == '\0');
	/* Every byte except the terminator was filled with 'z'. */
	for (size_t i = 0; i < sizeof(p.hostname) - 1; i++) {
		ASSERT_TRUE(p.hostname[i] == 'z');
	}
	assert_canaries_intact(&p);
}

static void test_empty_source_leaves_empty_string(void) {
	struct probe p;
	reset_probe(&p);
	strncopy(p.hostname, "", sizeof(p.hostname));
	ASSERT_TRUE(p.hostname[0] == '\0');
	assert_canaries_intact(&p);
}

int main(void) {
	test_short_hostname_is_preserved();
	test_hostname_exactly_at_bound_is_nul_terminated();
	test_overlong_hostname_does_not_walk_past_bound();
	test_empty_source_leaves_empty_string();
	return finish_tests("get_namebyhost tests");
}
