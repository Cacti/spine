/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | SNMPv3 engine IDs are opaque octet strings (RFC 3411). They are free
 | to embed 0x00 anywhere, so strlen() against an engine-ID buffer
 | truncates silently. The fix routes engine IDs through
 | spine_snmp_decode_engine_id() which takes a hex-encoded string (the
 | Cacti DB convention) and emits raw bytes plus an explicit length.
 | This suite pins the decoder contract.
 +-------------------------------------------------------------------------+
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "test_platform_helpers.h"

extern int spine_snmp_decode_engine_id(const char *hex, unsigned char *bin, int bin_cap);

static void test_empty_returns_zero(void) {
	unsigned char bin[32] = {0};
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("", bin, (int)sizeof(bin)), 0);
	ASSERT_INT_EQ(spine_snmp_decode_engine_id(NULL, bin, (int)sizeof(bin)), 0);
}

static void test_round_trip_with_embedded_null_byte(void) {
	/* 0x80001F8880 is the RFC 3411 prefix for "enterprise 8072";
	 * the trailing zero byte is what strlen() would cut on. */
	const char *hex = "80001F888000";
	unsigned char bin[32] = {0};
	int n = spine_snmp_decode_engine_id(hex, bin, (int)sizeof(bin));
	ASSERT_INT_EQ(n, 6);
	ASSERT_INT_EQ(bin[0], 0x80);
	ASSERT_INT_EQ(bin[1], 0x00);
	ASSERT_INT_EQ(bin[2], 0x1F);
	ASSERT_INT_EQ(bin[3], 0x88);
	ASSERT_INT_EQ(bin[4], 0x80);
	ASSERT_INT_EQ(bin[5], 0x00);
}

static void test_mixed_case_hex_accepted(void) {
	unsigned char bin[32] = {0};
	int n = spine_snmp_decode_engine_id("aAbBcCdD", bin, (int)sizeof(bin));
	ASSERT_INT_EQ(n, 4);
	ASSERT_INT_EQ(bin[0], 0xAA);
	ASSERT_INT_EQ(bin[1], 0xBB);
	ASSERT_INT_EQ(bin[2], 0xCC);
	ASSERT_INT_EQ(bin[3], 0xDD);
}

static void test_optional_0x_prefix_stripped(void) {
	unsigned char bin[32] = {0};
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("0x1234", bin, (int)sizeof(bin)), 2);
	ASSERT_INT_EQ(bin[0], 0x12);
	ASSERT_INT_EQ(bin[1], 0x34);

	memset(bin, 0, sizeof(bin));
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("0X1234", bin, (int)sizeof(bin)), 2);
	ASSERT_INT_EQ(bin[0], 0x12);
	ASSERT_INT_EQ(bin[1], 0x34);
}

static void test_odd_length_rejected(void) {
	unsigned char bin[32] = {0};
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("ABC", bin, (int)sizeof(bin)), 0);
}

static void test_non_hex_character_rejected(void) {
	unsigned char bin[32] = {0};
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("ZZ", bin, (int)sizeof(bin)), 0);
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("AZ", bin, (int)sizeof(bin)), 0);
}

static void test_overflow_rejected(void) {
	/* bin_cap of 2 cannot hold 3 bytes. */
	unsigned char bin[2] = {0};
	ASSERT_INT_EQ(spine_snmp_decode_engine_id("AABBCC", bin, (int)sizeof(bin)), 0);
}

int main(void) {
	test_empty_returns_zero();
	test_round_trip_with_embedded_null_byte();
	test_mixed_case_hex_accepted();
	test_optional_0x_prefix_stripped();
	test_odd_length_rejected();
	test_non_hex_character_rejected();
	test_overflow_rejected();
	return finish_tests("snmp_engine_id tests");
}
