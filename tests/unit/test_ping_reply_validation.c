/*
 * Unit test: ICMP echo reply payload validation.
 *
 * Verifies that a reply carrying the expected magic + pid_mask is
 * accepted and that any tampering (wrong magic, wrong pid_mask,
 * undersized buffer, NULL inputs) is rejected. Network-free.
 */
#include <stdint.h>
#include <string.h>

#include "ping_wire.h"
#include "test_platform_helpers.h"

static void test_wire_format_size(void) {
	/* Defensive runtime check in addition to ping_wire.h's _Static_assert,
	 * for toolchains that silently skip the _Static_assert. */
	ASSERT_INT_EQ((int) sizeof(spine_ping_payload_t), 16);
}

static void test_accepts_well_formed(void) {
	spine_ping_payload_t p;
	p.magic = SPINE_PING_MAGIC;
	p.pid_mask = 0xDEADBEEFu;
	p.timestamp_us = 12345u;
	ASSERT_INT_EQ(spine_ping_validate_payload(&p, sizeof(p), 0xDEADBEEFu), 1);
}

static void test_rejects_wrong_magic(void) {
	spine_ping_payload_t p;
	p.magic = 0xBADC0FFEEULL;
	p.pid_mask = 0xDEADBEEFu;
	p.timestamp_us = 0;
	ASSERT_INT_EQ(spine_ping_validate_payload(&p, sizeof(p), 0xDEADBEEFu), 0);
}

static void test_rejects_wrong_pid_mask(void) {
	spine_ping_payload_t p;
	p.magic = SPINE_PING_MAGIC;
	p.pid_mask = 0x11111111u;
	p.timestamp_us = 0;
	ASSERT_INT_EQ(spine_ping_validate_payload(&p, sizeof(p), 0x22222222u), 0);
}

static void test_rejects_undersized(void) {
	unsigned char short_buf[4] = { 0, 0, 0, 0 };
	ASSERT_INT_EQ(spine_ping_validate_payload(short_buf, sizeof(short_buf), 0), 0);
}

static void test_rejects_null_buf(void) {
	ASSERT_INT_EQ(spine_ping_validate_payload(NULL, 128, 0), 0);
}

static void test_accepts_extra_trailing(void) {
	unsigned char buf[sizeof(spine_ping_payload_t) + 16];
	spine_ping_payload_t p;
	p.magic = SPINE_PING_MAGIC;
	p.pid_mask = 0x01020304u;
	p.timestamp_us = 99u;
	memset(buf, 0xAA, sizeof(buf));
	memcpy(buf, &p, sizeof(p));
	ASSERT_INT_EQ(spine_ping_validate_payload(buf, sizeof(buf), 0x01020304u), 1);
}

int main(void) {
	test_wire_format_size();
	test_accepts_well_formed();
	test_rejects_wrong_magic();
	test_rejects_wrong_pid_mask();
	test_rejects_undersized();
	test_rejects_null_buf();
	test_accepts_extra_trailing();
	return finish_tests("ping reply validation tests");
}
