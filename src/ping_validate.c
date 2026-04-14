/*
 * Standalone ICMP echo payload validator.
 *
 * Extracted into its own translation unit so unit tests can link just
 * this object without pulling in the full spine runtime (mysql,
 * net-snmp, the poller, etc). The validator is called from the raw
 * receive paths in ping.c and must stay byte-identical with the
 * on-wire signature built by build_ping_payload().
 */
#include <stddef.h>
#include <stdint.h>

#define SPINE_PING_MAGIC 0x53504E50494E4721ULL  /* "SPNPING!" */

typedef struct {
	uint64_t magic;
	uint32_t pid_mask;
	uint32_t timestamp_us;
} spine_ping_payload_t;

int spine_ping_validate_payload(const void *buf, size_t len,
                                uint32_t expect_pid_mask) {
	const spine_ping_payload_t *p;
	if (buf == NULL) {
		return 0;
	}
	if (len < sizeof(spine_ping_payload_t)) {
		return 0;
	}
	p = (const spine_ping_payload_t *) buf;
	if (p->magic != SPINE_PING_MAGIC) {
		return 0;
	}
	if (p->pid_mask != expect_pid_mask) {
		return 0;
	}
	return 1;
}
