/*
 * On-wire ICMP echo signature used by spine.
 *
 * Single source of truth for SPINE_PING_MAGIC and spine_ping_payload_t.
 * All three TUs that compose or validate echo payloads (src/ping.c,
 * src/ping_validate.c, src/platform/platform_icmp_win.c) MUST include
 * this header; independent redefinitions have drifted in the past and
 * silently broken reply validation.
 */
#ifndef SPINE_PING_WIRE_H
#define SPINE_PING_WIRE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPINE_PING_MAGIC 0x53504E50494E4721ULL  /* "SPNPING!" */

typedef struct {
	uint64_t magic;
	uint32_t pid_mask;
	uint32_t timestamp_us;
} spine_ping_payload_t;

/* C11 static_assert in a portable form: the C standard guarantees
 * nothing about padding in a 16-byte struct with this layout, but
 * every target ABI spine runs on packs it flush. Loud failure here
 * beats a silent wire-format drift on a future platform. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(spine_ping_payload_t) == 16,
               "spine_ping_payload_t must be exactly 16 bytes on wire");
#endif

/* Validator. Returns 1 on match, 0 on mismatch. NULL buf or len
 * smaller than the struct is rejected. */
int spine_ping_validate_payload(const void *buf, size_t len,
                                uint32_t expect_pid_mask);

#ifdef __cplusplus
}
#endif

#endif /* SPINE_PING_WIRE_H */
