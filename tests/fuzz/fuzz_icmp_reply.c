/* libFuzzer target for the two ICMP reply classifiers.
 *
 * This parses a raw ICMP datagram straight off a shared SOCK_RAW socket, so
 * the bytes come from any host that can reach the poller. The raw classifier
 * walks the IP header length field before touching the ICMP header, which is
 * exactly the shape that goes wrong; the datagram classifier is handed a
 * buffer with no IP header at all. Both are driven here, chosen by an input
 * byte. The real ping.c is linked, not a copy.
 */
#include <stdint.h>
#include <string.h>

#include "common.h"
#include "spine.h"
#include "ping.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	const struct icmp *pkt = NULL;
	spine_icmp_reply_t verdict;
	uint16_t want_id, want_seq;
	int dgram;

	/* first byte picks the socket type, next four steer the identity check,
	 * the rest is the datagram */
	if (size < 5) return 0;

	dgram    = (data[0] & 1) != 0;
	want_id  = (uint16_t)((data[1] << 8) | data[2]);
	want_seq = (uint16_t)((data[3] << 8) | data[4]);
	data += 5;
	size -= 5;

	if (dgram) {
		verdict = spine_icmp_classify_dgram_reply(data, (ssize_t) size, want_seq, &pkt);
	} else {
		verdict = spine_icmp_classify_reply(data, (ssize_t) size, want_id, want_seq, &pkt);
	}

	/* a packet is only handed back when it was accepted, and it must then
	 * point inside the buffer we were given */
	if (verdict == SPINE_ICMP_REPLY_OK) {
		if (pkt == NULL) abort();
		if ((const uint8_t *) pkt < data) abort();
		if ((const uint8_t *) pkt + ICMP_HDR_SIZE > data + size) abort();
	} else if (pkt != NULL) {
		abort();
	}

	return 0;
}
