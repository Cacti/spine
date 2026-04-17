/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Hex-string -> binary decoder for SNMPv3 engine IDs. Lives in its own
 | TU so the unit test suite can link the decoder without dragging in
 | Net-SNMP.
 +-------------------------------------------------------------------------+
*/

#include <stddef.h>
#include <string.h>

int spine_snmp_decode_engine_id(const char *hex, unsigned char *bin, int bin_cap) {
	if (hex == NULL || bin == NULL || bin_cap <= 0) {
		return 0;
	}
	size_t hex_len = strlen(hex);
	/* Cacti stores the engine ID as a hex string, optionally prefixed
	 * with "0x". Skip a prefix if present. */
	if (hex_len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
		hex += 2;
		hex_len -= 2;
	}
	if (hex_len == 0 || (hex_len % 2) != 0 || (int)(hex_len / 2) > bin_cap) {
		return 0;
	}
	int out_len = 0;
	for (size_t i = 0; i < hex_len; i += 2) {
		int hi = hex[i];
		int lo = hex[i + 1];
		int hv, lv;
		if      (hi >= '0' && hi <= '9') hv = hi - '0';
		else if (hi >= 'a' && hi <= 'f') hv = 10 + (hi - 'a');
		else if (hi >= 'A' && hi <= 'F') hv = 10 + (hi - 'A');
		else return 0;
		if      (lo >= '0' && lo <= '9') lv = lo - '0';
		else if (lo >= 'a' && lo <= 'f') lv = 10 + (lo - 'a');
		else if (lo >= 'A' && lo <= 'F') lv = 10 + (lo - 'A');
		else return 0;
		bin[out_len++] = (unsigned char)((hv << 4) | lv);
	}
	return out_len;
}
