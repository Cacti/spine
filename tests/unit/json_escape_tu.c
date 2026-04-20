/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Stand-alone copy of spine_json_escape for the json_log unit test. The
 | in-tree definition in util.c lives behind common.h (mysql + net-snmp),
 | which the test deliberately avoids. The implementation MUST stay in
 | sync with util.c:spine_json_escape. Any change here requires a
 | matching change there and vice versa.
 +-------------------------------------------------------------------------+
*/

#include <stdio.h>
#include <stddef.h>

char *spine_json_escape(char *dst, size_t dst_len, const char *src) {
	size_t i = 0;
	if (dst_len == 0) return dst;
	if (!src) { dst[0] = '\0'; return dst; }

	while (*src && i + 7 < dst_len) {
		unsigned char c = (unsigned char)*src++;
		if (c == '"' || c == '\\') {
			dst[i++] = '\\';
			dst[i++] = (char)c;
		} else if (c == '\n') {
			dst[i++] = '\\'; dst[i++] = 'n';
		} else if (c == '\r') {
			dst[i++] = '\\'; dst[i++] = 'r';
		} else if (c == '\t') {
			dst[i++] = '\\'; dst[i++] = 't';
		} else if (c < 0x20) {
			i += (size_t)snprintf(dst + i, dst_len - i, "\\u%04x", c);
		} else {
			dst[i++] = (char)c;
		}
	}
	dst[i] = '\0';
	return dst;
}
