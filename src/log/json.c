/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include <stdio.h>
#include <string.h>
#include "log/log.h"

/* A fixed log record needs only JSON string encoding, not a general parser.
 * Preserve valid UTF-8 and reject invalid sequences before emitting a record. */
typedef struct {
	char *cursor;
	size_t remaining;
} json_writer_t;

static bool json_bytes(json_writer_t *writer, const char *bytes, size_t length) {
	if (length >= writer->remaining) return false;
	memcpy(writer->cursor, bytes, length);
	writer->cursor += length;
	writer->remaining -= length;
	*writer->cursor = '\0';
	return true;
}

static size_t utf8_length(const unsigned char *bytes, size_t remaining) {
	size_t count;
	size_t index;
	unsigned char first = bytes[0];

	if (first < 0x80) return 1;
	if (first >= 0xc2 && first <= 0xdf) count = 2;
	else if (first >= 0xe0 && first <= 0xef) count = 3;
	else if (first >= 0xf0 && first <= 0xf4) count = 4;
	else return 0;
	if (count > remaining) return 0;
	for (index = 1; index < count; index++) {
		if (bytes[index] < 0x80 || bytes[index] > 0xbf) return 0;
	}
	if ((first == 0xe0 && bytes[1] < 0xa0) ||
		(first == 0xed && bytes[1] >= 0xa0) ||
		(first == 0xf0 && bytes[1] < 0x90) ||
		(first == 0xf4 && bytes[1] >= 0x90)) return 0;
	return count;
}

static bool json_string(json_writer_t *writer, const char *text) {
	const unsigned char *cursor = (const unsigned char *) text;
	size_t remaining = strlen(text);

	if (!json_bytes(writer, "\"", 1)) return false;
	while (remaining != 0) {
		size_t count = utf8_length(cursor, remaining);
		char escape[7];
		if (count == 0) return false;
		if (*cursor < 0x20 || *cursor == 0x7f) {
			snprintf(escape, sizeof(escape), "\\u%04x", (unsigned int) *cursor);
			if (!json_bytes(writer, escape, 6)) return false;
		} else if (*cursor == '\"' || *cursor == '\\') {
			escape[0] = '\\';
			escape[1] = (char) *cursor;
			if (!json_bytes(writer, escape, 2)) return false;
		} else if (!json_bytes(writer, (const char *) cursor, count)) {
			return false;
		}
		cursor += count;
		remaining -= count;
	}
	return json_bytes(writer, "\"", 1);
}

bool spine_json_log_record(char *output, size_t capacity, const char *timestamp,
	const char *severity, const char *message) {
	json_writer_t writer = {output, capacity};

	if (output == NULL || capacity == 0) return false;
	output[0] = '\0';
	if (timestamp == NULL || severity == NULL || message == NULL) return false;
	if (!json_bytes(&writer, "{\"timestamp\":", 13) || !json_string(&writer, timestamp) ||
		!json_bytes(&writer, ",\"severity\":", 12) || !json_string(&writer, severity) ||
		!json_bytes(&writer, ",\"message\":", 11) || !json_string(&writer, message) ||
		!json_bytes(&writer, "}\n", 2)) {
		output[0] = '\0';
		return false;
	}
	return true;
}
