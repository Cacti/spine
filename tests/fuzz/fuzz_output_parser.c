/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public License      |
 | as published by the Free Software Foundation; either version 2.1       |
 | of the License, or (at your option) any later version.                  |
 +-------------------------------------------------------------------------+
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "spine.h"
#include "poller.h"
#include "util.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	char value[1025];
	char row[RESULTS_BUFFER + SMALL_BUFSIZE];
	const char *result;
	static const char *expressions[] = {
		REGEX_NUMBER,
		"[0-9][0-9]*",
		"[a-zA-Z][a-zA-Z0-9_.:-]*",
		".*"
	};
	size_t value_len;

	if (data == NULL || size == 0 || size > sizeof(value)) {
		return 0;
	}

	value_len = size - 1;
	memcpy(value, data + 1, value_len);
	value[value_len] = '\0';

	result = regex_replace(expressions[data[0] %
		(sizeof(expressions) / sizeof(expressions[0]))], value);
	if (result == NULL) {
		abort();
	}

	(void)format_poller_output_row(row, sizeof(row), 1,
		"fuzz", "1700000000", result);
	(void)is_multipart_output(value);
	(void)validate_result(value);

	return 0;
}
