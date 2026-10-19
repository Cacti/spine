/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "internal/common.h"
#include "app/spine.h"
#include "poller/poller.h"
#include "internal/util.h"

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
	classified_result_t classified;
	if (classify_result(value, &classified) == RESULT_UNKNOWN &&
		!IS_UNDEFINED(classified.text)) {
		abort();
	}

	return 0;
}
