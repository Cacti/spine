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
	char expression[257];
	char value[1025];
	const uint8_t *separator;
	const char *result;
	size_t expression_len;
	size_t value_len;

	if (data == NULL || size == 0 || size > 1280) {
		return 0;
	}

	separator = memchr(data, '\n', size);
	if (separator != NULL) {
		expression_len = (size_t)(separator - data);
		value_len = size - expression_len - 1;
	} else {
		expression_len = size / 2;
		value_len = size - expression_len;
	}

	if (expression_len > sizeof(expression) - 1 ||
	    value_len > sizeof(value) - 1) {
		return 0;
	}

	memcpy(expression, data, expression_len);
	expression[expression_len] = '\0';
	memcpy(value, data + size - value_len, value_len);
	value[value_len] = '\0';

	result = regex_replace(expression, value);
	if (result == NULL || strnlen(result, sizeof(value)) >= sizeof(value)) {
		abort();
	}

	(void)is_multipart_output(value);
	(void)validate_result(value);

	return 0;
}
