/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#ifndef SPINE_RESULT_H
#define SPINE_RESULT_H

#include <stdint.h>
#include "internal/constants.h"

/* what a poll returned; text is what poller_output stores, U if unknown */
typedef enum {
	RESULT_UNKNOWN = 0,
	RESULT_COUNTER,
	RESULT_SIGNED,
	RESULT_FLOAT,
	RESULT_HEX_COUNTER,
	RESULT_MULTIPART
} result_kind_t;

typedef struct {
	result_kind_t kind;
	union {
		uint64_t counter;
		int64_t integer;
		double real;
	} value;
	char text[RESULTS_BUFFER];
} classified_result_t;

extern result_kind_t classify_result(const char *raw, classified_result_t *out);

#endif
