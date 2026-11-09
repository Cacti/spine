/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SPINE_TEST_FIXTURES_H
#define SPINE_TEST_FIXTURES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Live fixtures are named by environment variables, and the cases that need
 * one are left out when its variable is unset. SPINE_TEST_REQUIRE lists the
 * fixtures a CI step provides, separated by spaces or commas; a listed
 * fixture whose variable is unset aborts the run instead, so a step that
 * loses a fixture fails rather than silently testing less. */
static inline const char *spine_test_fixture(const char *name, const char *variable) {
	const char *value = getenv(variable);
	const char *required = getenv("SPINE_TEST_REQUIRE");
	size_t length = strlen(name);
	size_t total;
	size_t start = 0;

	if (value != NULL && value[0] != '\0') return value;
	if (required == NULL) return NULL;
	total = strlen(required);
	/* Walk the list by index, so every access stays below its length. */
	while (start < total) {
		size_t end = start;

		while (end < total && required[end] != ' ' && required[end] != ',') end++;
		if (end - start == length && memcmp(required + start, name, length) == 0) {
			fprintf(stderr, "required test fixture %s is missing: set %s\n", name, variable);
			abort();
		}
		start = end + 1;
	}
	return NULL;
}

#endif
