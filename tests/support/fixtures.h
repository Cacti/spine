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

	if (value != NULL && value[0] != '\0') return value;
	while (required != NULL && *required != '\0') {
		size_t token = strcspn(required, " ,");

		if (token == length && strncmp(required, name, length) == 0) {
			fprintf(stderr, "required test fixture %s is missing: set %s\n", name, variable);
			abort();
		}
		required += token;
		required += strspn(required, " ,");
	}
	return NULL;
}

#endif
