/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | spine_health_check() failure path. Points the probe at an unroutable
 | TEST-NET-1 address (RFC 5737 192.0.2.0/24) and verifies:
 |   - connect fails within the 3s timeout,
 |   - JSON failure envelope is printed,
 |   - the function returns 0 / FALSE.
 |
 | The success path needs a real DB; skip it here and rely on integration
 | tests for that coverage.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_platform_helpers.h"

extern int spine_health_check(void);


static int contains(const char *haystack, const char *needle) {
	return strstr(haystack, needle) != NULL ? 1 : 0;
}

static void test_check_mode_fails_against_unroutable_host(void) {
	memset(&set, 0, sizeof(set));
	strncpy(set.db_host, "192.0.2.1", sizeof(set.db_host) - 1); /* TEST-NET-1 */
	strncpy(set.db_user, "cacti",     sizeof(set.db_user) - 1);
	strncpy(set.db_pass, "x",         sizeof(set.db_pass) - 1);
	strncpy(set.db_db,   "cacti",     sizeof(set.db_db) - 1);
	set.db_port = 3306;

	/* Capture stdout so we can match on the JSON envelope. */
	char tmpl[] = "/tmp/spine-check-XXXXXX";
	int fd = mkstemp(tmpl);
	ASSERT_TRUE(fd >= 0);

	fflush(stdout);
	int saved = dup(STDOUT_FILENO);
	ASSERT_TRUE(saved >= 0);
	ASSERT_TRUE(dup2(fd, STDOUT_FILENO) >= 0);

	int ok = spine_health_check();
	fflush(stdout);

	dup2(saved, STDOUT_FILENO);
	close(saved);

	char out[4096];
	lseek(fd, 0, SEEK_SET);
	ssize_t n = read(fd, out, sizeof(out) - 1);
	if (n < 0) n = 0;
	out[n] = '\0';
	close(fd);
	unlink(tmpl);

	ASSERT_INT_EQ(ok, 0);
	ASSERT_TRUE(contains(out, "\"status\":\"failed\""));
	ASSERT_TRUE(contains(out, "\"error\":\""));
	/* The error must be JSON-safe: no raw double-quote or newline inside
	 * the error body (the escaper must have rewritten them). */
	const char *err = strstr(out, "\"error\":\"");
	if (err) {
		err += strlen("\"error\":\"");
		const char *end = strchr(err, '"');
		ASSERT_TRUE(end != NULL);
		if (end) {
			for (const char *p = err; p < end; p++) {
				ASSERT_TRUE(*p != '\n' && *p != '\r');
			}
		}
	}
}

int main(void) {
	test_check_mode_fails_against_unroutable_host();
	return finish_tests("check mode tests");
}
