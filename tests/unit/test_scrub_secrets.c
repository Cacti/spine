/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | spine_scrub_secrets(): populate the credential fields, call the scrub,
 | assert every byte is zero. Exercises the HAVE_EXPLICIT_BZERO branch and
 | the volatile-pointer fallback depending on what the toolchain exposes.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"
#include "util.h"

#include <string.h>

#include "test_platform_helpers.h"

/* `set` is provided by test_spine_stubs.c. */

static int all_zero(const char *p, size_t n) {
	for (size_t i = 0; i < n; i++) {
		if (p[i] != '\0') return 0;
	}
	return 1;
}

static void populate_credentials(void) {
	memset(&set, 0, sizeof(set));
	memset(set.db_pass,  'A', sizeof(set.db_pass)  - 1);
	memset(set.rdb_pass, 'B', sizeof(set.rdb_pass) - 1);
	memset(set.db_user,  'C', sizeof(set.db_user)  - 1);
	memset(set.rdb_user, 'D', sizeof(set.rdb_user) - 1);
	set.db_pass[sizeof(set.db_pass)   - 1] = '\0';
	set.rdb_pass[sizeof(set.rdb_pass) - 1] = '\0';
	set.db_user[sizeof(set.db_user)   - 1] = '\0';
	set.rdb_user[sizeof(set.rdb_user) - 1] = '\0';
}

static void test_all_fields_zeroed(void) {
	populate_credentials();

	/* Sanity: non-zero before the scrub. */
	ASSERT_TRUE(set.db_pass[0]  != '\0');
	ASSERT_TRUE(set.rdb_pass[0] != '\0');
	ASSERT_TRUE(set.db_user[0]  != '\0');
	ASSERT_TRUE(set.rdb_user[0] != '\0');

	spine_scrub_secrets();

	ASSERT_TRUE(all_zero(set.db_pass,  sizeof(set.db_pass)));
	ASSERT_TRUE(all_zero(set.rdb_pass, sizeof(set.rdb_pass)));
	ASSERT_TRUE(all_zero(set.db_user,  sizeof(set.db_user)));
	ASSERT_TRUE(all_zero(set.rdb_user, sizeof(set.rdb_user)));
}

static void test_scrub_is_idempotent(void) {
	spine_scrub_secrets();
	spine_scrub_secrets();
	ASSERT_TRUE(all_zero(set.db_pass,  sizeof(set.db_pass)));
	ASSERT_TRUE(all_zero(set.rdb_pass, sizeof(set.rdb_pass)));
}

int main(void) {
	test_all_fields_zeroed();
	test_scrub_is_idempotent();
	return finish_tests("scrub_secrets");
}
