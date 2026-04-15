/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | spine_dump_config(): every effective setting prints as key=value and
 | password fields are redacted. We capture stdout by redirecting fd 1
 | to a temp file before the call, then grep the buffer.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test_platform_helpers.h"

extern void spine_dump_config(void);

/* `set` is provided by test_spine_stubs.c. */

static int contains(const char *haystack, const char *needle) {
	return strstr(haystack, needle) != NULL ? 1 : 0;
}

static void populate_config(void) {
	memset(&set, 0, sizeof(set));
	strncpy(set.db_host, "db.example.com", sizeof(set.db_host) - 1);
	strncpy(set.db_db,   "cacti",         sizeof(set.db_db) - 1);
	strncpy(set.db_user, "cactiuser",     sizeof(set.db_user) - 1);
	strncpy(set.db_pass, "supersecret",   sizeof(set.db_pass) - 1);
	set.db_port = 3306;
	set.db_ssl  = 0;

	strncpy(set.rdb_host, "remote.example.com", sizeof(set.rdb_host) - 1);
	strncpy(set.rdb_pass, "othersecret",        sizeof(set.rdb_pass) - 1);
	set.rdb_port = 3307;

	set.poller_id   = 2;
	set.threads     = 8;
	strncpy(set.path_logfile, "/var/log/cacti/spine.log", sizeof(set.path_logfile) - 1);
	set.mode        = 0;
	set.ping_method = 1;
	set.ping_retries = 3;
	set.ping_timeout = 400;
	set.log_level   = 2;
	set.log_format  = 0;
	set.dry_run     = 0;
	set.circuit_breaker_threshold = 5;
}

static void capture_dump(char *out, size_t out_len) {
	char tmpl[] = "/tmp/spine-dump-config-XXXXXX";
	int fd = mkstemp(tmpl);
	ASSERT_TRUE(fd >= 0);

	fflush(stdout);
	int saved = dup(STDOUT_FILENO);
	ASSERT_TRUE(saved >= 0);
	ASSERT_TRUE(dup2(fd, STDOUT_FILENO) >= 0);

	spine_dump_config();
	fflush(stdout);

	dup2(saved, STDOUT_FILENO);
	close(saved);

	lseek(fd, 0, SEEK_SET);
	ssize_t n = read(fd, out, out_len - 1);
	if (n < 0) n = 0;
	out[n] = '\0';
	close(fd);
	unlink(tmpl);
}

static void test_dump_config_contents(void) {
	populate_config();

	char buf[8192];
	capture_dump(buf, sizeof(buf));

	/* Plain keys that must appear in the effective-config dump. */
	ASSERT_TRUE(contains(buf, "DB_Host = db.example.com"));
	ASSERT_TRUE(contains(buf, "DB_Database = cacti"));
	ASSERT_TRUE(contains(buf, "DB_User = cactiuser"));
	ASSERT_TRUE(contains(buf, "DB_Port = 3306"));
	ASSERT_TRUE(contains(buf, "RDB_Host = remote.example.com"));
	ASSERT_TRUE(contains(buf, "RDB_Port = 3307"));
	ASSERT_TRUE(contains(buf, "Poller = 2"));
	ASSERT_TRUE(contains(buf, "Threads = 8"));
	ASSERT_TRUE(contains(buf, "Cacti_Log = /var/log/cacti/spine.log"));
	ASSERT_TRUE(contains(buf, "PingMethod = 1"));
	ASSERT_TRUE(contains(buf, "PingRetries = 3"));
	ASSERT_TRUE(contains(buf, "PingTimeout = 400"));
	ASSERT_TRUE(contains(buf, "LogVerbosity = 2"));
	ASSERT_TRUE(contains(buf, "DryRun = 0"));
	ASSERT_TRUE(contains(buf, "CircuitBreakerThreshold = 5"));

	/* Redaction: the real password must never land in the dump output.
	 * "[REDACTED]" is the sentinel printed when the field is non-empty. */
	ASSERT_TRUE(contains(buf, "DB_Pass = [REDACTED]"));
	ASSERT_TRUE(contains(buf, "RDB_Pass = [REDACTED]"));
	ASSERT_TRUE(!contains(buf, "supersecret"));
	ASSERT_TRUE(!contains(buf, "othersecret"));
}

static void test_dump_config_empty_password_not_redacted(void) {
	memset(&set, 0, sizeof(set));
	/* Leaving db_pass empty should produce "DB_Pass = " with nothing
	 * behind the equals; [REDACTED] is reserved for populated passwords. */
	char buf[8192];
	capture_dump(buf, sizeof(buf));

	ASSERT_TRUE(contains(buf, "DB_Pass = \n"));
	ASSERT_TRUE(!contains(buf, "DB_Pass = [REDACTED]"));
}

int main(void) {
	test_dump_config_contents();
	test_dump_config_empty_password_not_redacted();
	return finish_tests("dump config tests");
}
