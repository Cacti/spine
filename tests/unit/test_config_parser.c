/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | read_spine_config(): the tokenizer rejects overlong keywords, overlong
 | lines, embedded NUL bytes, and out-of-range integer fields; preserves
 | interior whitespace in values; and never silently truncates.
 +-------------------------------------------------------------------------+
*/

#include "common.h"
#include "spine.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_platform_helpers.h"

/* `set` is provided by test_spine_stubs.c. */

/*
 * make_test_conf - create a temp config file at 0600 and write body into it.
 *
 * mkstemp(3) honours the process umask when it creates the file, so on Linux
 * CI (umask 022) the file lands at 0644.  open(2) mode only applies when
 * O_CREAT actually creates a new file, not when it opens an existing one, so
 * a subsequent open(..., O_CREAT|O_TRUNC, 0600) on the already-existing
 * mkstemp path leaves the 0644 mode intact and H1 refuses.  We must call
 * fchmod on the fd mkstemp gave us -- before closing it -- to ensure the
 * inode reaches 0600 regardless of the caller's umask.
 */
static int make_test_conf(char *tmp_template, const char *body, size_t body_len) {
	int fd = mkstemp(tmp_template);
	if (fd < 0) return -1;
	if (fchmod(fd, 0600) != 0) { close(fd); unlink(tmp_template); return -1; }
	ssize_t n = write(fd, body, body_len);
	close(fd);
	if (n != (ssize_t)body_len) { unlink(tmp_template); return -1; }
	return 0;
}

static void capture_stderr_begin(int *saved_fd, int *pipe_read_fd) {
	int pipefd[2];
	if (pipe(pipefd) != 0) {
		*saved_fd = -1;
		*pipe_read_fd = -1;
		return;
	}
	fflush(stderr);
	*saved_fd = dup(STDERR_FILENO);
	dup2(pipefd[1], STDERR_FILENO);
	close(pipefd[1]);
	*pipe_read_fd = pipefd[0];
}

static void capture_stderr_end(int saved_fd, int pipe_read_fd,
                               char *out, size_t out_len) {
	fflush(stderr);
	dup2(saved_fd, STDERR_FILENO);
	close(saved_fd);

	size_t total = 0;
	while (total + 1 < out_len) {
		ssize_t n = read(pipe_read_fd, out + total, out_len - 1 - total);
		if (n <= 0) break;
		total += (size_t)n;
	}
	out[total] = '\0';
	close(pipe_read_fd);
}

static void reset_set(void) {
	memset(&set, 0, sizeof(set));
	set.stderr_notty = 0;
	set.stdout_notty = 1;   /* suppress the "Using spine config file" line */
	set.log_level    = 0;
}

static void test_keyword_too_long(void) {
	char tmp[] = "/tmp/spine-cfg-XXXXXX";
	/* 65 'A' chars then a space then a value; p1 cap is 64 (63 usable). */
	const char body[] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA value\n"
		"DB_Port 3306\n";
	ASSERT_INT_EQ(make_test_conf(tmp, body, sizeof(body) - 1), 0);

	reset_set();
	int saved, rd; char err[4096];
	capture_stderr_begin(&saved, &rd);
	int rc = read_spine_config(tmp);
	capture_stderr_end(saved, rd, err, sizeof(err));

	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(strstr(err, "keyword exceeds") != NULL);
	/* The good directive following the bad one must still parse. */
	ASSERT_INT_EQ(set.db_port, 3306);
	unlink(tmp);
}

static void test_value_with_spaces(void) {
	char tmp[] = "/tmp/spine-cfg-XXXXXX";
	const char body[] =
		"DB_Pass my pass with spaces\n"
		"DB_Host localhost\n";
	ASSERT_INT_EQ(make_test_conf(tmp, body, sizeof(body) - 1), 0);

	reset_set();
	int rc = read_spine_config(tmp);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(strcmp(set.db_pass, "my pass with spaces") == 0);
	ASSERT_TRUE(strcmp(set.db_host, "localhost") == 0);
	unlink(tmp);
}

static void test_overlong_line(void) {
	char tmp[] = "/tmp/spine-cfg-XXXXXX";
	/* Build a single line that spills BUFSIZE (1024) with no newline. */
	size_t body_len = BUFSIZE + 64;
	char *body = malloc(body_len + 2);
	ASSERT_TRUE(body != NULL);
	memcpy(body, "DB_Host ", 8);
	memset(body + 8, 'x', body_len - 8);
	body[body_len] = '\n';
	body[body_len + 1] = '\0';
	ASSERT_INT_EQ(make_test_conf(tmp, body, body_len + 1), 0);

	reset_set();
	int saved, rd; char err[4096];
	capture_stderr_begin(&saved, &rd);
	int rc = read_spine_config(tmp);
	capture_stderr_end(saved, rd, err, sizeof(err));

	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(strstr(err, "line exceeds") != NULL);
	/* set.db_host must remain unset by the overlong line. */
	ASSERT_TRUE(set.db_host[0] == '\0');
	free(body);
	unlink(tmp);
}

static void test_embedded_nul(void) {
	char tmp[] = "/tmp/spine-cfg-XXXXXX";
	/* "DB_Host loc\0alhost\n" - explicit length includes the NUL. */
	const char body[] = { 'D','B','_','H','o','s','t',' ',
	                      'l','o','c','\0','a','l','h','o','s','t','\n' };
	ASSERT_INT_EQ(make_test_conf(tmp, body, sizeof(body)), 0);

	reset_set();
	int saved, rd; char err[4096];
	capture_stderr_begin(&saved, &rd);
	int rc = read_spine_config(tmp);
	capture_stderr_end(saved, rd, err, sizeof(err));

	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(strstr(err, "embedded NUL") != NULL);
	ASSERT_TRUE(set.db_host[0] == '\0');
	unlink(tmp);
}

static void test_port_out_of_range(void) {
	struct { const char *line; int expected; } cases[] = {
		{ "DB_Port 0\n",     0 },      /* 0 is invalid; default stays */
		{ "DB_Port 65536\n", 0 },
		{ "DB_Port -1\n",    0 },
		{ "DB_Port 3306\n",  3306 },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		char tmp[] = "/tmp/spine-cfg-XXXXXX";
		ASSERT_INT_EQ(make_test_conf(tmp, cases[i].line, strlen(cases[i].line)), 0);

		reset_set();
		int saved, rd; char err[4096];
		capture_stderr_begin(&saved, &rd);
		int rc = read_spine_config(tmp);
		capture_stderr_end(saved, rd, err, sizeof(err));

		ASSERT_INT_EQ(rc, 0);
		ASSERT_INT_EQ(set.db_port, cases[i].expected);
		if (cases[i].expected == 0) {
			ASSERT_TRUE(strstr(err, "rejected") != NULL);
		}
		unlink(tmp);
	}
}

static void test_symlink_rejected(void) {
	char tgt[] = "/tmp/spine-cfg-tgt-XXXXXX";
	char lnk[] = "/tmp/spine-cfg-lnk-XXXXXX";

	const char body[] = "DB_Host localhost\n";
	ASSERT_INT_EQ(make_test_conf(tgt, body, sizeof(body) - 1), 0);

	/* Reserve a name for the symlink: mkstemp creates the file, so we
	 * unlink it immediately to free the name for symlink(2). */
	int fd = mkstemp(lnk);
	if (fd >= 0) { close(fd); unlink(lnk); }
	if (symlink(tgt, lnk) != 0) {
		/* Filesystem might refuse symlink creation; skip silently. */
		unlink(tgt);
		return;
	}

	reset_set();
	int saved, rd; char err[4096];
	capture_stderr_begin(&saved, &rd);
	int rc = read_spine_config(lnk);
	capture_stderr_end(saved, rd, err, sizeof(err));

	ASSERT_INT_EQ(rc, -1);
	ASSERT_TRUE(strstr(err, "symlink") != NULL);
	unlink(lnk);
	unlink(tgt);
}

int main(void) {
	/* Ensure temp files are created 0600 even before fchmod runs. Without
	 * this, mkstemp under umask 022 yields 0644 and H1 refuses the file. */
	umask(077);
	/* H1 also checks that the config owner matches the startup euid captured
	 * before any privilege drop.  Unit tests never call spine_main, so we
	 * capture it here; the file is created by this process, so the owner
	 * will match geteuid() and the check passes. */
	spine_capture_startup_euid();
	test_keyword_too_long();
	test_value_with_spaces();
	test_overlong_line();
	test_embedded_nul();
	test_port_out_of_range();
	test_symlink_rejected();
	return finish_tests("config_parser");
}
