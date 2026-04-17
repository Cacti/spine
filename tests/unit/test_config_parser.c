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

static int write_conf(const char *path, const char *body, size_t body_len) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) return -1;
	ssize_t n = write(fd, body, body_len);
	close(fd);
	return (n == (ssize_t)body_len) ? 0 : -1;
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
	int fd = mkstemp(tmp); close(fd);
	/* 65 'A' chars then a space then a value; p1 cap is 64 (63 usable). */
	const char body[] =
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA value\n"
		"DB_Port 3306\n";
	ASSERT_INT_EQ(write_conf(tmp, body, sizeof(body) - 1), 0);

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
	int fd = mkstemp(tmp); close(fd);
	const char body[] =
		"DB_Pass my pass with spaces\n"
		"DB_Host localhost\n";
	ASSERT_INT_EQ(write_conf(tmp, body, sizeof(body) - 1), 0);

	reset_set();
	int rc = read_spine_config(tmp);
	ASSERT_INT_EQ(rc, 0);
	ASSERT_TRUE(strcmp(set.db_pass, "my pass with spaces") == 0);
	ASSERT_TRUE(strcmp(set.db_host, "localhost") == 0);
	unlink(tmp);
}

static void test_overlong_line(void) {
	char tmp[] = "/tmp/spine-cfg-XXXXXX";
	int fd = mkstemp(tmp); close(fd);
	/* Build a single line that spills BUFSIZE (1024) with no newline. */
	size_t body_len = BUFSIZE + 64;
	char *body = malloc(body_len + 2);
	ASSERT_TRUE(body != NULL);
	memcpy(body, "DB_Host ", 8);
	memset(body + 8, 'x', body_len - 8);
	body[body_len] = '\n';
	body[body_len + 1] = '\0';
	ASSERT_INT_EQ(write_conf(tmp, body, body_len + 1), 0);

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
	int fd = mkstemp(tmp); close(fd);
	/* "DB_Host loc\0alhost\n" - explicit length includes the NUL. */
	const char body[] = { 'D','B','_','H','o','s','t',' ',
	                      'l','o','c','\0','a','l','h','o','s','t','\n' };
	ASSERT_INT_EQ(write_conf(tmp, body, sizeof(body)), 0);

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
		int fd = mkstemp(tmp); close(fd);
		ASSERT_INT_EQ(write_conf(tmp, cases[i].line, strlen(cases[i].line)), 0);

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
	int fd = mkstemp(tgt); close(fd);
	fd = mkstemp(lnk); close(fd);
	unlink(lnk);  /* mkstemp created the file; symlink needs the name free */

	const char body[] = "DB_Host localhost\n";
	ASSERT_INT_EQ(write_conf(tgt, body, sizeof(body) - 1), 0);
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
	test_keyword_too_long();
	test_value_with_spaces();
	test_overlong_line();
	test_embedded_nul();
	test_port_out_of_range();
	test_symlink_rejected();
	return finish_tests("config_parser");
}
