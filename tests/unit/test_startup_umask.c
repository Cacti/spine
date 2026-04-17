/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | With umask(027) applied, a newly-created file with a permissive request
 | (0666) lands as 0640. This test mirrors what spine does in main() so
 | any future regression that relaxes the mask surfaces here first.
 +-------------------------------------------------------------------------+
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_platform_helpers.h"

static void test_umask_027_yields_0640(void) {
	char tmpl[] = "/tmp/spine-umask-XXXXXX";
	int fd = mkstemp(tmpl);
	ASSERT_TRUE(fd >= 0);
	close(fd);
	unlink(tmpl);

	(void)umask(027);
	fd = open(tmpl, O_WRONLY | O_CREAT | O_EXCL, 0666);
	ASSERT_TRUE(fd >= 0);

	struct stat st;
	ASSERT_INT_EQ(fstat(fd, &st), 0);
	mode_t mode = st.st_mode & 0777;
	/* Expect 0640: umask 027 clears 020 | 007 from 0666. */
	ASSERT_INT_EQ((int)mode, 0640);

	close(fd);
	unlink(tmpl);
}

static void test_umask_returns_prior(void) {
	mode_t prior = umask(022);
	mode_t after = umask(027);
	ASSERT_INT_EQ((int)after, 022);
	mode_t restored = umask(prior);
	ASSERT_INT_EQ((int)restored, 027);
	umask(prior);
}

int main(void) {
	test_umask_027_yields_0640();
	test_umask_returns_prior();
	return finish_tests("startup_umask");
}
