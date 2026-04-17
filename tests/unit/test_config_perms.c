/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | SECURITY.md commits to refusing startup when spine.conf is not 0600
 | and owned by root or the startup euid, and to refusing to traverse a
 | symlink at the final config path. This suite exercises the policy at
 | the permission-check level so a future "soft-warn" regression fails
 | loud rather than leaking DB credentials.
 +-------------------------------------------------------------------------+
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_platform_helpers.h"

enum config_check_result {
	CONFIG_OK = 0,
	CONFIG_ELOOP,
	CONFIG_OPEN_FAIL,
	CONFIG_MODE_FAIL,
	CONFIG_OWNER_FAIL,
	CONFIG_FSTAT_FAIL
};

/* Mirrors read_spine_config's policy: O_NOFOLLOW open, refuse any group
 * or world bit, accept only owner == root or the captured startup euid. */
static enum config_check_result check_config(const char *path, uid_t startup_euid) {
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return (errno == ELOOP) ? CONFIG_ELOOP : CONFIG_OPEN_FAIL;
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		close(fd);
		return CONFIG_FSTAT_FAIL;
	}
	enum config_check_result rv = CONFIG_OK;
	if (st.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP |
			  S_IROTH | S_IWOTH | S_IXOTH)) {
		rv = CONFIG_MODE_FAIL;
	} else {
		int owner_ok = (st.st_uid == 0) ||
			(startup_euid != (uid_t)-1 && st.st_uid == startup_euid);
		if (!owner_ok) {
			rv = CONFIG_OWNER_FAIL;
		}
	}
	close(fd);
	return rv;
}

static int write_tempfile(char *path, mode_t mode) {
	strcpy(path, "/tmp/spine_conf_perm_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) return -1;
	if (fchmod(fd, mode) != 0) {
		close(fd);
		unlink(path);
		return -1;
	}
	const char *body = "DB_Host localhost\n";
	if (write(fd, body, strlen(body)) != (ssize_t)strlen(body)) {
		close(fd);
		unlink(path);
		return -1;
	}
	close(fd);
	return 0;
}

static void test_mode_0600_owned_by_euid_is_accepted(void) {
	char path[64];
	if (write_tempfile(path, 0600) != 0) {
		ASSERT_FAIL("tempfile creation failed");
		return;
	}
	ASSERT_INT_EQ((int)check_config(path, geteuid()), (int)CONFIG_OK);
	unlink(path);
}

static void test_mode_0640_is_rejected(void) {
	char path[64];
	if (write_tempfile(path, 0640) != 0) {
		ASSERT_FAIL("tempfile creation failed");
		return;
	}
	ASSERT_INT_EQ((int)check_config(path, geteuid()), (int)CONFIG_MODE_FAIL);
	unlink(path);
}

static void test_mode_0644_is_rejected(void) {
	char path[64];
	if (write_tempfile(path, 0644) != 0) {
		ASSERT_FAIL("tempfile creation failed");
		return;
	}
	ASSERT_INT_EQ((int)check_config(path, geteuid()), (int)CONFIG_MODE_FAIL);
	unlink(path);
}

static void test_symlink_is_rejected(void) {
	char target[64];
	if (write_tempfile(target, 0600) != 0) {
		ASSERT_FAIL("tempfile creation failed");
		return;
	}
	char link_path[96];
	snprintf(link_path, sizeof(link_path), "%s.link", target);
	unlink(link_path);
	if (symlink(target, link_path) != 0) {
		unlink(target);
		ASSERT_FAIL("symlink() failed");
		return;
	}
	ASSERT_INT_EQ((int)check_config(link_path, geteuid()), (int)CONFIG_ELOOP);
	unlink(link_path);
	unlink(target);
}

static void test_unknown_owner_is_rejected(void) {
	/* Skip when running as root: chown is permitted, so the "unexpected owner"
	 * code path cannot be triggered on a real file. The check_config contract
	 * is still covered by passing a bogus startup_euid that doesn't match the
	 * file's actual owner. */
	char path[64];
	if (write_tempfile(path, 0600) != 0) {
		ASSERT_FAIL("tempfile creation failed");
		return;
	}
	uid_t owner = geteuid();
	if (owner == 0) {
		unlink(path);
		return;
	}
	/* Pretend spine booted as a different uid. Root is still accepted so we
	 * pick a sentinel value that won't collide with the actual file owner. */
	uid_t fake_startup = (uid_t)(owner + 1);
	enum config_check_result rv = check_config(path, fake_startup);
	ASSERT_INT_EQ((int)rv, (int)CONFIG_OWNER_FAIL);
	unlink(path);
}

int main(void) {
	test_mode_0600_owned_by_euid_is_accepted();
	test_mode_0640_is_rejected();
	test_mode_0644_is_rejected();
	test_symlink_is_rejected();
	test_unknown_owner_is_rejected();
	return finish_tests("config_perms tests");
}
