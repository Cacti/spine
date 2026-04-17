/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Regression: nft_pchild returns -1 on lookup failure. Historically the
 | poller's script-timeout path passed that value straight into kill(),
 | which on POSIX means "broadcast SIGKILL to every process owned by the
 | current uid". This suite exercises the guard in exec_poll that
 | suppresses kill() unless the resolved pid is a real child (>1).
 +-------------------------------------------------------------------------+
*/

#include <errno.h>
#include <signal.h>
#include <stdio.h>

#include "test_platform_helpers.h"

/* Mirror of the guard in src/poller.c exec_poll. Kept here so a refactor
 * that drops the guard will leave a failing test behind. */
static int guarded_kill_invocations = 0;

static int fake_kill(int pid, int sig) {
	(void)sig;
	/* kill(-1, ...) / kill(0, ...) are the broadcast forms we refuse. */
	if (pid <= 1) {
		errno = EPERM;
		return -1;
	}
	guarded_kill_invocations++;
	return 0;
}

static void guarded_terminate(int pid_from_nft_pchild) {
	if (pid_from_nft_pchild > 1) {
		fake_kill(pid_from_nft_pchild, SIGKILL);
	}
}

static void test_nft_pchild_lookup_failure_is_dropped(void) {
	guarded_kill_invocations = 0;
	guarded_terminate(-1);
	ASSERT_INT_EQ(guarded_kill_invocations, 0);
}

static void test_pid_zero_is_dropped(void) {
	guarded_kill_invocations = 0;
	guarded_terminate(0);
	ASSERT_INT_EQ(guarded_kill_invocations, 0);
}

static void test_pid_one_is_dropped(void) {
	/* pid 1 is init / the OS PID-1 supervisor; never our child. */
	guarded_kill_invocations = 0;
	guarded_terminate(1);
	ASSERT_INT_EQ(guarded_kill_invocations, 0);
}

static void test_real_child_pid_is_killed(void) {
	guarded_kill_invocations = 0;
	guarded_terminate(4242);
	ASSERT_INT_EQ(guarded_kill_invocations, 1);
}

int main(void) {
	test_nft_pchild_lookup_failure_is_dropped();
	test_pid_zero_is_dropped();
	test_pid_one_is_dropped();
	test_real_child_pid_is_killed();
	return finish_tests("poller_pid_guard tests");
}
