/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Platform sandbox smoke test. Verifies that:
 |   1. spine_sandbox_unveil_paths(NULL,NULL,NULL) is a no-op on every
 |      platform (including the ones that fall back to an empty stub).
 |   2. spine_sandbox_restrict() does not itself kill the process. The
 |      call is made inside a forked child so an accidental pledge/seccomp
 |      abort only fails the child, not the test harness.
 |   3. On Linux with libseccomp, PR_GET_NO_NEW_PRIVS returns 1 after the
 |      restrict call.
 +-------------------------------------------------------------------------+
*/

#include "platform/platform_sandbox.h"
#include "test_platform_helpers.h"

#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__linux__)
#include <sys/prctl.h>
#endif

static void test_unveil_null_is_noop(void) {
	spine_sandbox_unveil_paths(NULL, NULL, NULL);
	spine_sandbox_unveil_paths("/tmp/fake-log", NULL, NULL);
	spine_sandbox_unveil_paths(NULL, "/tmp/fake-pid", NULL);
	spine_sandbox_unveil_paths(NULL, NULL, "/tmp/fake-scripts");
}

#ifndef _WIN32
static void test_restrict_does_not_kill_process(void) {
	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed; skipping sandbox restrict test\n");
		return;
	}

	if (pid == 0) {
		/* Child: declare paths, then drop privileges. On OpenBSD pledge
		 * would terminate the child if it crossed the promise boundary;
		 * here we do nothing promise-violating before _exit. On Linux
		 * PR_SET_NO_NEW_PRIVS is cheap and cannot fail the process. */
		spine_sandbox_unveil_paths("/tmp", "/tmp", "/tmp");
		spine_sandbox_restrict();

#if defined(__linux__)
		int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
		_exit(nnp == 1 ? 0 : 2);
#else
		_exit(0);
#endif
	}

	int status = 0;
	pid_t waited = waitpid(pid, &status, 0);
	ASSERT_TRUE(waited == pid);
	ASSERT_TRUE(WIFEXITED(status));
	if (WIFEXITED(status)) {
		ASSERT_INT_EQ(WEXITSTATUS(status), 0);
	}
}
#endif

int main(void) {
	test_unveil_null_is_noop();
#ifndef _WIN32
	test_restrict_does_not_kill_process();
#endif
	return finish_tests("platform sandbox tests");
}
