/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SPINE_TEST_CHILD_RUN_H
#define SPINE_TEST_CHILD_RUN_H

#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/* Fatal paths end in die(), which exits the whole process. Run the body in a
 * child so the parent can assert the exit status. Returns the exit status, or
 * 128 plus the signal number when the child was killed. The child's stderr is
 * silenced because die() reports there on purpose. */
static inline int spine_test_run_child(void (*body)(void)) {
	pid_t child;
	int status;

	fflush(NULL);
	child = fork();
	if (child < 0) return -1;
	if (child == 0) {
		/* cmocka traps SIGSEGV and would turn a crash into a hang */
		signal(SIGSEGV, SIG_DFL);
		signal(SIGABRT, SIG_DFL);
		if (freopen("/dev/null", "w", stderr) == NULL) _exit(120);
		if (freopen("/dev/null", "w", stdout) == NULL) _exit(121);
		body();
		_exit(0);
	}
	if (waitpid(child, &status, 0) != child) return -1;
	if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
	return WEXITSTATUS(status);
}

#endif
