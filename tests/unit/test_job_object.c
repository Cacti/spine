/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Windows Job Object lifecycle: child processes must inherit the Job so
 | closing the Job Object kills them (KILL_ON_JOB_CLOSE). This guards the
 | Windows-only orphan-cleanup path used by the spine poller when a
 | script exceeds its timeout budget.
 +-------------------------------------------------------------------------+
*/

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>

#include "platform/platform.h"
#include "test_platform_helpers.h"

static void test_job_object_created_and_assigned_to_self(void) {
	spine_win_init_job();
	HANDLE job = (HANDLE) spine_win_job_object();
	ASSERT_TRUE(job != NULL);

	BOOL in_job = FALSE;
	ASSERT_TRUE(IsProcessInJob(GetCurrentProcess(), NULL, &in_job));
	ASSERT_TRUE(in_job);
}

static void test_job_object_is_idempotent(void) {
	HANDLE first  = (HANDLE) spine_win_job_object();
	spine_win_init_job();
	HANDLE second = (HANDLE) spine_win_job_object();
	ASSERT_TRUE(first == second);
}

int main(void) {
	test_job_object_created_and_assigned_to_self();
	test_job_object_is_idempotent();
	return finish_tests("windows job object tests");
}

#else

int main(void) {
	return 0;
}

#endif
