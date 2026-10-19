/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#ifndef SPINE_COVERAGE_PROCESS_EXIT_H
#define SPINE_COVERAGE_PROCESS_EXIT_H
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
/* Instrumentation only: flush owned subprocess counters before POSIX _exit.
 * Preserve _exit's descriptor and stdio behavior; do not replace it with exit. */
#include <unistd.h>
extern void __gcov_dump(void);
static inline __attribute__((noreturn)) void spine_coverage_process_exit(int status) {
	__gcov_dump();
	_exit(status);
}
#define _exit(status) spine_coverage_process_exit(status)

/* A successful exec replaces the process before its normal gcov teardown. */
static inline int spine_coverage_process_exec(const char *path, char *const arguments[], char *const environment[]) {
	__gcov_dump();
	return execve(path, arguments, environment);
}
#define execve(path, arguments, environment) spine_coverage_process_exec(path, arguments, environment)

#endif
