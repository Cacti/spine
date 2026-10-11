/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 */
#ifndef SPINE_COVERAGE_PROCESS_EXIT_H
#define SPINE_COVERAGE_PROCESS_EXIT_H
/* This header is force-included before common.h. Feature selection must
 * precede the first system header, just as it does in production builds. */
#ifndef _GNU_SOURCE
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

#endif
