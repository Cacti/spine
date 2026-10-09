/* Copyright (C) 2026 The Cacti Group
 * Licensed under the GNU Lesser General Public License, version 2.1 or later. */
#ifndef SPINE_COVERAGE_PROCESS_EXIT_H
#define SPINE_COVERAGE_PROCESS_EXIT_H
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
