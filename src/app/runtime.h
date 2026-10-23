/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#ifndef SPINE_RUNTIME_H
#define SPINE_RUNTIME_H

/* One invocation per process. Owns initialization, workers and shutdown.
 * Uses the existing process-wide state and exits with the existing exit code;
 * tests invoke it in an isolated child process, never concurrently in-process.
 * argv is borrowed and may be modified during CLI parsing. */
_Noreturn void spine_run(int argc, char *argv[]);

#endif
