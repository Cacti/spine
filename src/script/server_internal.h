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

#ifndef SPINE_PHP_INTERNAL_H
#define SPINE_PHP_INTERNAL_H

#include "internal/common.h"
#include "app/spine.h"
extern char **environ;



char *php_read_result(int php_process, const char *command, int allow_restart);
void php_fail_read(int php_process, int allow_restart);
ssize_t php_write_no_sigpipe(int fd, const void *buffer, size_t length);
#ifdef SPINE_PHP_RUNTIME_TESTING
/* Test seam avoids libc symbol aliases defeating linker interposition. */
int spine_php_test_sigmask(int how, const sigset_t *mask, sigset_t *previous);
#endif
#endif
