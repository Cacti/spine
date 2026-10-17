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

#ifndef SPINE_PHP_H
#define SPINE_PHP_H
extern char *php_cmd(const char *php_command, int php_process);
extern char *php_readpipe(int php_process, const char *command);
extern void php_command_script(const char *command, char *script, size_t capacity);
extern int php_init(int php_process);
extern void php_close(int php_process);
extern int php_get_process(void);
extern void php_processes_initialize(php_t *processes, int count);

#ifdef SPINE_PHP_RUNTIME_TESTING
extern ssize_t php_write_no_sigpipe_for_test(int fd, const void *buffer, size_t length);
extern char *php_read_result_for_test(int php_process, char *command, int allow_restart);
#endif

#endif /* SPINE_PHP_H */
