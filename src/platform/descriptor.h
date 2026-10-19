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

#ifndef SPINE_DESCRIPTOR_H
#define SPINE_DESCRIPTOR_H

/* set borrows fd; dup returns a new owned descriptor. On failure return -1
 * with errno. Caller closes successful duplicates and synchronizes descriptor
 * lifetime; errors use the normal logging path. */
int spine_set_cloexec(int fd);
int spine_dup_cloexec(int fd);
/* Filesystem observation only; 1 if stat succeeds, 0 otherwise. */
int file_exists(const char *filename);

#endif
