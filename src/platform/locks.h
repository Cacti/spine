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

#ifndef SPINE_LOCKS_H
#define SPINE_LOCKS_H
extern const char* get_name(int lock);
extern void init_mutexes(void);
extern void thread_mutex_lock(int mutex);
extern void thread_mutex_unlock(int mutex);
extern int thread_mutex_trylock(int mutex);
extern pthread_cond_t* get_cond(int lock);
extern pthread_mutex_t* get_lock(int lock);
extern pthread_once_t* get_attr(int locko);

#endif /* SPINE_LOCKS_H */
