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

#ifndef SPINE_POLLER_H
#define SPINE_POLLER_H
#include "database/cacti_query.h"

extern void *child(void *arg);
extern void child_cleanup(void *arg);
extern void child_cleanup_thread(void *arg);
extern void child_cleanup_script(void *arg);
extern void poll_host(const poller_thread_t *work, int *host_errors);
extern char *exec_poll(host_t *current_host, char *command, int id, const char *type);
extern void get_system_information(host_t *host, MYSQL *mysql, int system);
enum poll_result_status {
	POLL_RESULT_VALID,
	POLL_RESULT_UNDEFINED,
	POLL_RESULT_INVALID
};
extern enum poll_result_status normalize_poll_result(char *result, bool snmp);
extern int format_poller_output_row(char *output, size_t output_size,
	int local_data_id, const char *escaped_rrd_name,
	const char *host_time, const char *escaped_result);
extern void buffer_output_errors(char *error_string, int *buf_size, int *buf_errors, int device_id, int thread_id, int local_data_id, bool flush);

#endif /* SPINE_POLLER_H */
