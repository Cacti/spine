/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_POLLER_H
#define SPINE_POLLER_H
typedef struct {
	char items[BUFSIZE];
	char host[BIG_BUFSIZE];
	char reindex[BUFSIZE];
	char due_items[BUFSIZE];
	char schedule[BUFSIZE];
	char output[BUFSIZE];
	char agents[BUFSIZE];
	char due_agents[BUFSIZE];
	char boost_output[BUFSIZE];
	char suffix[BUFSIZE];
} poller_queries_t;

extern void poller_prepare_queries(poller_queries_t *queries, int host_id, int host_thread, int host_data_ids);

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
extern void buffer_output_errors(char * error_string, int * buf_size, int * buf_errors, int device_id, int thread_id, int local_data_id, bool flush);

#endif /* SPINE_POLLER_H */
