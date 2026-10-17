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

#ifndef SPINE_TYPES_H
#define SPINE_TYPES_H

#include "internal/common.h"

#include "internal/constants.h"
#include "config/model.h"
#include "platform/thread.h"

/*! Target Structure
 *
 * This structure holds the contents of the Poller Items table and the results
 * of each polling action.
 *
 */
/* Owned SNMP identity and transport options. The borrowed snmp_connection_t
 * adapter remains separate; these arrays are never external pointers. */
typedef struct {
	char community[100];
	int version;
	char username[50];
	char password[50];
	char auth_protocol[7];
	char priv_passphrase[200];
	char priv_protocol[8];
	char context[65];
	char engine_id[30];
	int port;
	int timeout;
} snmp_profile_t;

typedef struct {
	int method;
	int ping_method;
	int port;
	int timeout;
	int retries;
} device_availability_t;

typedef struct target_struct {
	int target_id;
	char result[RESULTS_BUFFER];
	int local_data_id;
	int action;
	char command[256];
	char hostname[250];
	char rrd_name[30];
	char rrd_path[255];
	int rrd_num;
	char arg1[1024];
	char arg2[255];
	char arg3[255];
	char output_regex[255];
	snmp_profile_t snmp;
	device_availability_t availability;
} target_t;

/*! SNMP OID's Structure
 *
 * This structure holds SNMP get results temporarily while polling is taking place.
 *
 */
typedef struct snmp_oids {
	int array_position;
	char oid[1024];
	char result[RESULTS_BUFFER];
} snmp_oids_t;

/*! Poller Structure
 *
 * This structure holds thread polling instructions.
 *
 */
/* Process-local permits use a mutex because Darwin does not implement
 * unnamed POSIX semaphores. No caller needs a blocking semaphore wait. */

typedef struct poller_thread {
	int device_counter;
	int host_id;
	int host_thread;
	int host_threads;
	int host_data_ids;
	int threads_complete;
	int complete;
	int output_failed;
	int poll_failed;
	char host_time[40];
	double host_time_double;
	spine_permits_t *thread_init_sem;
} poller_thread_t;

/*! PHP Script Server Structure
 *
 * This structure holds status and PID information for all the running
 * PHP Script Server processes.
 *
 */
typedef struct php_processes {
	int php_state;
	pid_t php_pid;
	int php_write_fd;
	int php_read_fd;
} php_t;

/*! Host Structure
 *
 * This structure holds host information from the host table and is used throughout
 * the application.
 *
 */
typedef struct {
	snmp_profile_t profile;
	int retries;
	int max_oids;
	void *session;
	int status;
} host_snmp_t;

typedef struct {
	char snmp_sysDescr[600];
	char snmp_sysObjectID[160];
	unsigned long long snmp_sysUpTimeInstance;
	char snmp_sysContact[300];
	char snmp_sysName[300];
	char snmp_sysLocation[600];
} host_system_t;

typedef struct {
	int status;
	int status_event_count;
	char status_fail_date[40];
	char status_rec_date[40];
	char status_last_error[BUFSIZE * 2 + 2];
} host_state_t;

typedef struct {
	double min_time;
	double max_time;
	double cur_time;
	double avg_time;
	int total_polls;
	int failed_polls;
	double availability;
} host_statistics_t;

typedef struct host_struct {
	int id;
	char hostname[250];
	int ignore_host;
	host_snmp_t snmp;
	host_system_t system;
	device_availability_t availability;
	host_state_t state;
	host_statistics_t statistics;
} host_t;

/*! Host Reindex Structure
 *
 * This structure holds the results of the host re-index checks and values.
 *
 */
typedef struct host_reindex_struct {
	char op[4];
	char assert_value[100];
	char arg1[1024];
	int data_query_id;
	int action;
} reindex_t;

/*! Ping Result Structure
 *
 * This structure holds the results of a host ping.
 *
 */
typedef struct ping_results {
	char hostname[BUFSIZE];
	char ping_status[50];
	char ping_response[BUFSIZE];
	char snmp_status[50];
	char snmp_response[BUFSIZE];
} ping_t;

/*! Name Result Structure
 *
 * This structure holds the results of a name/port split
 *
 */
typedef struct name_port {
	// Method = 0 - default, 1 - tcp, 2 - udp
	char hostname[BUFSIZE];
	int method;
	int port;
} name_t;

/*! MySQL Connection Pool Structure
 *
 * This structure holds the mysql connection pool object.
 */
typedef struct db_connection {
	int id;
	int free;
	MYSQL mysql;
} pool_t;

#endif /* SPINE_TYPES_H */
