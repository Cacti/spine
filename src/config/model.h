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

#ifndef SPINE_CONFIG_MODEL_H
#define SPINE_CONFIG_MODEL_H

#include <stddef.h>
#include "internal/constants.h"

/*! Config Structure
 *
 * This structure holds Spine database configuration information and/or override values
 * obtained via either accessing the database or reading the runtime options.  In addition,
 * it contains runtime status information.
 *
 */
/* Console configuration and runtime state. */
typedef struct {
	int stdout_notty;
	int stderr_notty;
} spine_console_config_t;

/* Poller configuration and runtime state. */
typedef struct {
	int poller_id;
	int poller_interval;
	int parent_fork;
	int num_parent_processes;
	int active_profiles;
	int threads;
	int threads_set;
	int snmponly;
	int SQL_readonly;
	int mode;
} spine_poller_config_t;

/* Hosts configuration and runtime state. */
typedef struct {
	int start_host_id;
	int end_host_id;
	char host_id_list[BIG_BUFSIZE];
	int has_device_0;
	int has_output_regex;
} spine_hosts_config_t;

/* Database configuration and runtime state. */
typedef struct {
	char host[BUFSIZE];
	char database[BUFSIZE];
	char user[BUFSIZE];
	char password[BUFSIZE];
	int ssl;
	char ssl_key[BUFSIZE];
	char ssl_cert[BUFSIZE];
	char ssl_ca[BUFSIZE];
	unsigned int port;
	char version[BUFSIZE];
	int onupdate;
} spine_database_config_t;

/* Php configuration and runtime state. */
typedef struct {
	char path_php[BUFSIZE];
	char path_php_server[BUFSIZE];
	int script_timeout;
	int php_required;
	int php_initialized;
	int php_servers;
	int php_current_server;
} spine_php_config_t;

/* Logging configuration and runtime state. */
typedef struct {
	char path_logfile[DBL_BUFSIZE];
	int logfile_processed;
	int log_level;
	int log_destination;
	int log_perror;
	int log_pwarn;
	int log_pstats;
	char selective_device_debug[LRG_BUFSIZE];
	int spine_log_level;
	int log_datetime_separator;
	int log_datetime_format;
} spine_logging_config_t;

/* Availability configuration and runtime state. */
typedef struct {
	int icmp_avail;
	int icmp_uses_caps;
	int availability_method;
	int ping_method;
	int ping_retries;
	int ping_timeout;
	int ping_failure_count;
	int ping_recovery_count;
	int ping_only;
} spine_availability_config_t;

/* Snmp configuration and runtime state. */
typedef struct {
	int total_snmp_ports;
	int snmp_max_get_size;
	int snmp_retries;
	char snmp_clientaddr[BUFSIZE];
	int mibs;
} spine_snmp_config_t;

/* Boost configuration and runtime state. */
typedef struct {
	int boost_enabled;
	int boost_redirect;
} spine_boost_config_t;

/* Exit configuration and runtime state. */
typedef struct {
	int exit_code;
	size_t exit_size;
	void *exit_stack[10];
} spine_exit_config_t;

/* Process-local aggregate. A full rebuild is required when its layout changes. */
typedef struct config_struct {
	spine_console_config_t console;
	spine_poller_config_t poller;
	spine_hosts_config_t hosts;
	spine_database_config_t database;
	spine_database_config_t remote_database;
	spine_php_config_t php;
	spine_logging_config_t logging;
	spine_availability_config_t availability;
	spine_snmp_config_t snmp;
	spine_boost_config_t boost;
	spine_exit_config_t exit;
	int d_b;
	int cacti_version;
	int cygwinshloc;
} config_t;

#endif
