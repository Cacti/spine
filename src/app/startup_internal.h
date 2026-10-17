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

#ifndef SPINE_STARTUP_INTERNAL_H
#define SPINE_STARTUP_INTERNAL_H

#include "internal/common.h"
#include "app/spine.h"
#include "database/persistence.h"
extern int *debug_devices;
extern int entries;
extern int num_hosts;
extern double start_time;
extern double total_time;
extern poller_thread_t **details;



int wait_for_workers(double begin_time);
void report_worker_completion(int num_rows);
void launch_poll_workers(MYSQL *mysql, MYSQL_RES *result, int num_rows,
	pthread_t *threads, spine_permits_t *thread_init_sem,
	const pthread_attr_t *attr, char *host_time);
void prepare_worker_storage(MYSQL_RES *result, int *rows,
	pthread_t **worker_threads, int **host_ids, char **timestamp);
void free_worker_storage(int num_rows, pthread_t *threads, int *ids,
	char *conf_file, char *host_time);
char *load_startup_configuration(char *conf_file);
void report_startup(int mode);
double initialize_process_defaults(void);
int initialize_main_database(MYSQL *mysql, MYSQL *mysqlr);
void initialize_main_php(void);
void close_main_php(void);
void report_poll_statistics(double begin_time, int num_rows);
#endif
