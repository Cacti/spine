/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#ifndef _CACTID_H_
#define _CACTID_H_ 1

/* Defines */
#ifndef FALSE
# define FALSE 0
#endif
#ifndef TRUE
# define TRUE !FALSE
#endif

/* Constants */
#define MAX_THREADS 100
#define BUFSIZE 512
#define LOGSIZE 255
#define BITSINBYTE 8
#define THIRTYTWO 4294967295ul
#define SIXTYFOUR 18446744073709551615ul

#define CONFIG_PATHS 5
#define CONFIG_PATH_1 ""
#define CONFIG_PATH_2 "/etc/"
#define CONFIG_PATH_3 "/wwwroot/cacti"
#define CONFIG_PATH_4 "c:/wwwroot/cacti"
#define CONFIG_PATH_5 "c:/inetpub/wwwroot/cacti"

/* Defaults */
#define DEFAULT_CONF_FILE "cactid.conf"
#define DEFAULT_THREADS 5
#define DEFAULT_INTERVAL 300
#define DEFAULT_OUT_OF_RANGE 93750000000
#define DEFAULT_DB_HOST "localhost"
#define DEFAULT_DB_DB "cacti"
#define DEFAULT_DB_USER "cactiuser"
#define DEFAULT_DB_PASS "cactiuser"
#define DEFAULT_Log_File "/wwwroot/cacti/log/cacti.log"
#define DEFAULT_PATH_PHP_SERVER "/wwwroot/cacti/script_server.php"
#define DEFAULT_SNMP_VER 1

/* Verbosity levels LOW=info MEDIUM=info+hoststats HIGH=info+SQL DEBUG=info+SQL+junk */
#define NONE 1
#define LOW 2
#define MEDIUM 3
#define HIGH 4
#define DEBUG 5

#define LOCK_SNMP 0
#define LOCK_THREAD 1
#define LOCK_MYSQL 2
#define LOCK_RRDTOOL 3
#define LOCK_PIPE 4
#define LOCK_SYSLOG 5
#define LOCK_PHP 6

#define LOCK_SNMP_O 0
#define LOCK_THREAD_O 1
#define LOCK_MYSQL_O 2
#define LOCK_RRDTOOL_O 3
#define LOCK_PIPE_O 4
#define LOCK_SYSLOG_O 5
#define LOCK_PHP_O 6

#define POLLER_ACTION_SNMP 0
#define POLLER_ACTION_SCRIPT 1
#define POLLER_ACTION_PHP_SCRIPT_SERVER 2

#define POLLER_COMMAND_REINDEX 1

#define POLLER_VERBOSITY_NONE 1
#define POLLER_VERBOSITY_LOW 2
#define POLLER_VERBOSITY_MEDIUM 3
#define POLLER_VERBOSITY_HIGH 4
#define POLLER_VERBOSITY_DEBUG 5

#define AVAIL_SNMP_AND_PING 1
#define AVAIL_SNMP 2
#define AVAIL_PING 3

#define PING_ICMP 1
#define PING_UDP 2

#define HOST_UNKNOWN 0
#define HOST_DOWN 1
#define HOST_RECOVERING 2
#define HOST_UP 3

#define STAT_DESCRIP_ERROR 99

/* Typedefs */
typedef struct config_struct {
	int interval;
	int poller_id;
	long out_of_range;
	char dbhost[80];
	char dbdb[80];
	char dbuser[80];
	char dbpass[80];
	char path_logfile[250];
	char path_php[250];
	char path_php_server[250];
	int log_destination;
	int log_perror;
	int log_pstats;
	int availability_method;
	int ping_method;
	int ping_retries;
	int ping_timeout;
	int ping_failure_count;
	int ping_recovery_count;
	int verbose;
	int dboff;
	int snmp_ver;
	int threads;
} config_t;

typedef struct target_struct {
	int target_id;
	char result[512];
	int local_data_id;
	int rrd_num;
	int action;
	char command[256];
	char hostname[250];
	char snmp_community[100];
	int snmp_version;
	char snmp_username[50];
	char snmp_password[50];
	int snmp_port;
	int snmp_timeout;
	char rrd_name[30];
	char rrd_path[255];
	char arg1[255];
	char arg2[255];
	char arg3[255];
} target_t;

typedef struct php_pipe_struct {
	int php_write_fd;
	int php_read_fd;
} php_t;

typedef struct host_struct {
	int id;
	char hostname[250];
	char snmp_community[100];
	int snmp_version;
	int snmp_port;
	int snmp_timeout;
	int status;
	int status_event_count;
	char status_fail_date[40];
	char status_rec_date[40];
	char status_last_error[50];
	double min_time;
	double max_time;
	double cur_time;
	double avg_time;
	int total_polls;
	int failed_polls;
	double availability;
	int ignore_host;
	void *snmp_session;
} host_t;

typedef struct host_reindex_struct {
	char op[2];
	char assert_value[100];
	char arg1[100];
	int data_query_id;
	int action;
} reindex_t;

typedef struct ping_results {
	char hostname[255];
	char ping_status[50];
	char ping_response[50];
	char snmp_status[50];
	char snmp_response[50];
} ping_t;

typedef struct cacti_icmp {
	char icmp_type;
	char icmp_code;
	short icmp_chksm;
	short icmp_uid;
	short icmp_sqn;
	char data[23];
} icmp_t;

/* Globals */
config_t set;
php_t php_pipes;

char config_paths[CONFIG_PATHS][BUFSIZE];

#endif /* not _CACTID_H_ */
