/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#ifndef _CACTID_H_
#define _CACTID_H_

/* Defines */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE !FALSE
#endif

/* general constants */
#define MAX_THREADS 100
#define BUFSIZE 1024
#define LOGSIZE 1024
#define BITSINBYTE 8
#define THIRTYTWO 4294967295ul
#define SIXTYFOUR 18446744073709551615ul
#define STAT_DESCRIP_ERROR 99
#define CACTID_PARENT 1
#define CACTID_FORK 0

/* locations to search for the config file */
#define CONFIG_PATHS 5
#define CONFIG_PATH_1 ""
#define CONFIG_PATH_2 "/etc/"
#define CONFIG_PATH_3 "/cygdrive/c/wwwroot/cacti"
#define CONFIG_PATH_4 "/cygdrive/c/webroot/cacti"
#define CONFIG_PATH_5 "/cygdrive/c/inetpub/wwwroot/cacti"

/* config file defaults */
#define DEFAULT_CONF_FILE "cactid.conf"
#define DEFAULT_THREADS 5
#define DEFAULT_INTERVAL 300
#define DEFAULT_OUT_OF_RANGE 93750000000
#define DEFAULT_DB_HOST "localhost"
#define DEFAULT_DB_DB "cacti"
#define DEFAULT_DB_USER "cactiuser"
#define DEFAULT_DB_PASS "cactiuser"
#define DEFAULT_DB_PORT 3306
#define DEFAULT_LOGFILE "/wwwroot/cacti/log/rrd.log"
#define DEFAULT_SNMP_VER 1
#define DEFAULT_TIMEOUT 294000000

/* threads constants */
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

/* poller actions */
#define POLLER_ACTION_SNMP 0
#define POLLER_ACTION_SCRIPT 1
#define POLLER_ACTION_PHP_SCRIPT_SERVER 2

/* reindex constants */
#define POLLER_COMMAND_REINDEX 1

/* logging levels */
#define POLLER_VERBOSITY_NONE 1
#define POLLER_VERBOSITY_LOW 2
#define POLLER_VERBOSITY_MEDIUM 3
#define POLLER_VERBOSITY_HIGH 4
#define POLLER_VERBOSITY_DEBUG 5

/* host availability statics */
#define AVAIL_SNMP_AND_PING 1
#define AVAIL_SNMP 2
#define AVAIL_PING 3

#define PING_ICMP 1
#define PING_UDP 2

#define HOST_UNKNOWN 0
#define HOST_DOWN 1
#define HOST_RECOVERING 2
#define HOST_UP 3

/* required for ICMP and UDP ping */
#define ICMP_ECHO 8
#define ICMP_HDR_SIZE 8

/* required for validation of script results */
#define RESULT_INIT 0
#define RESULT_ARGX 1
#define RESULT_VALX 2
#define RESULT_SEPARATOR 3
#define RESULT_SPACE 4
#define RESULT_ALPHA 5
#define RESULT_DIGIT 6

/* snmp session status */
#define SNMP_1 0
#define SNMP_2c 1
#define SNMP_3 3
#define SNMP_NONE 4

/* Typedefs */
typedef struct config_struct {
	int interval;
	int poller_id;
	long out_of_range;
	char dbhost[80];
	char dbdb[80];
	char dbuser[80];
	char dbpass[80];
    unsigned int dbport;
	char path_logfile[250];
	char path_php[250];
	char path_php_server[250];
	int log_destination;
	int log_perror;
	int log_pwarn;
	int log_pstats;
	int availability_method;
	int ping_method;
	int ping_retries;
	int ping_timeout;
	int ping_failure_count;
	int ping_recovery_count;
	int verbose;
	int php_running;
	int parent_fork;
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

struct icmphdr {
    char type;
	char code;
	unsigned short checksum;
	union {
		struct {
			unsigned short id;
			unsigned short sequence;
		} echo;
		unsigned int gateway;
		struct {
			unsigned short unused;
    		unsigned short mtu;
		} frag;
	} un;
};


/* Globals */
config_t set;
php_t php_pipes;

/* Variables for Time Display */
char start_datetime[20];

char config_paths[CONFIG_PATHS][BUFSIZE];

#endif /* not _CACTID_H_ */
