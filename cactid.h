/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
#define TRUE 1
#endif

#ifndef __GNUC__
# define __attribute__(x)  /* NOTHING */
#endif

/* if a host is legal, return TRUE */
#define HOSTID_DEFINED(x)	((x) >= 0)

/* general constants */
#define MAX_THREADS 100
#define BUFSIZE 1024
#define LOGSIZE 4096
#define BITSINBYTE 8
#define THIRTYTWO 4294967295ul
#define SIXTYFOUR 18446744073709551615ul
#define STAT_DESCRIP_ERROR 99
#define CACTID_PARENT 1
#define CACTID_FORK 0

/* locations to search for the config file */
#define CONFIG_PATHS 2
#define CONFIG_PATH_1 ""
#define CONFIG_PATH_2 "/etc/"

/* config file defaults */
#define DEFAULT_CONF_FILE "cactid.conf"
#define DEFAULT_THREADS 5
#define DEFAULT_DB_HOST "localhost"
#define DEFAULT_DB_DB "cacti"
#define DEFAULT_DB_USER "cactiuser"
#define DEFAULT_DB_PASS "cactiuser"
#define DEFAULT_DB_PORT 3306
#define DEFAULT_LOGFILE "/wwwroot/cacti/log/cactid.log"
#define DEFAULT_TIMEOUT 294000000

/* threads constants */
#define LOCK_SNMP 0
#define LOCK_THREAD 1
#define LOCK_MYSQL 2
#define LOCK_GHBN 3
#define LOCK_PIPE 4
#define LOCK_SYSLOG 5
#define LOCK_PHP 6
#define LOCK_PHP_PROC_0 7
#define LOCK_PHP_PROC_1 8
#define LOCK_PHP_PROC_2 9
#define LOCK_PHP_PROC_3 10
#define LOCK_PHP_PROC_4 11
#define LOCK_PHP_PROC_5 12
#define LOCK_PHP_PROC_6 13
#define LOCK_PHP_PROC_7 14
#define LOCK_PHP_PROC_8 15
#define LOCK_PHP_PROC_9 16

#define LOCK_SNMP_O 0
#define LOCK_THREAD_O 1
#define LOCK_MYSQL_O 2
#define LOCK_GHBN_O 3
#define LOCK_PIPE_O 4
#define LOCK_SYSLOG_O 5
#define LOCK_PHP_O 6
#define LOCK_PHP_PROC_0_O 7
#define LOCK_PHP_PROC_1_O 8
#define LOCK_PHP_PROC_2_O 9
#define LOCK_PHP_PROC_3_O 10
#define LOCK_PHP_PROC_4_O 11
#define LOCK_PHP_PROC_5_O 12
#define LOCK_PHP_PROC_6_O 13
#define LOCK_PHP_PROC_7_O 14
#define LOCK_PHP_PROC_8_O 15
#define LOCK_PHP_PROC_9_O 16

/* poller actions */
#define POLLER_ACTION_SNMP 0
#define POLLER_ACTION_SCRIPT 1
#define POLLER_ACTION_PHP_SCRIPT_SERVER 2

/* reindex constants */
#define POLLER_COMMAND_REINDEX 1

/* log destinations */
#define LOGDEST_FILE   1
#define LOGDEST_BOTH   2
#define LOGDEST_SYSLOG 3
#define LOGDEST_STDOUT 4

#define IS_LOGGING_TO_FILE(ld)   ((ld) == LOGDEST_FILE   || (ld) == LOGDEST_BOTH)
#define IS_LOGGING_TO_SYSLOG(ld) ((ld) == LOGDEST_SYSLOG || (ld) == LOGDEST_BOTH)

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

/* required for PHP Script Server */
#define MAX_PHP_SERVERS 10
#define PHP_READY 0
#define PHP_BUSY 1
#define PHP_INIT 999
#define PHP_ERROR 99

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

/*! Config Structure
 *
 * This structure holds Cactid database configuration information and/or override values
 * obtained via either accessing the database or reading the runtime options.  In addition,
 * it contains runtime status information.
 *
 */
typedef struct config_struct {
	/* general configuration/runtime settings */
	int poller_id;
	int poller_interval;
	int parent_fork;
	int num_parent_processes;
	int script_timeout;
	int threads;
	/* debugging options */
	int snmponly;
	int SQL_readonly;
	/* host range to be poller with this cactid process */
	int start_host_id;
	int end_host_id;
	/* database connection information */
	char dbhost[80];
	char dbdb[80];
	char dbuser[80];
	char dbpass[80];
	int dboff;
	unsigned int dbport;
	/* path information */
	char path_logfile[250];
	char path_php[250];
	char path_php_server[250];
	/* logging options */
	int log_level;
	int log_destination;
	int log_perror;
	int log_pwarn;
	int log_pstats;
	/* ping settings */
	int availability_method;
	int ping_method;
	int ping_retries;
	int ping_timeout;
	int ping_failure_count;
	int ping_recovery_count;
	/* snmp options */
	int snmp_max_get_size;
	int snmp_retries;
	/* PHP Script Server Options */
	int php_required;
	int php_initialized;
	int php_servers;
	int php_current_server;
} config_t;

/*! Target Structure
 *
 * This structure holds the contents of the Poller Items table and the results
 * of each polling action.
 *
 */
typedef struct target_struct {
	int target_id;
	char result[512];
	int local_data_id;
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
	int rrd_num;
	char arg1[255];
	char arg2[255];
	char arg3[255];
} target_t;

/*! SNMP OID's Structure
 *
 * This structure holds SNMP get results temporarily while polling is taking place.
 *
 */
typedef struct snmp_oids {
	int array_position;
	char oid[255];
	char result[255];
} snmp_oids_t;

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
typedef struct host_struct {
	int id;
	char hostname[250];
	char snmp_community[100];
	char snmp_username[50];
	char snmp_password[50];
	int snmp_version;
	int snmp_port;
	int snmp_timeout;
	int status;
	int status_event_count;
	char status_fail_date[40];
	char status_rec_date[40];
	char status_last_error[100];
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

/*! Host Reindex Structure
 *
 * This structure holds the results of the host re-index checks and values.
 *
 */
typedef struct host_reindex_struct {
	char op[4];
	char assert_value[100];
	char arg1[100];
	int data_query_id;
	int action;
} reindex_t;

/*! Ping Result Struction
 *
 * This structure holds the results of a host ping.
 *
 */
typedef struct ping_results {
	char hostname[255];
	char ping_status[50];
	char ping_response[50];
	char snmp_status[50];
	char snmp_response[50];
} ping_t;

/*! ICMP Ping Structure
 *
 * This structure is required to craft a raw ICMP packet in order to ping a host.
 *
 */
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

/*! Override Options Structure
 *
 * When we fetch a setting from the database, we allow the user to override
 * it from the command line. These overrides are provided with the --option
 * parameter and stored in this table: we *use* them when the config code
 * reads from the DB.
 *
 * It's not an error to set an option which is unknown, but maybe should be.
 *
 */
static struct {
	const char *opt;
	const char *val;
} opttable[256];

/* Globals */
static int nopts = 0;
config_t set;
php_t *php_processes;
char start_datetime[20];
char config_paths[CONFIG_PATHS][BUFSIZE];

static void display_help(void);
static char *getarg(char *opt, char ***pargv);
void die(const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 1, 2)));

#endif /* not _CACTID_H_ */
