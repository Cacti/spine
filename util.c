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

#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <errno.h>
#include "common.h"
#include "cactid.h"
#include "util.h"
#include "snmp.h"
#include "sql.h"

/******************************************************************************/
/*  read_config_options() - load default values from the database for poller  */
/*                          processing.                                       */
/******************************************************************************/
int read_config_options(config_t *set) {
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int num_rows;
	char logmessage[LOGSIZE];
	uid_t ruid;
	char web_root[BUFSIZE];

	db_connect(set->dbdb, &mysql);

	/* get logging level from database - overrides cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_verbosity'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (atoi(mysql_row[0])) {
			set->verbose = atoi(mysql_row[0]);
		}
	}

	/* determine script server path operation and default log file processing */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_webroot'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		strncpy(set->path_php_server,mysql_row[0], sizeof(set->path_php_server));
		strncpy(web_root, mysql_row[0], sizeof(web_root));
		strncat(set->path_php_server,"/script_server.php", sizeof(set->path_php_server));
	}

	/* determine logfile path */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_cactilog'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (strlen(mysql_row[0]) != 0) {
			strncpy(set->path_logfile,mysql_row[0], sizeof(set->path_logfile));
		} else {
			strncpy(set->path_logfile, strcat(web_root, "/log/cacti.log"), sizeof(set->path_logfile));
		}
	} else {
		strncpy(set->path_logfile, strcat(web_root, "/log/cacti.log"), sizeof(set->path_logfile));
 	}

	/* log the path_webroot variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The path_php_server variable is %s\n" ,set->path_php_server);
		cacti_log(logmessage);
	}

	/* log the path_cactilog variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The path_cactilog variable is %s\n" ,set->path_logfile);
		cacti_log(logmessage);
	}

	/* determine log file, syslog or both, default is 1 or log file only */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_destination'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set->log_destination = atoi(mysql_row[0]);
	}else{
		set->log_destination = 1;
	}

	/* log the log_destination variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The log_destination variable is %i\n" ,set->log_destination);
		cacti_log(logmessage);
	}

	/* get PHP Path Information for Scripting */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_php_binary'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		strncpy(set->path_php,mysql_row[0], sizeof(set->path_php));
	}

	/* log the path_php variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The path_php variable is %s\n" ,set->path_php);
		cacti_log(logmessage);
	}

	/* set availability_method */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='availability_method'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->availability_method = atoi(mysql_row[0]);
	}

	/* log the availability_method variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The availability_method variable is %i\n" ,set->availability_method);
		cacti_log(logmessage);
	}

	/* set ping_recovery_count */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_recovery_count'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_recovery_count = atoi(mysql_row[0]);
	}

	/* log the ping_recovery_count variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The ping_recovery_count variable is %i\n" ,set->ping_recovery_count);
		cacti_log(logmessage);
	}

	/* set ping_failure_count */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_failure_count'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_failure_count = atoi(mysql_row[0]);
	}

	/* log the ping_failure_count variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The ping_failure_count variable is %i\n" ,set->ping_failure_count);
		cacti_log(logmessage);
	}

	/* set ping_method */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_method'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_method = atoi(mysql_row[0]);
	}

	ruid = 999;

	#if defined(__CYGWIN__)
	/* root check not required for windows */
	ruid = 0;
	printf("CACTID: Windows Environment, root permissions not required for ICMP Ping\n");

	#else
	/* check for root status (ruid=0) */
	ruid = getuid();

	/* fall back to UDP ping if ICMP is not available */
	if (ruid != 0) {
		if ((set->availability_method == AVAIL_SNMP_AND_PING) || (set->availability_method == AVAIL_PING)) {
			if (set->ping_method == PING_ICMP) {
    			set->ping_method = PING_UDP;
				printf("CACTID: WARNING: Falling back to UDP Ping due to User not being ROOT\n");
				printf("        To setup a process to run as root, see your documentaion\n");
				if (set->verbose == POLLER_VERBOSITY_DEBUG) {
					snprintf(logmessage, LOGSIZE, "DEBUG: Falling back to UDP Ping due to the running User not being ROOTBEER\n");
					cacti_log(logmessage);
				}
			}
		}
	} else {
		printf("CACTID: Non Window envrionment, running as root, ICMP Ping available\n");
	}

	#endif

	/* log the ping_method variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The ping_method variable is %i\n" ,set->ping_method);
		cacti_log(logmessage);
	}

	/* set ping_retries */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_retries'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_retries = atoi(mysql_row[0]);
	}

	/* log the ping_retries variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The ping_retries variable is %i\n" ,set->ping_retries);
		cacti_log(logmessage);
	}

	/* set ping_timeout */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_timeout'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_timeout = atoi(mysql_row[0]);
	}

	/* log the ping_timeout variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The ping_timeout variable is %i\n" ,set->ping_timeout);
		cacti_log(logmessage);
	}

	/* set logging option for errors */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_perror'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (!strcmp(mysql_row[0],"on")) {
			set->log_perror = 1;
		}else {
			set->log_perror = 0;
		}
	}

	/* log the log_perror variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The log_perror variable is %i\n" ,set->log_perror);
		cacti_log(logmessage);
	}

	/* set logging option for errors */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_pwarn'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (!strcmp(mysql_row[0],"on")) {
			set->log_pwarn = 1;
		}else {
			set->log_pwarn = 0;
		}
	}

	/* log the log_pwarn variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The log_pwarn variable is %i\n" ,set->log_pwarn);
		cacti_log(logmessage);
	}

	/* set logging option for statistics */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_pstats'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (!strcmp(mysql_row[0],"on")) {
			set->log_pstats = 1;
		}else {
			set->log_pstats = 0;
		}
	}

	/* log the log_pstats variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The log_pstats variable is %i\n" ,set->log_pstats);
		cacti_log(logmessage);
	}

	/* get Cacti defined max threads override cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='max_threads'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set->threads = atoi(mysql_row[0]);
		if (set->threads > 30) {
			set->threads = 30;
		}
	}

	/* log the threads variable */
	if (set->verbose == POLLER_VERBOSITY_DEBUG) {
		snprintf(logmessage, LOGSIZE, "DEBUG: The threads variable is %i\n" ,set->threads);
		cacti_log(logmessage);
	}

	mysql_free_result(result);
	mysql_close(&mysql);
}

/******************************************************************************/
/*  read_cactid_config() - read the CACTID configuration files to obtain      */
/*                         environment settings.                              */
/******************************************************************************/
int read_cactid_config(char *file, config_t *set) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];

	if ((fp = fopen(file, "rb")) == NULL) {
		printf("ERROR: Could not open config file\n");
		return (-1);
	}else{
		if (set->verbose >= POLLER_VERBOSITY_HIGH) {
			printf("CACTID: Using cactid config file [%s]\n", file);
		}

		while(!feof(fp)) {
			fgets(buff, BUFSIZE, fp);
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%15s %255s", p1, p2);

				if (!strcasecmp(p1, "Interval")) set->interval = atoi(p2);
				else if (!strcasecmp(p1, "DB_Host")) strncpy(set->dbhost, p2, sizeof(set->dbhost));
				else if (!strcasecmp(p1, "DB_Database")) strncpy(set->dbdb, p2, sizeof(set->dbdb));
				else if (!strcasecmp(p1, "DB_User")) strncpy(set->dbuser, p2, sizeof(set->dbuser));
				else if (!strcasecmp(p1, "DB_Pass")) strncpy(set->dbpass, p2, sizeof(set->dbpass));
                else if (!strcasecmp(p1, "DB_Port")) set->dbport = atoi(p2);
				else {
					printf("WARNING: Unrecongized directive: %s=%s in %s\n", p1, p2, file);
				}
			}
		}

		return (0);
	}
}

/******************************************************************************/
/*  config_defaults() - populate system variables with default values.        */
/******************************************************************************/
void config_defaults(config_t * set) {
	set->interval = DEFAULT_INTERVAL;
	set->snmp_ver = DEFAULT_SNMP_VER;
	set->threads = DEFAULT_THREADS;
    set->dbport = DEFAULT_DB_PORT;

	strncpy(set->dbhost, DEFAULT_DB_HOST, sizeof(set->dbhost));
	strncpy(set->dbdb, DEFAULT_DB_DB, sizeof(set->dbhost));
	strncpy(set->dbuser, DEFAULT_DB_USER, sizeof(set->dbhost));
	strncpy(set->dbpass, DEFAULT_DB_PASS, sizeof(set->dbhost));

	strncpy(config_paths[0], CONFIG_PATH_1, sizeof(config_paths[0]));
	strncpy(config_paths[1], CONFIG_PATH_2, sizeof(config_paths[1]));
	strncpy(config_paths[2], CONFIG_PATH_3, sizeof(config_paths[2]));
	strncpy(config_paths[3], CONFIG_PATH_4, sizeof(config_paths[3]));
	strncpy(config_paths[4], CONFIG_PATH_5, sizeof(config_paths[4]));

	return;
}

/******************************************************************************/
/*  cacti_log() - output user messages to the Cacti logfile facility.         */
/*                Can also output to the syslog facility if desired.          */
/******************************************************************************/
void cacti_log(char *logmessage) {
	FILE *log_file = NULL;

	/* Variables for Time Display */
	time_t nowbin;
	const struct tm *nowstruct;
	char logprefix[40]; /* Formatted Log Prefix */
	char flogmessage[LOGSIZE];	/* Formatted Log Message */
	extern config_t set;
	int fileopen = 0;

	/* log message prefix */
	snprintf(logprefix, sizeof(logprefix), "CACTID: Poller[%i] ", set.poller_id);

	if (((set.log_destination == 1) || (set.log_destination == 2)) && (set.verbose != POLLER_VERBOSITY_NONE)) {
		while (!fileopen) {
			if (!file_exists(set.path_logfile)) {
				log_file = fopen(set.path_logfile, "w");
			}else {
				log_file = fopen(set.path_logfile, "a");
			}

			if (log_file != NULL) {
				fileopen = 1;
			}else {
				printf("ERROR: Could not open Logfile will not be logging\n");
				break;
			}
		}
	}

	/* get time for logfile */
	if (time(&nowbin) == (time_t) - 1)
		printf("ERROR: Could not get time of day from time()\n");

	nowstruct = localtime(&nowbin);

	if (strftime(flogmessage, 50, "%m/%d/%Y %I:%M:%S %p - ", nowstruct) == (size_t) 0)
		printf("ERROR: Could not get string from strftime()\n");

	strcat(flogmessage, logprefix);
	strcat(flogmessage, logmessage);

	if ( fileopen != 0 ) {
		fputs(flogmessage, log_file);
		fclose(log_file);
	}

	/* output to syslog/eventlog */
	if ((set.log_destination == 2) || (set.log_destination == 3)) {
		openlog("Cacti Logging", LOG_NDELAY | LOG_PID, LOG_SYSLOG);
		if ((strstr(flogmessage,"ERROR")) && (set.log_perror)) {
			syslog(LOG_CRIT,"%s\n", flogmessage);
		}
		if ((strstr(flogmessage,"WARNING")) && (set.log_pwarn)){
			syslog(LOG_WARNING,"%s\n", flogmessage);
		}
		if ((strstr(flogmessage,"STATS")) && (set.log_pstats)){
				syslog(LOG_NOTICE,"%s\n", flogmessage);
		}
		closelog();
	}

	if (set.verbose >= POLLER_VERBOSITY_MEDIUM) {
	    snprintf(flogmessage, LOGSIZE, "CACTID: %s", logmessage);
		printf(flogmessage);
	}
}

/******************************************************************************/
/*  ping_host() - check for availability using the desired user method.       */
/******************************************************************************/
int ping_host(host_t *host, ping_t *ping) {
	int ping_result;
	int snmp_result;

	/* initialize variables */
	strncpy(ping->ping_status, "down", sizeof(ping->ping_status));
	strncpy(ping->ping_response, "Ping not performed due to setting.", sizeof(ping->ping_response));
	strncpy(ping->snmp_status, "down", sizeof(ping->ping_status));
	strncpy(ping->snmp_response, "SNMP not performed due to setting or ping result", sizeof(ping->ping_response));

	/* snmp pinging has been selected at a minimum */
	ping_result = 0;
	snmp_result = 0;

	/* icmp/udp ping test */
	if ((set.availability_method == AVAIL_SNMP_AND_PING) || (set.availability_method == AVAIL_PING)) {
		if (!strstr(host->hostname, "localhost")) {
			if (set.ping_method == PING_ICMP) {
				ping_result = ping_icmp(host, ping);
			}else if (set.ping_method == PING_UDP) {
				ping_result = ping_udp(host, ping);
			}
		} else {
			strncpy(ping->ping_status, "0.000", sizeof(ping->ping_status));
			strncpy(ping->ping_response, "PING: Host does not require ping", sizeof(ping->ping_response));
			ping_result = HOST_UP;
		}
	}

	/* snmp test */
	if ((set.availability_method == AVAIL_SNMP) || ((set.availability_method == AVAIL_SNMP_AND_PING) && (ping_result == HOST_UP))) {
		snmp_result = ping_snmp(host, ping);
	}else {
		if ((set.availability_method == AVAIL_SNMP_AND_PING) && (ping_result != HOST_UP)) {
			snmp_result = HOST_DOWN;
		}
	}

	switch (set.availability_method) {
		case AVAIL_SNMP_AND_PING:
			if (snmp_result == HOST_UP)
				return HOST_UP;
			if (ping_result == HOST_DOWN)
				return HOST_DOWN;
			else
				return HOST_DOWN;
		case AVAIL_SNMP:
			if (snmp_result == HOST_UP)
				return HOST_UP;
			else
				return HOST_DOWN;
		case AVAIL_PING:
			if (ping_result == HOST_UP)
				return HOST_UP;
			else
				return HOST_DOWN;
		default:
			return HOST_DOWN;
	}
}

/******************************************************************************/
/*  ping_snmp() - perform an SNMP based ping of host.                         */
/******************************************************************************/
int ping_snmp(host_t *host, ping_t *ping) {
	struct timeval now;
	char *poll_result;
	double begin_time, end_time;

	if (strlen(host->snmp_community) != 0) {
		/* record start time */
		gettimeofday(&now, NULL);
		begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");

		/* record end time */
		gettimeofday(&now, NULL);
		end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	} else {
		strncpy(ping->snmp_status, "0.00", sizeof(ping->snmp_status));
		strncpy(ping->snmp_response, "Host does not require SNMP", sizeof(ping->snmp_response));
		poll_result = strdup("0.00");
	}

	if ((strlen(poll_result) == 0) || (strstr(poll_result,"ERROR"))) {
		strncpy(ping->snmp_response, "Host did not respond to SNMP", sizeof(ping->snmp_response));
		free(poll_result);
		return HOST_DOWN;
	} else {
		if (strlen(host->snmp_community) != 0) {
			strncpy(ping->snmp_response, "Host responded to SNMP", sizeof(ping->snmp_response));
			snprintf(ping->snmp_status, sizeof(ping->snmp_status), "%.5f",((end_time-begin_time)*1000));
		}

		free(poll_result);
		return HOST_UP;
	}
}

/******************************************************************************/
/*  init_socket() - allocate the ICMP socket.                                 */
/******************************************************************************/
int init_socket()
{
	int icmp_socket;

	/* error getting socket */
	if ((icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
	{
		cacti_log("ERROR: init_socket: cannot open the ICMP socket\n");
		exit(-1);
	}

	return(icmp_socket);
}

/******************************************************************************/
/*  ping_icmp() - perform an ICMP ping of a host.                             */
/******************************************************************************/
int ping_icmp(host_t *host, ping_t *ping) {
	extern int errno;
	int icmp_socket;

	double begin_time, end_time, total_time;
	struct timeval now;
	struct timeval timeout;

	struct sockaddr_in servername;
	char socket_reply[BUFSIZE];
	int retry_count;
	char request[BUFSIZE];
	char *cacti_msg = "cacti-monitoring-system";
	int request_len;
	int return_code;
	int packet_len;
	int fromlen;
	fd_set socket_fds;
	int numfds;

	static unsigned int seq = 0;
	struct icmphdr* icmp;
	size_t packet_size;
	unsigned char* packet;

	/* get ICMP socket and release setuid */
 	icmp_socket = init_socket();

	/* establish timeout value */
	timeout.tv_sec  = 0;
	timeout.tv_usec = set.ping_timeout * 1000;

	/* allocate the packet in memory */
	packet_len = ICMP_HDR_SIZE + strlen(cacti_msg);
	packet = malloc(packet_len);

	icmp = (struct icmphdr*)packet;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = getpid();
	icmp->un.echo.sequence = seq++;
	gettimeofday((struct timeval*)(icmp+1), NULL);
	icmp->checksum = 0;
	memcpy(packet+ICMP_HDR_SIZE, cacti_msg, strlen(cacti_msg));
	icmp->checksum = checksum(packet, packet_len);

	/* hostname must be nonblank */
	if (strlen(host->hostname) != 0) {
		/* initialize variables */
		strncpy(ping->ping_status,"down", sizeof(ping->ping_status));
		strncpy(ping->ping_response,"default", sizeof(ping->ping_response));

		/* set the socket timeout */
		setsockopt(icmp_socket,SOL_SOCKET,SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

		/* get address of hostname */
		init_sockaddr(&servername, host->hostname, 7);

		retry_count = 0;

		/* initialize file descriptor to review for input/output */
		FD_ZERO(&socket_fds);
		FD_SET(icmp_socket,&socket_fds);

		while (1) {
			if (retry_count >= set.ping_retries) {
				strncpy(ping->ping_response,"ICMP: Ping timed out", sizeof(ping->ping_response));
				strncpy(ping->ping_status,"down",sizeof(ping->ping_status));
				free(packet);
				close(icmp_socket);
				return HOST_DOWN;
			}

			/* record start time */
			gettimeofday(&now, NULL);
			begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			/* send packet to destination */
			return_code = sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &servername, sizeof(servername));

			/* wait for a response on the socket */
			select(FD_SETSIZE, &socket_fds, NULL, NULL, &timeout);

   			fromlen = sizeof(servername);

			/* check to see which socket talked */
			if (FD_ISSET(icmp_socket, &socket_fds)) {
				return_code = recvfrom(icmp_socket, socket_reply, BUFSIZE, 0, (struct sockaddr *) &servername, &fromlen);
			} else {
				return_code = -10;
			}

			/* record end time */
			gettimeofday(&now, NULL);
			end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			/* caculate total time */
			total_time = (end_time - begin_time) * 1000;

			if ((return_code >= 0) || ((return_code == -1) && ((errno == ECONNRESET) || (errno = ECONNREFUSED)))) {
				if (total_time < set.ping_timeout) {
					strncpy(ping->ping_response,"ICMP: Host is Alive",sizeof(ping->ping_response));
					sprintf(ping->ping_status,"%.5f",total_time);
					free(packet);
					close(icmp_socket);
					return HOST_UP;
				}
			}

			retry_count++;
			usleep(50);
		}
	} else {
		strncpy(ping->ping_response,"ICMP: Destination address not specified",sizeof(ping->ping_response));
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status));
		free(packet);
  		close(icmp_socket);
		return HOST_DOWN;
	}
}

/******************************************************************************/
/*  checksum() - calculate 16bit checksum of a packet buffer.                 */
/******************************************************************************/
unsigned short checksum(void* buf, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short answer;
	unsigned short* w = (unsigned short*)buf;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
		sum += *(unsigned char*)w;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;				/* truncate to 16 bits */
	return answer;
}

/******************************************************************************/
/*  ping_udp() - perform a UDP ping.  Function may vary from OS to OS.        */
/******************************************************************************/
int ping_udp(host_t *host, ping_t *ping) {
	extern int errno;
	double begin_time, end_time, total_time;
	struct timeval now;
	struct timeval timeout;
	int udp_socket;
	struct sockaddr_in servername;
	char socket_reply[BUFSIZE];
	char logmessage[LOGSIZE];
	int retry_count;
	char request[BUFSIZE];
	int request_len;
	int return_code;
	fd_set socket_fds;
	int numfds;

	/* establish timeout value */
	timeout.tv_sec  = 0;
	timeout.tv_usec = set.ping_timeout * 1000;

	/* hostname must be nonblank */
	if (strlen(host->hostname) != 0) {
		/* initialize variables */
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status));
		strncpy(ping->ping_response,"default",sizeof(ping->ping_response));

		/* initilize the socket */
		udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		/* set the socket timeout */
		setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

		/* get address of hostname */
		init_sockaddr(&servername, host->hostname, 33439);

		if (connect(udp_socket, (struct sockaddr *) &servername, sizeof(servername)) >= 0) {
				// do nothing
		} else {
			strcpy(ping->ping_status, "down");
			strcpy(ping->ping_response, "UDP: Cannot connect to host");
			return HOST_DOWN;
		}

		/* format packet */
		sprintf(request, "cacti-monitoring-system"); // the actual test data
		request_len = strlen(request);

		retry_count = 0;

		/* initialize file descriptor to review for input/output */
		FD_ZERO(&socket_fds);
		FD_SET(udp_socket,&socket_fds);

		numfds = udp_socket + 1;

		while (1) {
			if (retry_count >= set.ping_retries) {
				strncpy(ping->ping_response,"UDP: Ping timed out",sizeof(ping->ping_response));
				strncpy(ping->ping_status,"down",sizeof(ping->ping_status));
				close(udp_socket);
				return HOST_DOWN;
			}

			/* record start time */
			gettimeofday(&now, NULL);
			begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			/* send packet to destination */
			send(udp_socket, request, request_len, 0);

			/* wait for a response on the socket */
			select(numfds, &socket_fds, NULL, NULL, &timeout);

			/* check to see which socket talked */
			if (FD_ISSET(udp_socket, &socket_fds)) {
				return_code = read(udp_socket, socket_reply, BUFSIZE-1);
			} else {
				return_code = -10;
			}

			/* record end time */
			gettimeofday(&now, NULL);
			end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			/* caculate total time */
			total_time = end_time - begin_time;

			if (set.verbose == POLLER_VERBOSITY_DEBUG) {
				snprintf(logmessage, LOGSIZE, "DEBUG: The UDP Ping return_code was %i, errno was %i, total_time was %.4f\n",return_code,errno,(total_time*1000));
				cacti_log(logmessage);
			}

			if ((return_code >= 0) || ((return_code == -1) && ((errno == ECONNRESET) || (errno = ECONNREFUSED)))) {
				if ((total_time * 1000) <= set.ping_timeout) {
					strncpy(ping->ping_response,"UDP: Host is Alive",sizeof(ping->ping_response));
					sprintf(ping->ping_status,"%.5f",(total_time*1000));
					close(udp_socket);
					return HOST_UP;
				}
			}

			retry_count++;
		}
	} else {
		strncpy(ping->ping_response,"UDP: Destination address not specified",sizeof(ping->ping_response));
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status));
		return HOST_DOWN;
	}
}

/******************************************************************************/
/*  update_host_status - calculate the status of a host and update the host   */
/*                       table.                                               */
/******************************************************************************/
int update_host_status(int status, host_t *host, ping_t *ping, int availability_method) {
	int issue_log_message = FALSE;
	char logmessage[LOGSIZE];
	double ping_time;
 	double hundred_percent = 100.00;
	char current_date[40];
	time_t nowbin;
	const struct tm *nowstruct;
	extern config_t set;

	/* get date and format for mysql */
	if (time(&nowbin) == (time_t) - 1) {
		printf("ERROR: Could not get time of day from time()\n");
		exit(-1);
	}

	nowstruct = localtime(&nowbin);
	strftime(current_date, sizeof(current_date), "%Y-%m-%d %H:%M", nowstruct);

	/* host is down */
	if (status == HOST_DOWN) {
		/* update total polls, failed polls and availability */
		host->failed_polls = host->failed_polls + 1;
		host->total_polls = host->total_polls + 1;
		host->availability = hundred_percent * (host->total_polls - host->failed_polls) / host->total_polls;

		/*determine the error message to display */
		switch (availability_method) {
		case AVAIL_SNMP_AND_PING:
			if (strlen(host->snmp_community) == 0) {
				snprintf(host->status_last_error, sizeof(host->status_last_error), "%s", ping->ping_response);
			}else {
				snprintf(host->status_last_error, sizeof(host->status_last_error),"%s, %s",ping->snmp_response,ping->ping_response);
			}
			break;
		case AVAIL_SNMP:
			if (strlen(host->snmp_community) == 0) {
				snprintf(host->status_last_error, sizeof(host->status_last_error), "%s", "Device does not require SNMP");
			}else {
				snprintf(host->status_last_error, sizeof(host->status_last_error), "%s", ping->snmp_response);
			}
				break;
		default:
			snprintf(host->status_last_error, sizeof(host->status_last_error), "%s", ping->ping_response);
		}

		/* determine if to send an alert and update remainder of statistics */
		if (host->status == HOST_UP) {
			/* increment the event failure count */
			host->status_event_count = host->status_event_count + 1;

			/* if it's time to issue an error message, indicate so */
			if (host->status_event_count >= set.ping_failure_count) {
				/* host is now down, flag it that way */
				host->status = HOST_DOWN;

				issue_log_message = TRUE;

				/* update the failure date only if the failure count is 1 */
				if (set.ping_failure_count == 1) {
					snprintf(host->status_fail_date, sizeof(host->status_fail_date), "%s", current_date);
				}
			/* host is down, but not ready to issue log message */
			} else {
				/* host down for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_fail_date, sizeof(host->status_fail_date), "%s", current_date);
				}
			}
		/* host is recovering, put back in failed state */
		} else if (host->status == HOST_RECOVERING) {
			host->status_event_count = 1;
			host->status = HOST_DOWN;

		/* host was unknown and now is down */
		} else if (host->status == HOST_UNKNOWN) {
			host->status = HOST_DOWN;
			host->status_event_count = 0;
		} else {
			host->status_event_count = host->status_event_count + 1;
		}
	/* host is up!! */
	} else {
		/* update total polls and availability */
		host->total_polls = host->total_polls + 1;
		host->availability = hundred_percent * (host->total_polls - host->failed_polls) / host->total_polls;

		/* determine the ping statistic to set and do so */
		if (availability_method == AVAIL_SNMP_AND_PING) {
			if (strlen(host->snmp_community) == 0) {
				ping_time = atof(ping->ping_status);
			}else {
				/* calculate the average of the two times */
				ping_time = (atof(ping->snmp_status) + atof(ping->ping_status)) / 2;
			}
		}else if (availability_method == AVAIL_SNMP) {
			if (strlen(host->snmp_community) == 0) {
				ping_time = 0.000;
			}else {
				ping_time = atof(ping->snmp_status);
			}
		}else {
			ping_time = atof(ping->ping_status);
		}

		/* update times as required */
		host->cur_time = ping_time;

		/* maximum time */
		if (ping_time > host->max_time)
			host->max_time = ping_time;

		/* minimum time */
		if (ping_time < host->min_time)
			host->min_time = ping_time;

		/* average time */
		host->avg_time = (((host->total_polls-1-host->failed_polls)
			* host->avg_time) + ping_time) / (host->total_polls-host->failed_polls);

		/* the host was down, now it's recovering */
		if ((host->status == HOST_DOWN) || (host->status == HOST_RECOVERING )) {
			/* just up, change to recovering */
			if (host->status == HOST_DOWN) {
				host->status = HOST_RECOVERING;
				host->status_event_count = 1;
			} else {
				host->status_event_count = host->status_event_count + 1;
			}

			/* if it's time to issue a recovery message, indicate so */
			if (host->status_event_count >= set.ping_recovery_count) {
				/* host is up, flag it that way */
				host->status = HOST_UP;

				issue_log_message = TRUE;

				/* update the recovery date only if the recovery count is 1 */
				if (set.ping_recovery_count == 1) {
					snprintf(host->status_rec_date, sizeof(host->status_rec_date), "%s", current_date);
				}

				/* reset the event counter */
				host->status_event_count = 0;
			/* host is recovering, but not ready to issue log message */
			} else {
				/* host recovering for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_rec_date, sizeof(host->status_rec_date), "%s", current_date);
				}
			}
		} else {
		/* host was unknown and now is up */
			host->status = HOST_UP;
			host->status_event_count = 0;
		}
	}
	/* if the user wants a flood of information then flood them */
	if (set.verbose >= POLLER_VERBOSITY_HIGH) {
		if ((host->status == HOST_UP) || (host->status == HOST_RECOVERING)) {
			/* log ping result if we are to use a ping for reachability testing */
			if (availability_method == AVAIL_SNMP_AND_PING) {
				snprintf(logmessage, LOGSIZE, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
				snprintf(logmessage, LOGSIZE, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else if (availability_method == AVAIL_SNMP) {
				if (host->snmp_community == "") {
					snprintf(logmessage, LOGSIZE, "Host[%i] SNMP Result: Device does not require SNMP\n", host->id);
					cacti_log(logmessage);
				}else{
					snprintf(logmessage, LOGSIZE, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
					cacti_log(logmessage);
				}
			} else {
				snprintf(logmessage, LOGSIZE, "Host[%i] PING: Result %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
			}
		} else {
			if (availability_method == AVAIL_SNMP_AND_PING) {
				snprintf(logmessage, LOGSIZE, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
				snprintf(logmessage, LOGSIZE, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else if (availability_method == AVAIL_SNMP) {
				snprintf(logmessage, LOGSIZE, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else {
				snprintf(logmessage, LOGSIZE, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
			}
		}
	}

	/* if there is supposed to be an event generated, do it */
	if (issue_log_message) {
		if (host->status == HOST_DOWN) {
			snprintf(logmessage, LOGSIZE, "Host[%i] ERROR: HOST EVENT: Host is DOWN Message: %s\n", host->id, host->status_last_error);
			cacti_log(logmessage);
		} else {
			snprintf(logmessage, LOGSIZE, "Host[%i] NOTICE: HOST EVENT: Host Returned from DOWN State\n", host->id);
			cacti_log(logmessage);
		}
	}
}

/******************************************************************************/
/*  file_exists - check for the existance of a file.                          */
/******************************************************************************/
int file_exists(char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return 0;
	}else{
		return 1;
	}
}

/******************************************************************************/
/*  is_numeric() - check to see if a string is long or double.                */
/******************************************************************************/
int is_numeric(char *string)
{
	extern int errno;
	long local_lval;
	double local_dval;
	char *end_ptr_long, *end_ptr_double;
	int conv_base=10;
	int length;

	length = strlen(string);

	if (!length) {
		return 0;
	}

 	/* check for an integer */
	errno = 0;
	local_lval = strtol(string, &end_ptr_long, conv_base);
	if (errno!=ERANGE) {
		if (end_ptr_long == string + length) { /* integer string */
			return 1;
		} else if (end_ptr_long == string &&
				*end_ptr_long != '\0') { /* ignore partial string matches */
			return 0;
		}
	} else {
		end_ptr_long=NULL;
	}

	errno=0;
	local_dval = strtod(string, &end_ptr_double);
	if (errno != ERANGE) {
		if (end_ptr_double == string + length) { /* floating point string */
			return 1;
		}
	} else {
		end_ptr_double=NULL;
	}

	if (!errno) {
		return 1;
	} else {
		return 0;
 	}
}

/******************************************************************************/
/*  string_to_argv() - convert a string to an argc/argv combination           */
/******************************************************************************/
char **string_to_argv(char *argstring, int *argc){
	char *p, **argv;
	char *last;
	int i = 0;

	for((*argc)=1, i=0; i<strlen(argstring); i++) if(argstring[i]==' ') (*argc)++;

	argv = (char **)malloc((*argc) * sizeof(char**));
	for((p = strtok_r(argstring, " ", &last)), i=0; p; (p = strtok_r(NULL, " ", &last)), i++) argv[i] = p;
	argv[i] = NULL;

	return argv;
}

/******************************************************************************/
/*  clean_string() - change backslashes to forward slashes for system calls   */
/******************************************************************************/
char *clean_string(char *string) {
	char *posptr;

	posptr = strchr(string,'\\');

	while(posptr != NULL)
	{
		*posptr = '/';
		posptr = strchr(string,'\\');
	}

	return(string);
}

/******************************************************************************/
/*  add_win32_slashes() - add slashes to Window'z arguments for scripts.      */
/******************************************************************************/
char *add_win32_slashes(char *string, int arguments_2_strip) {
	int length;
	int space_count;
	int position;
	int new_position;
	
	char *return_str = (char *) malloc(BUFSIZE);

	length = strlen(string);
	space_count = 0;
	position = 0;
	new_position = position;
	
	/* simply return on blank string */
	if (!length) {
		return string;
	}

	while (position < length) {
		/* backslash detected, change to forward slash */
		if (string[position] == '\\') {	
			/* only add slashes for first x arguments */
			if (space_count < arguments_2_strip) {
				return_str[new_position] = '/';
			} else {
				return_str[new_position] = string[position];
			}
		/* end of argument detected */
		} else if (string[position] == ' ') {
			return_str[new_position] = ' ';
			space_count++;
		/* normal character detected */
		} else {
			return_str[new_position] = string[position];
		}
		new_position++;
		position++;
	}
	return_str[new_position] = '\0';

	return(return_str);
}

/******************************************************************************/
/*  strip_quotes() - remove beginning and ending quotes from a string         */
/******************************************************************************/
char *strip_quotes(char *string) {
	int length;
	char *posptr, *startptr;
	char type;

	length = strlen(string);

	/* simply return on blank string */
	if (!length) {
		return string;
	}

	/* set starting postion of string */
	startptr = string;

	/* find first quote in the string, determine type */
	if ((posptr = strchr(string, '"')) != NULL) {
		type = '"';
	} else if ((posptr = strchr(string, '\'')) != NULL) {
		type = '\'';
	} else {
		return string;
	}

	posptr = strchr(string,type);

	/* if the first character is a string, then we are ok */
	if (startptr == posptr) {
		/* remove leading quote */
		memmove(startptr, posptr+1, strlen(string) - 1);
		string[length] = '\0';

		/* remove trailing quote */
		posptr = strchr(string,type);
		if (posptr != NULL) {
			*posptr = '\0';
		}
 	}

	return string;
}

/******************************************************************************/
/*  strip_string_crlf() - remove control conditions from a string             */
/******************************************************************************/
char *strip_string_crlf(char *string) {
	char *posptr;

	posptr = strchr(string,'\n');

	while(posptr != NULL)
	{
		*posptr = '\0';
		posptr = strchr(string,'\n');
	}

	posptr = strchr(string,'\r');

	while(posptr != NULL)
	{
		*posptr = '\0';
		posptr = strchr(string,'\r');
	}

	return(string);
}

/******************************************************************************/
/*  init_sockaddr - convert host name to internet address                     */
/******************************************************************************/
void init_sockaddr (struct sockaddr_in *name, const char *hostname, unsigned short int port) {
	struct hostent *hostinfo;
	char logmessage[255];

	name->sin_family = AF_INET;
	name->sin_port = htons (port);
	hostinfo = gethostbyname (hostname);
	if (hostinfo == NULL) {
		snprintf(logmessage, LOGSIZE, "WARNING: Unknown host %s\n", hostname);
		cacti_log(logmessage);
	}
	name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}

