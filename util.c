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

//#include <netinet/in.h>
//#include <netinet/ip.h>
//#include <ctype.h>
//#include <arpa/inet.h>
//#include <stdlib.h>
//#include <stdio.h>
//#include <unistd.h>
//#include <sys/types.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
//#include <sys/time.h>
//#include <string.h>

int read_config_options(config_t *set) {
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL_ROW mysql_row;
	int num_rows;

	db_connect(set->dbdb, &mysql);

	/* determine log file, syslog or both, default is 1 or log file only */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_destination'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set->log_destination = atoi(mysql_row[0]);
	}else{
		set->log_destination = 1;
	}

	/* determine script server path operation */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_webroot'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		strncpy(set->path_php_server,mysql_row[0], sizeof(set->path_php_server));
		strncat(set->path_php_server,"/script_server.php", sizeof(set->path_php_server));
	}

	/* determine logfile path */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_cactilog'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		strncpy(set->path_logfile,mysql_row[0], sizeof(set->path_logfile));
	}

	/* set availability_method */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='availability_method'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->availability_method = atoi(mysql_row[0]);
	}

	/* set ping_recovery_count */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_recovery_count'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_recovery_count = atoi(mysql_row[0]);
	}

	/* set ping_failure_count */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_failure_count'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_failure_count = atoi(mysql_row[0]);
	}

	/* set ping_method */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_method'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_method = atoi(mysql_row[0]);
	}

	/* set ping_retries */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_retries'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_retries = atoi(mysql_row[0]);
	}

	/* set ping_timeout */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='ping_timeout'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		set->ping_timeout = atoi(mysql_row[0]);
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

	/* get logging level from database - overrides cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='log_verbosity'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);

		if (atoi(mysql_row[0])) {
			set->verbose = atoi(mysql_row[0]);
		}
	}

	/* get Cacti defined max threads override cactid.conf */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='max_threads'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		set->threads = atoi(mysql_row[0]);
	}

	/* get PHP Path Information for Scripting */
	result = db_query(&mysql, "SELECT value FROM settings WHERE name='path_php_binary'");
	num_rows = (int)mysql_num_rows(result);

	if (num_rows > 0) {
		mysql_row = mysql_fetch_row(result);
		strncpy(set->path_php,mysql_row[0], sizeof(set->path_php));
	}

	mysql_free_result(result);
	mysql_close(&mysql);
}

/* read configuration file to establish local environment */
int read_cactid_config(char *file, config_t *set) {
	FILE *fp;
	char buff[BUFSIZE];
	char p1[BUFSIZE];
	char p2[BUFSIZE];

	if ((fp = fopen(file, "rb")) == NULL) {
		printf("ERROR: Could not open config file.\n");
		return (-1);
	}else{
		if (set->verbose >= HIGH) {
			printf("CACTID: Using cactid config file [%s].\n", file);
		}

		while(!feof(fp)) {
			fgets(buff, BUFSIZE, fp);
			if (!feof(fp) && *buff != '#' && *buff != ' ' && *buff != '\n') {
				sscanf(buff, "%20s %255s", p1, p2);

				if (!strcasecmp(p1, "Interval")) set->interval = atoi(p2);
				else if (!strcasecmp(p1, "SNMP_Ver")) set->snmp_ver = atoi(p2);
				else if (!strcasecmp(p1, "Threads")) set->threads = atoi(p2);
				else if (!strcasecmp(p1, "LogFile")) strncpy(set->path_logfile, p2, sizeof(set->path_logfile));
				else if (!strcasecmp(p1, "DB_Host")) strncpy(set->dbhost, p2, sizeof(set->dbhost));
				else if (!strcasecmp(p1, "DB_Database")) strncpy(set->dbdb, p2, sizeof(set->dbdb));
				else if (!strcasecmp(p1, "DB_User")) strncpy(set->dbuser, p2, sizeof(set->dbuser));
				else if (!strcasecmp(p1, "DB_Pass")) strncpy(set->dbpass, p2, sizeof(set->dbpass));
				else {
					printf("ERROR: Unrecongized directive: %s=%s in %s\n",
					p1, p2, file);
					exit(-1);
				}
			}
		}

		if (set->snmp_ver != 1 && set->snmp_ver != 2) {
			printf("ERROR: Unsupported SNMP version: %d.\n", set->snmp_ver);
			exit(-1);
		}

		if (set->threads < 1 || set->threads > MAX_THREADS) {
			printf("ERROR: Invalid Number of Threads: %d (max=%d).\n", set->threads, MAX_THREADS);
			exit(-1);
		}

		return (0);
	}
}

/* populate master configuration defaults */
void config_defaults(config_t * set) {
	set->interval = DEFAULT_INTERVAL;
	set->snmp_ver = DEFAULT_SNMP_VER;
	set->threads = DEFAULT_THREADS;

	strncpy(set->dbhost, DEFAULT_DB_HOST, sizeof(set->dbhost));
	strncpy(set->dbdb, DEFAULT_DB_DB, sizeof(set->dbhost));
	strncpy(set->dbuser, DEFAULT_DB_USER, sizeof(set->dbhost));
	strncpy(set->dbpass, DEFAULT_DB_PASS, sizeof(set->dbhost));

	strncpy(config_paths[0], CONFIG_PATH_1, sizeof(config_paths[0]));
	strncpy(config_paths[1], CONFIG_PATH_2, sizeof(config_paths[1]));
	strncpy(config_paths[2], CONFIG_PATH_3, sizeof(config_paths[2]));
	strncpy(config_paths[3], CONFIG_PATH_4, sizeof(config_paths[3]));
	strncpy(config_paths[4], CONFIG_PATH_5, sizeof(config_paths[4]));
	strncpy(config_paths[5], CONFIG_PATH_6, sizeof(config_paths[5]));

	return;
}

/* cacti log file handler */
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
				printf("ERROR: Could not open Logfile will not be logging.\n");
				break;
			}
		}
	}

	/* get time for logfile */
	if (time(&nowbin) == (time_t) - 1)
		printf("ERROR: Could not get time of day from time()\n");

	nowstruct = localtime(&nowbin);

	if (strftime(flogmessage, 50, "%m/%d/%Y %I:%M %p - ", nowstruct) == (size_t) 0)
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

	if (set.verbose >= MEDIUM) {
		printf(flogmessage);
	}
}

/* ping host */
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

/* perform an SNMP based ping */
int ping_snmp(host_t *host, ping_t *ping) {
	struct timeval now;
	char *poll_result;
	double begin_time, end_time;

	if (strlen(host->snmp_community) != 0) {
		/* record start time */
		gettimeofday(&now, NULL);
		begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.1.0");

		/* record end time */
		gettimeofday(&now, NULL);
		end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	} else {
		strncpy(ping->snmp_status, "0.00", sizeof(ping->snmp_status));
		strncpy(ping->snmp_response, "Host does not require SNMP", sizeof(ping->snmp_response));
		poll_result = "0.00";
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

/* allocate the ICMP socket and release su */
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

/* perform an ICMP/ECHO based ping */
int ping_icmp(host_t *host, ping_t *ping) {
	extern int errno;
	int icmp_socket;

	double begin_time, end_time, total_time;
	struct timeval now;
	struct timeval timeout;

	struct sockaddr_in servername;
	char socket_reply[BUFSIZE];
	int retry_count;
	char request[256];
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
		strcpy(ping->ping_status,"down");
		strcpy(ping->ping_response,"default");

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
				strcpy(ping->ping_response,"ICMP: Ping timed out");
				strcpy(ping->ping_status,"down");
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
					strcpy(ping->ping_response,"ICMP: Host is Alive");
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
		strcpy(ping->ping_response,"ICMP: Destination address not specified");
		strcpy(ping->ping_status,"down");
		free(packet);
  		close(icmp_socket);
		return HOST_DOWN;
	}
}

/* calculate a checksum for the IP packet */
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

/* perform a udp based ping */
int ping_udp(host_t *host, ping_t *ping) {
	extern int errno;
	double begin_time, end_time, total_time;
	struct timeval now;
	struct timeval timeout;
	int udp_socket;
	struct sockaddr_in servername;
	char socket_reply[256];
	int retry_count;
	char request[256];
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
		strcpy(ping->ping_status,"down");
		strcpy(ping->ping_response,"default");

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
				strcpy(ping->ping_response,"UDP: Ping timed out");
				strcpy(ping->ping_status,"down");
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
				return_code = read(udp_socket, socket_reply, 256);
			} else {
				return_code = -10;
			}

			/* record end time */
			gettimeofday(&now, NULL);
			end_time = (double) now.tv_usec / 1000000 + now.tv_sec;

			/* caculate total time */
			total_time = end_time - begin_time;

			if (set.verbose == POLLER_VERBOSITY_DEBUG) {
				printf("The UDP Ping return_code was %i\n",return_code);
				printf("The UDP Ping errno was %i\n",errno);
				printf("The UDP Ping total_time was %.4f milliseconds\n",(total_time*1000));
			}

			if ((return_code >= 0) || ((return_code == -1) && ((errno == ECONNRESET) || (errno = ECONNREFUSED)))) {
				if ((total_time * 1000) <= set.ping_timeout) {
					strcpy(ping->ping_response,"UDP: Host is Alive");
					sprintf(ping->ping_status,"%.5f",(total_time*1000));
					close(udp_socket);
					return HOST_UP;
				}
			}

			retry_count++;
		}
	} else {
		strcpy(ping->ping_response,"UDP: Destination address not specified");
		strcpy(ping->ping_status,"down");
		return HOST_DOWN;
	}
}

int update_host_status(int status, host_t *host, ping_t *ping, int availability_method) {
	int issue_log_message = FALSE;
	char logmessage[256];
	double ping_time;
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
	strftime(current_date, sizeof(current_date), "%Y-%m-%d %I:%M", nowstruct);

	/* host is down */
	if (status == HOST_DOWN) {
		/* update total polls, failed polls and availability */
		host->failed_polls = host->failed_polls + 1;
		host->total_polls = host->total_polls + 1;
		host->availability = 100 * (host->total_polls - host->failed_polls) / host->total_polls;

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
		host->availability = 100 * (host->total_polls - host->failed_polls) / host->total_polls;

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

/* check for a file name */
int file_exists(char *filename) {
	struct stat file_stat;

	if (stat(filename, &file_stat)) {
		return 0;
	}else{
		return 1;
	}
}

/* retreive timestamp for logging */
void timestamp(char *str) {
	struct timeval now;
	struct tm *t;

	gettimeofday(&now, NULL);
	t = localtime(&now.tv_sec);
	printf("[%02d/%02d %02d:%02d:%02d %s]\n", t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, str);

	return;
}

/* verify is a number for error processing */
int is_number(char *string) {
	int i;

	for(i=0; i<strlen(string); i++) {
		if(!isdigit(string[i]) && !(i==strlen(string)-1 && isspace(string[i]))) return(0);
	}

	return(1);
}

/* convert a string to an argc/argv combination */
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

/* change backslashes to forward slashes for system calls */
char *clean_string( char *string_to_clean ) {
	char *posptr;

	posptr = strchr(string_to_clean,'\\');

	while(posptr != NULL)
	{
		*posptr = '/';
		posptr = strchr(string_to_clean,'\\');
	}

	return(string_to_clean);
}

void init_sockaddr (struct sockaddr_in *name, const char *hostname, unsigned short int port) {
	struct hostent *hostinfo;
	char logmessage[255];

	name->sin_family = AF_INET;
	name->sin_port = htons (port);
	hostinfo = gethostbyname (hostname);
	if (hostinfo == NULL) {
		sprintf(logmessage, "WARNING: Unknown host %s.\n", hostname);
		cacti_log(logmessage);
	}
	name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
}

