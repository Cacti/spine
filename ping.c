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
#include "ping.h"

/******************************************************************************/
/*  ping_host() - check for availability using the desired user method.       */
/******************************************************************************/
int ping_host(host_t *host, ping_t *ping) {
	int ping_result;
	int snmp_result;

	/* initialize variables */
	strncpy(ping->ping_status, "down", sizeof(ping->ping_status)-1);
	strncpy(ping->ping_response, "Ping not performed due to setting.", sizeof(ping->ping_response)-1);
	strncpy(ping->snmp_status, "down", sizeof(ping->ping_status)-1);
	strncpy(ping->snmp_response, "SNMP not performed due to setting or ping result", sizeof(ping->ping_response)-1);

	/* snmp pinging has been selected at a minimum */
	ping_result = 0;
	snmp_result = 0;

	/* test for asroot */
	#ifndef __CYGWIN__
	if (geteuid() != 0) {
		set.ping_method = PING_UDP;
		printf("CACTID: WARNING: Falling back to UDP Ping due to not running asroot.  Please use \"chmod xxx0 /usr/bin/cactid\" to resolve.\n");
		if (set.verbose == POLLER_VERBOSITY_DEBUG) {
			cacti_log("WARNING: Falling back to UDP Ping due to not running asroot.  Please use \"chmod xxx0 /usr/bin/cactid\" to resolve.\n");
		}
	}
	#endif

	/* icmp/udp ping test */
	if ((set.availability_method == AVAIL_SNMP_AND_PING) || (set.availability_method == AVAIL_PING)) {
		if (!strstr(host->hostname, "localhost")) {
			if (set.ping_method == PING_ICMP) {
				ping_result = ping_icmp(host, ping);
				setuid(getuid());
			}else if (set.ping_method == PING_UDP) {
				ping_result = ping_udp(host, ping);
			}
		} else {
			strncpy(ping->ping_status, "0.000", sizeof(ping->ping_status)-1);
			strncpy(ping->ping_response, "PING: Host does not require ping", sizeof(ping->ping_response)-1);
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
	double begin_time = 0;
	double end_time = 0;

	if (strlen(host->snmp_community) != 0) {
		/* record start time */
		gettimeofday(&now, NULL);
		begin_time = (double) now.tv_usec / 1000000 + now.tv_sec;

		poll_result = snmp_get(host, ".1.3.6.1.2.1.1.3.0");

		/* record end time */
		gettimeofday(&now, NULL);
		end_time = (double) now.tv_usec / 1000000 + now.tv_sec;
	} else {
		strncpy(ping->snmp_status, "0.00", sizeof(ping->snmp_status)-1);
		strncpy(ping->snmp_response, "Host does not require SNMP", sizeof(ping->snmp_response)-1);
		poll_result = strdup("0.00");
	}

	if ((strlen(poll_result) == 0) || (strstr(poll_result,"ERROR"))) {
		strncpy(ping->snmp_response, "Host did not respond to SNMP", sizeof(ping->snmp_response)-1);
		free(poll_result);
		return HOST_DOWN;
	} else {
		if (strlen(host->snmp_community) != 0) {
			strncpy(ping->snmp_response, "Host responded to SNMP", sizeof(ping->snmp_response)-1);
			snprintf(ping->snmp_status, sizeof(ping->snmp_status)-1, "%.5f",((end_time-begin_time)*1000));
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
		exit_cactid();
	}

	return(icmp_socket);
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
		snprintf(logmessage, LOGSIZE-1, "WARNING: Unknown host %s\n", hostname);
		cacti_log(logmessage);
	}
	name->sin_addr = *(struct in_addr *) hostinfo->h_addr;
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
	int packet_len;
	int fromlen;
	int return_code;
	fd_set socket_fds;

	static unsigned int seq = 0;
	struct icmphdr* icmp;
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
	icmp->checksum = get_checksum(packet, packet_len);

	/* hostname must be nonblank */
	if (strlen(host->hostname) != 0) {
		/* initialize variables */
		strncpy(ping->ping_status,"down", sizeof(ping->ping_status)-1);
		strncpy(ping->ping_response,"default", sizeof(ping->ping_response)-1);

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
				strncpy(ping->ping_response,"ICMP: Ping timed out", sizeof(ping->ping_response)-1);
				strncpy(ping->ping_status,"down",sizeof(ping->ping_status)-1);
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

			if ((return_code >= 0) || ((return_code == -1) && ((errno == ECONNRESET) || (errno == ECONNREFUSED)))) {
				if (total_time < set.ping_timeout) {
					strncpy(ping->ping_response,"ICMP: Host is Alive",sizeof(ping->ping_response)-1);
					snprintf(ping->ping_status,sizeof(ping->ping_status)-1,"%.5f",total_time);
					free(packet);
					close(icmp_socket);
					return HOST_UP;
				}
			}

			retry_count++;
			usleep(50);
		}
	} else {
		strncpy(ping->ping_response,"ICMP: Destination address not specified",sizeof(ping->ping_response)-1);
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status)-1);
		free(packet);
  		close(icmp_socket);
		return HOST_DOWN;
	}
}

/******************************************************************************/
/*  get_checksum() - calculate 16bit checksum of a packet buffer.             */
/******************************************************************************/
unsigned short get_checksum(void* buf, int len)
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
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status)-1);
		strncpy(ping->ping_response,"default",sizeof(ping->ping_response)-1);

		/* initilize the socket */
		udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

		/* set the socket timeout */
		setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

		/* get address of hostname */
		init_sockaddr(&servername, host->hostname, 33439);

		if (connect(udp_socket, (struct sockaddr *) &servername, sizeof(servername)) >= 0) {
				// do nothing
		} else {
			strncpy(ping->ping_status, "down", sizeof(ping->ping_status)-1);
			strncpy(ping->ping_response, "UDP: Cannot connect to host", sizeof(ping->ping_response)-1);
			return HOST_DOWN;
		}

		/* format packet */
		snprintf(request, sizeof(request)-1, "cacti-monitoring-system"); // the actual test data
		request_len = strlen(request);

		retry_count = 0;

		/* initialize file descriptor to review for input/output */
		FD_ZERO(&socket_fds);
		FD_SET(udp_socket,&socket_fds);

		numfds = udp_socket + 1;

		while (1) {
			if (retry_count >= set.ping_retries) {
				strncpy(ping->ping_response,"UDP: Ping timed out",sizeof(ping->ping_response)-1);
				strncpy(ping->ping_status,"down",sizeof(ping->ping_status)-1);
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
				snprintf(logmessage, LOGSIZE-1, "DEBUG: The UDP Ping return_code was %i, errno was %i, total_time was %.4f\n",return_code,errno,(total_time*1000));
				cacti_log(logmessage);
			}

			if ((return_code >= 0) || ((return_code == -1) && ((errno == ECONNRESET) || (errno == ECONNREFUSED)))) {
				if ((total_time * 1000) <= set.ping_timeout) {
					strncpy(ping->ping_response,"UDP: Host is Alive",sizeof(ping->ping_response)-1);
					snprintf(ping->ping_status, sizeof(ping->ping_status)-1, "%.5f",(total_time*1000));
					close(udp_socket);
					return HOST_UP;
				}
			}

			retry_count++;
		}
	} else {
		strncpy(ping->ping_response,"UDP: Destination address not specified",sizeof(ping->ping_response)-1);
		strncpy(ping->ping_status,"down",sizeof(ping->ping_status)-1);
		return HOST_DOWN;
	}
}

/******************************************************************************/
/*  update_host_status - calculate the status of a host and update the host   */
/*                       table.                                               */
/******************************************************************************/
void update_host_status(int status, host_t *host, ping_t *ping, int availability_method) {
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
		exit_cactid();
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
				snprintf(host->status_last_error, sizeof(host->status_last_error)-1, "%s", ping->ping_response);
			}else {
				snprintf(host->status_last_error, sizeof(host->status_last_error)-1,"%s, %s",ping->snmp_response,ping->ping_response);
			}
			break;
		case AVAIL_SNMP:
			if (strlen(host->snmp_community) == 0) {
				snprintf(host->status_last_error, sizeof(host->status_last_error)-1, "%s", "Device does not require SNMP");
			}else {
				snprintf(host->status_last_error, sizeof(host->status_last_error)-1, "%s", ping->snmp_response);
			}
				break;
		default:
			snprintf(host->status_last_error, sizeof(host->status_last_error)-1, "%s", ping->ping_response);
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
					snprintf(host->status_fail_date, sizeof(host->status_fail_date)-1, "%s", current_date);
				}
			/* host is down, but not ready to issue log message */
			} else {
				/* host down for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_fail_date, sizeof(host->status_fail_date)-1, "%s", current_date);
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
					snprintf(host->status_rec_date, sizeof(host->status_rec_date)-1, "%s", current_date);
				}

				/* reset the event counter */
				host->status_event_count = 0;
			/* host is recovering, but not ready to issue log message */
			} else {
				/* host recovering for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_rec_date, sizeof(host->status_rec_date)-1, "%s", current_date);
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
				snprintf(logmessage, LOGSIZE-1, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
				snprintf(logmessage, LOGSIZE-1, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else if (availability_method == AVAIL_SNMP) {
				if (host->snmp_community == "") {
					snprintf(logmessage, LOGSIZE-1, "Host[%i] SNMP Result: Device does not require SNMP\n", host->id);
					cacti_log(logmessage);
				}else{
					snprintf(logmessage, LOGSIZE-1, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
					cacti_log(logmessage);
				}
			} else {
				snprintf(logmessage, LOGSIZE-1, "Host[%i] PING: Result %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
			}
		} else {
			if (availability_method == AVAIL_SNMP_AND_PING) {
				snprintf(logmessage, LOGSIZE-1, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
				snprintf(logmessage, LOGSIZE-1, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else if (availability_method == AVAIL_SNMP) {
				snprintf(logmessage, LOGSIZE-1, "Host[%i] SNMP Result: %s\n", host->id, ping->snmp_response);
				cacti_log(logmessage);
			} else {
				snprintf(logmessage, LOGSIZE-1, "Host[%i] PING Result: %s\n", host->id, ping->ping_response);
				cacti_log(logmessage);
			}
		}
	}

	/* if there is supposed to be an event generated, do it */
	if (issue_log_message) {
		if (host->status == HOST_DOWN) {
			snprintf(logmessage, LOGSIZE-1, "Host[%i] ERROR: HOST EVENT: Host is DOWN Message: %s\n", host->id, host->status_last_error);
			cacti_log(logmessage);
		} else {
			snprintf(logmessage, LOGSIZE-1, "Host[%i] NOTICE: HOST EVENT: Host Returned from DOWN State\n", host->id);
			cacti_log(logmessage);
		}
	}
}

