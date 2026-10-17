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

#include "internal/common.h"
#include "app/spine.h"
#include "ping_internal.h"
#include <fcntl.h>

#ifdef __CYGWIN__
/*! \fn static void icmp_discard_reply(int icmp_socket, char *buffer)
 *  \brief consumes a datagram that ping_icmp() has only peeked at
 *
 *  Cygwin cannot use MSG_WAITALL on a raw socket, so ping_icmp() reads with
 *  MSG_PEEK.  A peeked datagram stays queued, so a reply we decline has to be
 *  drained here.  Otherwise the next pass reads the same bytes again and the
 *  loop spins until the device timeout expires.
 */
static void icmp_discard_reply(int icmp_socket, char *buffer) {
	while (recvfrom(icmp_socket, buffer, BUFSIZE, 0, NULL, NULL) < 0 && errno == EINTR) {
		/* interrupted before the datagram was removed, try again */
	}
}

#define ICMP_DISCARD_PEEKED(sock, buf) icmp_discard_reply((sock), (buf))
#else
#define ICMP_DISCARD_PEEKED(sock, buf) ((void) 0)
#endif


/*! \fn int ping_icmp(host_t *host, ping_t *ping)
 *  \brief ping a host using an ICMP packet
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using ICMP.  The ICMP packet contains a marker
 *  to the "Cacti" application so that firewall's can be configured to allow.
 *  It will modify the ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
int ping_icmp(const host_t *host, ping_t *ping) {
	int icmp_socket = -1;
	int icmp_dgram;
	int rc = HOST_DOWN;
	int socket_errno = 0;
	int icmp_use_shared = FALSE;
	icmp_waiter_t waiter;
	int waiting = FALSE;

	double begin_time, deadline, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;

	struct sockaddr_in recvname;
	struct sockaddr_in fromname;
	char socket_reply[BUFSIZE];
	int retry_count;
	const char *cacti_msg = "cacti-monitoring-system\0";
	int packet_len;
	socklen_t fromlen;
	ssize_t return_code;
	fd_set socket_fds;

	static unsigned int seq = 0;
	struct icmp *icmp;
	unsigned char *packet = NULL;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering ICMP Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("Device[%i] DEBUG: Entering ICMP Ping", host->id));
	}

	/* Linux hands out SOCK_DGRAM ICMP sockets to the groups listed in
	 * net.ipv4.ping_group_range, so try that before asking for root.  When
	 * the sysctl excludes us the call fails and the raw path below runs
	 * unchanged.  A datagram reply arrives with the IPv4 header already
	 * stripped, which the receive path has to account for. */
	icmp_dgram = FALSE;
	icmp_socket = icmp_open_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

	if (icmp_socket != -1) {
		icmp_dgram = TRUE;
	} else if (icmp_shared.fd != -1) {
		icmp_socket = icmp_shared.fd;
		icmp_use_shared = TRUE;
	}

	/* Otherwise open a raw socket of our own, which needs CAP_NET_RAW or a
	 * real root user.  Spine never regains root to do it: a setuid install
	 * without capabilities uses the shared socket above instead. */
	retry_count = 0;
	while (icmp_socket == -1) {
		icmp_socket = icmp_open_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
		socket_errno = errno;

		if (icmp_socket != -1) {
			break;
		}

		SPINE_LOG_MEDIUM(("WARNING: Device[%i] raw ICMP socket creation failed: %s",
			host->id, strerror(socket_errno)));

		retry_count++;

		if (retry_count > 4) {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Ping unable to create ICMP Socket");
			snprintf(ping->ping_status, 50, "down");

			rc = HOST_DOWN;
			goto cleanup;
		}

		usleep(500000);
	}

	/* convert the host timeout to a double precision number in seconds */
	host_timeout = host->availability.timeout;

	/* allocate the packet in memory */
	packet_len = ICMP_HDR_SIZE + strlen(cacti_msg);

	if (!(packet = malloc(packet_len))) {
		die("ERROR: Fatal malloc error: ping.c ping_icmp!");
	}
	memset(packet, 0, packet_len);

	/* set the memory of the ping address */
	memset(&fromname, 0, sizeof(fromname));
	memset(&recvname, 0, sizeof(recvname));

	icmp = (struct icmp *) packet;

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = getpid() & 0xFFFF;

	/* lock set/get the sequence and unlock */
	thread_mutex_lock(LOCK_GHBN);
	icmp->icmp_seq = seq++;
	thread_mutex_unlock(LOCK_GHBN);

	icmp->icmp_cksum = 0;
	memcpy(packet + ICMP_HDR_SIZE, cacti_msg, strlen(cacti_msg));
	icmp->icmp_cksum = get_checksum(packet, packet_len);

	/* hostname must be nonblank */
	if ((strlen(host->hostname) != 0) && (icmp_socket != -1)) {
		/* initialize variables */
		snprintf(ping->ping_status, 50, "down");
		snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

		/* get address of hostname */
		if (init_sockaddr(&fromname, host->hostname, 7)) {
			retry_count = 0;
			total_time = 0;

			if (icmp_use_shared) {
				memset(&waiter, 0, sizeof(waiter));
				waiter.shared = &icmp_shared;
				waiter.family = AF_INET;
				waiter.id = (uint16_t) (getpid() & 0xFFFF);
				waiter.seq = icmp->icmp_seq;
				waiter.peer = fromname.sin_addr;
				icmp_shared_register(&waiter);
				waiting = TRUE;
			}

			while (1) {
				if (retry_count > host->availability.retries) {
					snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Ping timed out");
					snprintf(ping->ping_status, 50, "down");
					rc = HOST_DOWN;
					goto cleanup;
				}

				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] DEBUG: Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, icmp->icmp_seq, retry_count, host->availability.retries));
				} else {
					SPINE_LOG_DEBUG(("Device[%i] DEBUG: Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, icmp->icmp_seq, retry_count, host->availability.retries));
				}

				if (waiting) {
					/* Socket options would change every other thread's socket too. */
					double attempt_begin = get_time_as_double();

					if (sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, sizeof(fromname)) >= 0 &&
						icmp_shared_await(&waiter, attempt_begin + host_timeout / one_thousand)) {
						total_time = (get_time_as_double() - attempt_begin) * one_thousand;

						if (is_debug_device(host->id)) {
							SPINE_LOG(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
						} else {
							SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
						}
						snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Device is Alive");
						snprintf(ping->ping_status, 50, "%.5f", total_time);
						rc = HOST_UP;
						goto cleanup;
					}

					retry_count++;
					continue;
				}

				begin_time = spine_monotonic_time();
				deadline = begin_time + host_timeout / one_thousand;
				ping_wait_left(deadline, &timeout);

				/* set the socket send and receive timeout */
				setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout));
				setsockopt(icmp_socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout));

				/* send packet to destination */
				return_code = sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, sizeof(fromname));

				fromlen = sizeof(fromname);

			/* wait for a response on the socket */
			/* reinitialize fd_set -- select(2) clears bits in place on return */
			keep_listening:
				FD_ZERO(&socket_fds);
				if (icmp_socket >= FD_SETSIZE) {
					SPINE_LOG(("ERROR: Device[%i] ICMP socket %d exceeds FD_SETSIZE %d", host->id, icmp_socket, FD_SETSIZE));
					snprintf(ping->ping_status, 50, "down");
					snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: fd exceeds FD_SETSIZE");
					rc = HOST_DOWN;
					goto cleanup;
				}
				FD_SET(icmp_socket, &socket_fds);
				/* a stray datagram must not restart the wait, and only Linux
				 * writes the time left back into the timeval */
				ping_wait_left(deadline, &timeout);
				return_code = select(icmp_socket + 1, &socket_fds, NULL, NULL, &timeout);

				if (return_code < 0 && errno == EINTR) {
					goto keep_listening;
				}

				total_time = (spine_monotonic_time() - begin_time) * one_thousand;

				if (return_code > 0 && total_time < host_timeout) {
#if !(defined(__CYGWIN__))
					return_code = recvfrom(icmp_socket, socket_reply, BUFSIZE, MSG_WAITALL, (struct sockaddr *) &recvname, &fromlen);
#else
					return_code = recvfrom(icmp_socket, socket_reply, BUFSIZE, MSG_PEEK, (struct sockaddr *) &recvname, &fromlen);
#endif

					if (return_code < 0) {
						if (errno == EINTR) {
							/* call was interrupted by some system event */

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] DEBUG: Received EINTR", host->id));
							} else {
								SPINE_LOG_DEBUG(("Device[%i] DEBUG: Received EINTR", host->id));
							}

							goto keep_listening;
						}
					} else {
						const struct icmp *reply_pkt = NULL;
						const struct icmp *seen = NULL;
						spine_icmp_reply_t verdict;

						if (icmp_dgram) {
							verdict = spine_icmp_classify_dgram_reply((const unsigned char *) socket_reply,
								return_code, icmp->icmp_seq, &reply_pkt);
						} else {
							verdict = spine_icmp_classify_reply((const unsigned char *) socket_reply,
								return_code, (uint16_t) (getpid() & 0xFFFF), icmp->icmp_seq, &reply_pkt);
						}

						if (verdict == SPINE_ICMP_REPLY_NOT_OURS) {
							/* a middlebox that rewrites ICMP query ids is indistinguishable
							 * from a dead device once the reply is dropped, so record what
							 * arrived.  Both classifiers validate the length before they can
							 * return this, so the header is safe to read here */
							if (icmp_dgram) {
								seen = (const struct icmp *) socket_reply;
							} else {
								seen = (const struct icmp *) (socket_reply + (((struct ip *) socket_reply)->ip_hl << 2));
							}

							SPINE_LOG_DEBUG(("DEBUG: Device[%i] Discarded ICMP reply, expected id:%d seq:%d, received id:%d seq:%d", host->id, (int) (getpid() & 0xFFFF), icmp->icmp_seq, seen->icmp_id, seen->icmp_seq));
						}

						if (verdict != SPINE_ICMP_REPLY_OK && verdict != SPINE_ICMP_REPLY_NOT_ECHO) {
							ICMP_DISCARD_PEEKED(icmp_socket, socket_reply);
							goto keep_listening;
						}

						if (fromname.sin_addr.s_addr == recvname.sin_addr.s_addr) {
							if (verdict == SPINE_ICMP_REPLY_OK) {

								if (is_debug_device(host->id)) {
									SPINE_LOG(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
								} else {
									SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
								}
								snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Device is Alive");
								snprintf(ping->ping_status, 50, "%.5f", total_time);
								rc = HOST_UP;
								goto cleanup;
							} else {
								/* received a response other than an echo reply; the
								 * echo reply may still arrive inside this deadline */
								ICMP_DISCARD_PEEKED(icmp_socket, socket_reply);
								goto keep_listening;
							}
						} else {
							/* another host responded */
							ICMP_DISCARD_PEEKED(icmp_socket, socket_reply);
							goto keep_listening;
						}
					}
				} else {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] DEBUG: Exceeded Device Timeout, Retrying", host->id));
					} else {
						SPINE_LOG_DEBUG(("Device[%i] DEBUG: Exceeded Device Timeout, Retrying", host->id));
					}
				}

				total_time = 0;
				retry_count++;
#ifndef SOLAR_THREAD
				usleep(1000);
#endif
			}
		} else {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Destination hostname invalid");
			snprintf(ping->ping_status, 50, "down");
			rc = HOST_DOWN;
			goto cleanup;
		}
	} else {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Destination address not specified");
		snprintf(ping->ping_status, 50, "down");
		rc = HOST_DOWN;
		goto cleanup;
	}

cleanup:
	/* One owner for both resources. Five exits used to spell this out
	 * separately and they had already drifted: the FD_SETSIZE guard closed the
	 * socket and returned without freeing the packet, once per affected device
	 * per cycle. See #593.
	 *
	 * The shared socket outlives this call; only a socket opened here is
	 * closed. */
	SPINE_FREE(packet);

	if (waiting) {
		icmp_shared_unregister(&waiter);
	}

	if (icmp_socket != -1 && !icmp_use_shared) {
		close(icmp_socket);
	}

	return rc;
}
