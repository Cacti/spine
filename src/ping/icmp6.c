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

#ifdef SPINE_HAVE_ICMPV6

/*! \fn static int init_sockaddr6(struct sockaddr_in6 *name, const char *hostname)
 *  \brief converts a hostname or IPv6 literal to an IPv6 socket address
 *
 *  \return TRUE if successful, FALSE otherwise.
 *
 */
static int init_sockaddr6(struct sockaddr_in6 *name, const char *hostname) {
	struct addrinfo hints, *hostinfo;
	int rv, retry_count;
	char address[BUFSIZE];

	memset(&hints, 0, sizeof(hints));

	/* AI_ADDRCONFIG is deliberately omitted: it hides IPv6 results on hosts
	 * that only carry a loopback address, which is exactly where a ::1 test
	 * has to work */
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;

	retry_count = 0;
	hostinfo = NULL;

	while (TRUE) {
		rv = getaddrinfo(ping_address(hostname, address, sizeof(address)), NULL, &hints, &hostinfo);

		if (rv == 0) {
			break;
		}

		if ((rv == EAI_AGAIN) && (retry_count < 3)) {
			retry_count++;
			usleep(50000);
			continue;
		}

		SPINE_LOG(("WARNING: Error resolving IPv6 host %s (%s)", hostname, gai_strerror(rv)));

		return FALSE;
	}

	if (hostinfo == NULL) {
		SPINE_LOG(("WARNING: Unknown host %s", hostname));

		return FALSE;
	}

	if ((hostinfo->ai_family != AF_INET6) || (hostinfo->ai_addrlen < sizeof(struct sockaddr_in6))) {
		SPINE_LOG(("WARNING: Host %s did not resolve to an IPv6 address", hostname));
		freeaddrinfo(hostinfo);

		return FALSE;
	}

	memcpy(name, hostinfo->ai_addr, sizeof(struct sockaddr_in6));

	/* on a raw IPv6 socket sin6_port carries the protocol number rather
	 * than a port, and the kernel rejects anything that disagrees with the
	 * socket's own protocol */
	name->sin6_port = 0;

	freeaddrinfo(hostinfo);

	return TRUE;
}

/*! \fn static void apply_ipv6_scope_id(struct sockaddr_in6 *name)
 *  \brief supplies a scope id for a link local destination that lacks one
 *
 *  getaddrinfo() only fills in sin6_scope_id when the literal carries a
 *  %zone suffix.  Without it the kernel refuses to send, so fall back to
 *  the first non loopback interface that carries an IPv6 address.
 *
 */
static void apply_ipv6_scope_id(struct sockaddr_in6 *name) {
#if defined(HAVE_IFADDRS_H) && defined(HAVE_NET_IF_H) && defined(HAVE_GETIFADDRS) && defined(HAVE_IF_NAMETOINDEX)
	struct ifaddrs *ifa_list, *ifa;
	unsigned int if_index;

	ifa_list = NULL;

	if (getifaddrs(&ifa_list) != 0) {
		return;
	}

	for (ifa = ifa_list; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if (ifa->ifa_addr->sa_family != AF_INET6) continue;
		if (ifa->ifa_flags & IFF_LOOPBACK) continue;

		if_index = if_nametoindex(ifa->ifa_name);

		if (if_index != 0) {
			name->sin6_scope_id = if_index;
			break;
		}
	}

	freeifaddrs(ifa_list);
#else
	(void) name;
#endif
}

/*! \fn static int ping_icmp_ipv6(host_t *host, ping_t *ping)
 *  \brief ping a host using an ICMPv6 echo request
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  The IPv6 counterpart of ping_icmp().  The payload carries the same
 *  "Cacti" marker so that firewalls can be configured to allow it, and the
 *  kernel computes the ICMPv6 checksum on our behalf.  It will modify the
 *  ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
int ping_icmp_ipv6(const host_t *host, ping_t *ping) {
	int icmp_socket;
	int socket_errno = 0;
	int icmp_use_shared = FALSE;
	icmp_waiter_t waiter;
	int waiting = FALSE;

	double begin_time, deadline, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;

	struct sockaddr_in6 recvname;
	struct sockaddr_in6 fromname;
	char socket_reply[BUFSIZE];
	int retry_count;
	const char *cacti_msg = icmp6_payload;
	size_t msg_len;
	int packet_len;
	socklen_t fromlen;
	ssize_t return_code;
	fd_set socket_fds;
	int result;

	static unsigned int seq = 0;

	struct icmp6_hdr *icmp6;
	unsigned char *packet;
	uint16_t our_id;
	uint16_t our_seq;
	int icmp_dgram;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering ICMPv6 Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering ICMPv6 Ping", host->id));
	}

	result = HOST_DOWN;
	packet = NULL;
	icmp_socket = -1;
	retry_count = 0;
	msg_len = strlen(cacti_msg);

	/* net.ipv4.ping_group_range governs IPPROTO_ICMPV6 datagram sockets as
	 * well, so the unprivileged path is worth trying here too.  The kernel
	 * rewrites the echo id on such a socket, which the reply match below
	 * accounts for. */
	icmp_dgram = FALSE;
	icmp_socket = icmp_open_socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);

	if (icmp_socket != -1) {
		icmp_dgram = TRUE;
	} else if (icmp6_shared.fd != -1) {
		icmp_socket = icmp6_shared.fd;
		icmp_use_shared = TRUE;
	}

	/* As in ping_icmp(), a socket of our own never involves regaining root. */
	while (icmp_socket == -1) {
		icmp_socket = icmp_open_socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		socket_errno = errno;

		if (icmp_socket != -1) {
			break;
		}

		SPINE_LOG_MEDIUM(("WARNING: Device[%i] raw ICMPv6 socket creation failed: %s",
			host->id, strerror(socket_errno)));

		usleep(500000);
		retry_count++;

		if (retry_count > 4) {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Ping unable to create ICMPv6 Socket");
			snprintf(ping->ping_status, 50, "down");

			return HOST_DOWN;
		}
	}

	/* RFC 3542 hardening.  Both options are best effort because older
	 * kernels and restricted sandboxes reject them without breaking the
	 * ping itself */
	{
		struct icmp6_filter filter;

		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);

		if (setsockopt(icmp_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0) {
			SPINE_LOG_DEBUG(("DEBUG: ICMP6_FILTER not supported: %s", strerror(errno)));
		}
	}

#ifdef IPV6_CHECKSUM
	{
		/* tell the kernel where to write the checksum it computes for us */
		int cksum_offset = (int) offsetof(struct icmp6_hdr, icmp6_cksum);

		if (setsockopt(icmp_socket, IPPROTO_IPV6, IPV6_CHECKSUM, &cksum_offset, sizeof(cksum_offset)) < 0) {
			SPINE_LOG_DEBUG(("DEBUG: IPV6_CHECKSUM not supported: %s", strerror(errno)));
		}
	}
#endif

	/* convert the host timeout to a double precision number in seconds */
	host_timeout = host->availability.timeout;

	/* allocate the packet in memory */
	packet_len = (int) (sizeof(struct icmp6_hdr) + msg_len);

	if (!(packet = malloc(packet_len))) {
		die("ERROR: Fatal malloc error: ping.c ping_icmp_ipv6!");
	}
	memset(packet, 0, packet_len);

	/* set the memory of the ping address */
	memset(&fromname, 0, sizeof(struct sockaddr_in6));
	memset(&recvname, 0, sizeof(struct sockaddr_in6));

	our_id = (uint16_t) (getpid() & 0xFFFF);

	/* lock set/get the sequence and unlock */
	thread_mutex_lock(LOCK_GHBN);
	our_seq = (uint16_t) seq++;
	thread_mutex_unlock(LOCK_GHBN);

	icmp6 = (struct icmp6_hdr *) packet;

	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = htons(our_id);
	icmp6->icmp6_seq = htons(our_seq);
	icmp6->icmp6_cksum = 0;

	memcpy(packet + sizeof(struct icmp6_hdr), cacti_msg, msg_len);

	/* hostname must be nonblank */
	if (strlen(host->hostname) == 0) {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Destination address not specified");
		snprintf(ping->ping_status, 50, "down");
		goto cleanup;
	}

	/* get address of hostname */
	if (!init_sockaddr6(&fromname, host->hostname)) {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Destination hostname invalid");
		snprintf(ping->ping_status, 50, "down");
		goto cleanup;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&fromname.sin6_addr) && (fromname.sin6_scope_id == 0)) {
		apply_ipv6_scope_id(&fromname);
	}

	/* initialize variables */
	snprintf(ping->ping_status, 50, "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

	retry_count = 0;
	total_time = 0;

	if (icmp_use_shared) {
		memset(&waiter, 0, sizeof(waiter));
		waiter.shared = &icmp6_shared;
		waiter.family = AF_INET6;
		waiter.id = htons(our_id);
		waiter.seq = htons(our_seq);
		waiter.peer6 = fromname.sin6_addr;
		icmp_shared_register(&waiter);
		waiting = TRUE;
	}

	while (1) {
		if (retry_count > host->availability.retries) {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Ping timed out");
			snprintf(ping->ping_status, 50, "down");
			goto cleanup;
		}

		if (is_debug_device(host->id)) {
			SPINE_LOG(("Device[%i] DEBUG: Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, our_seq, retry_count, host->availability.retries));
		} else {
			SPINE_LOG_DEBUG(("DEBUG: Device[%i] Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, our_seq, retry_count, host->availability.retries));
		}

		if (waiting) {
			/* Socket options would change every other thread's socket too. */
			double attempt_begin = get_time_as_double();

			if (sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, sizeof(fromname)) >= 0 &&
				icmp_shared_await(&waiter, attempt_begin + host_timeout / one_thousand)) {
				total_time = (get_time_as_double() - attempt_begin) * one_thousand;

				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
				}

				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Device is Alive");
				snprintf(ping->ping_status, 50, "%.5f", total_time);

				result = HOST_UP;
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
		if (sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, sizeof(fromname)) < 0) {
			SPINE_LOG_DEBUG(("DEBUG: Device[%i] ICMPv6 sendto failed (%s)", host->id, strerror(errno)));

			total_time = 0;
			retry_count++;
			continue;
		}

	/* wait for a response on the socket */
	/* reinitialize fd_set -- select(2) clears bits in place on return */
	keep_listening_ipv6:
		FD_ZERO(&socket_fds);
		if (icmp_socket >= FD_SETSIZE) {
			SPINE_LOG(("ERROR: Device[%i] ICMPv6 socket %d exceeds FD_SETSIZE %d", host->id, icmp_socket, FD_SETSIZE));
			snprintf(ping->ping_status, 50, "down");
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: fd exceeds FD_SETSIZE");
			goto cleanup;
		}
		FD_SET(icmp_socket, &socket_fds);
		/* a stray datagram must not restart the wait, and only Linux
		 * writes the time left back into the timeval */
		ping_wait_left(deadline, &timeout);
		return_code = select(icmp_socket + 1, &socket_fds, NULL, NULL, &timeout);

		if (return_code < 0 && errno == EINTR) {
			goto keep_listening_ipv6;
		}

		total_time = (spine_monotonic_time() - begin_time) * one_thousand;

		if ((return_code > 0) && (total_time < host_timeout)) {
			fromlen = sizeof(recvname);
			return_code = recvfrom(icmp_socket, socket_reply, BUFSIZE, 0, (struct sockaddr *) &recvname, &fromlen);

			if (return_code < 0) {
				if (errno == EINTR) {
					/* call was interrupted by some system event */

					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] DEBUG: Received EINTR", host->id));
					} else {
						SPINE_LOG_DEBUG(("DEBUG: Device[%i] Received EINTR", host->id));
					}

					goto keep_listening_ipv6;
				}
			} else {
				/* the kernel does not match the source address for us */
				if (memcmp(&fromname.sin6_addr, &recvname.sin6_addr, sizeof(struct in6_addr)) != 0) {
					/* another host responded */
					goto keep_listening_ipv6;
				}

				/* on a datagram socket the kernel assigns the echo id, so it
				 * will not match what we wrote; sequence, source address and
				 * payload still identify the reply */
				if (!icmp6_reply_matches((const unsigned char *) socket_reply, return_code,
						htons(our_id), htons(our_seq), !icmp_dgram)) {
					goto keep_listening_ipv6;
				}

				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count + 1, (total_time)));
				}

				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Device is Alive");
				snprintf(ping->ping_status, 50, "%.5f", total_time);

				result = HOST_UP;
				goto cleanup;
			}
		} else {
			if (is_debug_device(host->id)) {
				SPINE_LOG(("Device[%i] DEBUG: Exceeded Device Timeout, Retrying", host->id));
			} else {
				SPINE_LOG_DEBUG(("DEBUG: Device[%i] Exceeded Device Timeout, Retrying", host->id));
			}
		}

		total_time = 0;
		retry_count++;
#ifndef SOLAR_THREAD
		usleep(1000);
#endif
	}

cleanup:
	SPINE_FREE(packet);

	if (waiting) {
		icmp_shared_unregister(&waiter);
	}

	if (icmp_socket != -1 && !icmp_use_shared) {
		close(icmp_socket);
	}

	return result;
}

#endif /* SPINE_HAVE_ICMPV6 */
