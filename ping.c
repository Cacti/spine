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

#include "common.h"
#include "spine.h"
#include <fcntl.h>

#ifdef SPINE_HAVE_ICMPV6
static int ping_icmp_ipv6(const host_t *host, ping_t *ping);
#endif

/*! \fn int ping_host(host_t *host, ping_t *ping)
 *  \brief ping a host to determine if it is reachable for polling
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using the method specified within the system
 *  configuration and then returns the host status to the calling function.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 */
static int ping_network(host_t *host, ping_t *ping) {
	if (host->availability.ping_method == PING_ICMP && !set.availability.icmp_avail) {
		SPINE_LOG(("Device[%i] DEBUG Falling back to UDP Ping Due to SetUID Issues", host->id));
		host->availability.ping_method = PING_UDP;
	}
	if (strstr(host->hostname, "localhost")) {
		STRNCOPY(ping->ping_status, "0.000");
		STRNCOPY(ping->ping_response, "PING: Device does not require ping.");
		return HOST_UP;
	}
	int address_type = get_address_type(host);
	#ifdef SPINE_HAVE_ICMPV6
	if (address_type == SPINE_IPV6 && host->availability.ping_method == PING_ICMP) {
		return ping_icmp_ipv6(host, ping);
	}
	#endif
	if (address_type != SPINE_IPV4) {
		if (host->availability.method == AVAIL_PING) {
			STRNCOPY(ping->ping_status, "0.000");
			STRNCOPY(ping->ping_response, "PING: Device is Unknown or is IPV6.  Please use the SNMP ping options only.");
		}
		return HOST_DOWN;
	}
	switch (host->availability.ping_method) {
		case PING_ICMP: return ping_icmp(host, ping);
		case PING_UDP: return ping_udp(host, ping);
		case PING_TCP:
		case PING_TCP_CLOSED: return ping_tcp(host, ping);
		default: return HOST_DOWN;
	}
}

static int ping_snmp_availability(host_t *host, ping_t *ping, int ping_result) {
	if (host->availability.method == AVAIL_SNMP_AND_PING && ping_result != HOST_UP) return HOST_DOWN;
	if (host->availability.method == AVAIL_SNMP_OR_PING && ping_result == HOST_UP) return HOST_UP;
	/* Preserve the configured no-SNMP contract for v1/v2 without a community. */
	if (host->snmp.profile.community[0] == '\0' && host->snmp.profile.version < 3) return HOST_UP;
	double begin = get_time_as_double();
	int result = ping_snmp(host, ping);
	double elapsed = (get_time_as_double() - begin) * 1000.0;
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM,
		("Device[%i] INFO: SNMP Device %s, Time:%.4f ms", host->id, result == HOST_UP ? "Alive" : "Down", elapsed));
	return result;
}

int ping_host(host_t *host, ping_t *ping) {
	int network_result = HOST_DOWN;
	if (host->availability.method == AVAIL_SNMP_AND_PING ||
		host->availability.method == AVAIL_PING ||
		host->availability.method == AVAIL_SNMP_OR_PING) {
		network_result = ping_network(host, ping);
	}
	switch (host->availability.method) {
		case AVAIL_SNMP_AND_PING:
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP:
		case AVAIL_SNMP_GET_NEXT:
		case AVAIL_SNMP_GET_SYSDESC:
			return ping_snmp_availability(host, ping, network_result);
		case AVAIL_PING: return network_result;
		case AVAIL_NONE: return HOST_UP;
		default: return HOST_DOWN;
	}
}

/*! \fn int ping_snmp(host_t *host, ping_t *ping)
 *  \brief ping a host using snmp sysUptime
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using snmp.  It polls sysUptime by default.
 *  It will modify the ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
int ping_snmp(host_t *host, ping_t *ping) {
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: Entering SNMP Ping", host->id));
	if (!host->snmp.session) {
		STRNCOPY(ping->snmp_status, "0.00");
		STRNCOPY(ping->snmp_response, "Invalid SNMP Session");
		return HOST_DOWN;
	}
	if (host->snmp.profile.community[0] == '\0' && host->snmp.profile.version != 3) {
		STRNCOPY(ping->snmp_status, "0.00");
		STRNCOPY(ping->snmp_response, "Device does not require SNMP");
		return HOST_UP;
	}
	char oid[32];
	switch (host->availability.method) {
		case AVAIL_SNMP_GET_NEXT: STRNCOPY(oid, ".1.3"); break;
		case AVAIL_SNMP_GET_SYSDESC: STRNCOPY(oid, ".1.3.6.1.2.1.1.1.0"); break;
		default: STRNCOPY(oid, ".1.3.6.1.2.1.1.3.0"); break;
	}
	double begin = get_time_as_double();
	char *result = host->availability.method == AVAIL_SNMP_GET_NEXT ? snmp_getnext(host, oid) : snmp_get(host, oid);
	double elapsed = (get_time_as_double() - begin) * 1000.0;
	SPINE_FREE(result);
	if (host->snmp.status == SNMPERR_SUCCESS || host->snmp.status == SNMPERR_UNKNOWN_OBJID) {
		STRNCOPY(ping->snmp_response, "Device responded to SNMP");
		spine_snprintf(ping->snmp_status, sizeof(ping->snmp_status), "%.5f", elapsed);
		return HOST_UP;
	}
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH,
		("Device[%i] SNMP Ping %s", host->id, host->snmp.status == STAT_TIMEOUT ? "Timeout" : "Unknown Error"));
	STRNCOPY(ping->snmp_response, "Device did not respond to SNMP");
	return HOST_DOWN;
}

static int ping_down(ping_t *ping, const char *message);

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
#define ICMP_DISCARD_PEEKED(sock, buf) ((void)0)
#endif


/*! \fn spine_icmp_reply_t spine_icmp_classify_reply(const unsigned char *reply, ssize_t len, uint16_t want_id, uint16_t want_seq, const struct icmp **out_pkt)
 *  \brief bounds-check a raw ICMP reply and decide whether it answers our echo
 *
 *  The raw socket is shared across every poller thread and is fed by whatever
 *  the network sends, so this walks the IP header length field before touching
 *  the ICMP header.  Split out of ping_icmp() so the fuzz target exercises the
 *  same code the poller runs.
 *
 *  \return the reply classification; *out_pkt is set only for SPINE_ICMP_REPLY_OK
 */
spine_icmp_reply_t spine_icmp_classify_reply(const unsigned char *reply, ssize_t len,
	uint16_t want_id, uint16_t want_seq, const struct icmp **out_pkt) {
	size_t   ihl;
	uint16_t received_id;
	uint16_t received_seq;

	if (out_pkt != NULL) {
		*out_pkt = NULL;
	}

	if (reply == NULL || len < (ssize_t) sizeof(struct ip)) {
		return SPINE_ICMP_REPLY_TOO_SHORT;
	}

	/* Read header fields as bytes: the receive buffer has no alignment
	 * guarantee, and a raw socket can deliver a non-IPv4 or non-ICMP datagram. */
	ihl = (size_t) (reply[0] & 0x0F) << 2;

	if ((reply[0] >> 4) != 4 || reply[9] != IPPROTO_ICMP ||
		ihl < sizeof(struct ip) || len < (ssize_t) (ihl + ICMP_HDR_SIZE)) {
		return SPINE_ICMP_REPLY_BAD_HEADER;
	}

	/* An echo reply always carries code 0. */
	if (reply[ihl] != ICMP_ECHOREPLY || reply[ihl + 1] != 0) {
		return SPINE_ICMP_REPLY_NOT_ECHO;
	}

	memcpy(&received_id, reply + ihl + 4, sizeof(received_id));
	memcpy(&received_seq, reply + ihl + 6, sizeof(received_seq));

	if (received_id != want_id || received_seq != want_seq) {
		return SPINE_ICMP_REPLY_NOT_OURS;
	}

	if (out_pkt != NULL) {
		*out_pkt = (const struct icmp *) (reply + ihl);
	}

	return SPINE_ICMP_REPLY_OK;
}

/*! \fn spine_icmp_reply_t spine_icmp_classify_dgram_reply(const unsigned char *reply, ssize_t len, uint16_t want_seq, const struct icmp **out_pkt)
 *  \brief classifies an echo reply read from an unprivileged datagram socket
 *
 *  A SOCK_DGRAM ICMP socket delivers the reply with the IPv4 header already
 *  stripped, and the kernel assigns the echo id rather than honouring the one
 *  we wrote, so the sequence is all that is left to match on.  The caller has
 *  already checked the source address.
 */
spine_icmp_reply_t spine_icmp_classify_dgram_reply(const unsigned char *reply, ssize_t len,
	uint16_t want_seq, const struct icmp **out_pkt) {
	const struct icmp *pkt;
	uint16_t received_seq;

	if (out_pkt != NULL) {
		*out_pkt = NULL;
	}

	if (reply == NULL || len < (ssize_t) ICMP_HDR_SIZE) {
		return SPINE_ICMP_REPLY_TOO_SHORT;
	}

	pkt = (const struct icmp *) reply;

	/* Fields are read as bytes; the receive buffer has no alignment guarantee. */
	if (reply[0] != ICMP_ECHOREPLY || reply[1] != 0) {
		return SPINE_ICMP_REPLY_NOT_ECHO;
	}

	memcpy(&received_seq, reply + 6, sizeof(received_seq));

	if (received_seq != want_seq) {
		return SPINE_ICMP_REPLY_NOT_OURS;
	}

	if (out_pkt != NULL) {
		*out_pkt = pkt;
	}

	return SPINE_ICMP_REPLY_OK;
}

#ifdef SPINE_HAVE_ICMPV6
static const char icmp6_payload[] = "cacti-monitoring-system";

/*! \fn static int icmp6_reply_matches(const unsigned char *reply, ssize_t len, uint16_t id, uint16_t seq, int check_id)
 *  \brief decides whether an ICMPv6 message answers our echo request
 *
 *  ICMPv6 sockets deliver the message without the IPv6 header.  id and seq
 *  are in network order, as written into the request.  A datagram socket
 *  rewrites the echo id, so its caller passes check_id FALSE.
 */
static int icmp6_reply_matches(const unsigned char *reply, ssize_t len, uint16_t id, uint16_t seq, int check_id) {
	struct icmp6_hdr hdr;
	size_t payload_len = sizeof(icmp6_payload) - 1;

	if (len < 0 || (size_t) len < sizeof(hdr) + payload_len) {
		return FALSE;
	}

	memcpy(&hdr, reply, sizeof(hdr));

	if (hdr.icmp6_type != ICMP6_ECHO_REPLY || hdr.icmp6_seq != seq) {
		return FALSE;
	}

	if (check_id && hdr.icmp6_id != id) {
		return FALSE;
	}

	return memcmp(reply + sizeof(hdr), icmp6_payload, payload_len) == 0;
}
#endif

/* Raw sockets opened by drop_privileges() before a setuid root spine gave up
 * root for good.  Without CAP_NET_RAW nothing can open another, so every
 * poller thread shares them.  A raw socket queues each ICMP message once, so a
 * thread that reads a reply meant for another thread must hand it over rather
 * than drop it: one thread at a time reads, matches each reply against the
 * registered requests, and wakes only the thread it answers.  LOCK_ICMP guards
 * all of it. */
typedef struct {
	int fd;
	int reading;
} icmp_shared_t;

typedef struct icmp_waiter {
	struct icmp_waiter *next;
	icmp_shared_t *shared;
	pthread_cond_t wake;
	int      family;
	uint16_t id;
	uint16_t seq;
	struct in_addr  peer;
	#ifdef SPINE_HAVE_ICMPV6
	struct in6_addr peer6;
	#endif
	int      answered;
	int      sleeping;
} icmp_waiter_t;

/* A reader empties the queue in batches read without LOCK_ICMP held, so a
 * flood delays neither registrations nor the waiters being woken.  The bound
 * on one pass keeps the reader's own deadline check running.  Matching needs
 * only the IP header, the ICMP header and the payload marker, so each slot
 * keeps the first ICMP_SHARED_SNAPLEN bytes.  The queue itself is sized for
 * every poller thread rather than one. */
#define ICMP_SHARED_DRAIN_MAX 1024
#define ICMP_SHARED_BATCH     64
#define ICMP_SHARED_SNAPLEN   128
#define ICMP_SHARED_RCVBUF    (4 * 1024 * 1024)

#if defined(__linux__)
#ifndef SOL_RAW
#define SOL_RAW 255
#endif
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#endif

static icmp_shared_t  icmp_shared  = {-1, FALSE};
#ifdef SPINE_HAVE_ICMPV6
static icmp_shared_t  icmp6_shared = {-1, FALSE};
#endif
static icmp_waiter_t *icmp_waiters = NULL;

/*! \fn static int icmp_open_socket(int family, int type, int protocol)
 *  \brief opens an ICMP socket that PHP and script children cannot inherit
 *
 *  Poller threads posix_spawn() scripts while others ping, so the flag is set
 *  atomically where SOCK_CLOEXEC exists; elsewhere fcntl() narrows the window.
 */
static int icmp_open_socket(int family, int type, int protocol) {
	int fd;

	#ifdef SOCK_CLOEXEC
	fd = socket(family, type | SOCK_CLOEXEC, protocol);

	if (fd != -1 || errno != EINVAL) {
		return fd;
	}
	#endif

	fd = socket(family, type, protocol);

	if (fd != -1 && fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

static int icmp_open_shared(int family, int protocol) {
	int fd = icmp_open_socket(family, SOCK_RAW, protocol);

	if (fd == -1) {
		return -1;
	}

	/* A descriptor select() cannot watch is no use to the readers below. */
	if (fd >= FD_SETSIZE) {
		close(fd);
		return -1;
	}

	#if defined(__linux__)
	/* The kernel copies every inbound ICMP message to a raw socket.  Echo
	 * requests and errors aimed at this host would otherwise compete with
	 * the replies for the single shared queue.  Best effort, as is
	 * ICMP6_FILTER on the IPv6 socket. */
	if (family == AF_INET) {
		uint32_t blocked = ~(1U << ICMP_ECHOREPLY);

		(void) setsockopt(fd, SOL_RAW, ICMP_FILTER, &blocked, sizeof(blocked));
	}
	#endif

	/* Best effort as well.  SO_RCVBUFFORCE passes net.core.rmem_max, which
	 * is why this happens here, while spine is still root. */
	{
		int rcvbuf = ICMP_SHARED_RCVBUF;

		#ifdef SO_RCVBUFFORCE
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) != 0)
		#endif
		(void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	}

	return fd;
}

/*! \fn int ping_icmp_open_shared(void)
 *  \brief opens the shared raw ICMP sockets; the caller must still be root
 *
 *  \return TRUE if the IPv4 socket is open.  IPv6 is best effort.
 */
int ping_icmp_open_shared(void) {
	if (icmp_shared.fd == -1) {
		icmp_shared.fd = icmp_open_shared(AF_INET, IPPROTO_ICMP);
	}

	#ifdef SPINE_HAVE_ICMPV6
	if (icmp6_shared.fd == -1) {
		icmp6_shared.fd = icmp_open_shared(AF_INET6, IPPROTO_ICMPV6);
	}
	#endif

	return icmp_shared.fd != -1;
}

int ping_icmp_shared_available(void) {
	return icmp_shared.fd != -1;
}

/* Called with LOCK_ICMP held whenever nobody is reading a socket: wake one
 * sleeping waiter so it takes over.  A waiter that is not asleep finds the
 * socket free on its own before it next sleeps. */
static void icmp_shared_handoff(const icmp_shared_t *shared) {
	icmp_waiter_t *waiter;

	if (shared->reading) {
		return;
	}

	for (waiter = icmp_waiters; waiter != NULL; waiter = waiter->next) {
		if (waiter->shared == shared && waiter->sleeping && !waiter->answered) {
			pthread_cond_signal(&waiter->wake);
			return;
		}
	}
}

static void icmp_shared_register(icmp_waiter_t *waiter) {
	pthread_cond_init(&waiter->wake, NULL);

	thread_mutex_lock(LOCK_ICMP);
	waiter->answered = FALSE;
	waiter->sleeping = FALSE;
	waiter->next     = icmp_waiters;
	icmp_waiters     = waiter;
	thread_mutex_unlock(LOCK_ICMP);
}

static void icmp_shared_unregister(icmp_waiter_t *waiter) {
	icmp_waiter_t **link;

	thread_mutex_lock(LOCK_ICMP);
	for (link = &icmp_waiters; *link != NULL; link = &(*link)->next) {
		if (*link == waiter) {
			*link = waiter->next;
			break;
		}
	}
	icmp_shared_handoff(waiter->shared);
	thread_mutex_unlock(LOCK_ICMP);

	pthread_cond_destroy(&waiter->wake);
}

/* Called with LOCK_ICMP held.  A reply nobody waits for is dropped, exactly as
 * a per-thread socket would drop a reply that is not its own. */
static void icmp_shared_dispatch(int family, const unsigned char *reply, ssize_t len,
	const struct sockaddr_storage *from) {
	icmp_waiter_t *waiter;

	for (waiter = icmp_waiters; waiter != NULL; waiter = waiter->next) {
		if (waiter->family != family || waiter->answered) {
			continue;
		}

		if (family == AF_INET) {
			const struct sockaddr_in *source = (const struct sockaddr_in *) from;

			if (source->sin_addr.s_addr != waiter->peer.s_addr ||
				spine_icmp_classify_reply(reply, len, waiter->id, waiter->seq, NULL) != SPINE_ICMP_REPLY_OK) {
				continue;
			}
		}
		#ifdef SPINE_HAVE_ICMPV6
		else {
			const struct sockaddr_in6 *source = (const struct sockaddr_in6 *) from;

			if (memcmp(&source->sin6_addr, &waiter->peer6, sizeof(waiter->peer6)) != 0 ||
				!icmp6_reply_matches(reply, len, waiter->id, waiter->seq, TRUE)) {
				continue;
			}
		}
		#endif

		waiter->answered = TRUE;
		pthread_cond_signal(&waiter->wake);
		return;
	}
}

/*! \fn static int icmp_shared_await(icmp_waiter_t *waiter, double deadline)
 *  \brief waits until the reply to a registered request arrives, or deadline
 *
 *  Whichever waiting thread finds the socket idle reads it, so a reply is
 *  never stuck behind a thread whose own deadline is further away: a reader
 *  returns from select() as soon as anything arrives, drains the queue, and
 *  wakes the threads whose replies it found.
 *
 *  \return TRUE if the reply arrived in time.
 */
static int icmp_shared_await(icmp_waiter_t *waiter, double deadline) {
	icmp_shared_t *shared = waiter->shared;
	unsigned char  replies[ICMP_SHARED_BATCH][ICMP_SHARED_SNAPLEN];
	struct sockaddr_storage sources[ICMP_SHARED_BATCH];
	ssize_t        lengths[ICMP_SHARED_BATCH];
	socklen_t      fromlen;
	ssize_t        received;
	struct timeval wait;
	struct timespec until;
	fd_set         fds;
	double         now;
	double         remaining;
	int            readable;
	int            drained;
	int            count;
	int            slot;
	int            answered;

	until.tv_sec  = (time_t) deadline;
	until.tv_nsec = (long) ((deadline - (double) until.tv_sec) * 1000000000.0);

	thread_mutex_lock(LOCK_ICMP);

	while (!waiter->answered) {
		now = get_time_as_double();

		if (now >= deadline) {
			break;
		}

		if (shared->reading) {
			waiter->sleeping = TRUE;
			pthread_cond_timedwait(&waiter->wake, get_lock(LOCK_ICMP), &until);
			waiter->sleeping = FALSE;
			continue;
		}

		shared->reading = TRUE;
		thread_mutex_unlock(LOCK_ICMP);

		remaining    = deadline - now;
		wait.tv_sec  = (time_t) remaining;
		wait.tv_usec = (suseconds_t) ((remaining - (double) wait.tv_sec) * 1000000.0);

		FD_ZERO(&fds);
		FD_SET(shared->fd, &fds);
		readable = select(shared->fd + 1, &fds, NULL, NULL, &wait) > 0;

		/* Empty the queue: under a flood, one reply per pass falls behind
		 * and the kernel drops the replies that matter. */
		for (drained = 0; readable && drained < ICMP_SHARED_DRAIN_MAX; drained += count) {
			for (count = 0; count < ICMP_SHARED_BATCH; ) {
				fromlen  = sizeof(sources[count]);
				received = recvfrom(shared->fd, replies[count], ICMP_SHARED_SNAPLEN, MSG_DONTWAIT,
					(struct sockaddr *) &sources[count], &fromlen);

				if (received < 0) {
					if (errno == EINTR) {
						continue;
					}
					readable = FALSE;
					break;
				}

				lengths[count++] = received;
			}

			thread_mutex_lock(LOCK_ICMP);
			for (slot = 0; slot < count; slot++) {
				if (lengths[slot] > 0) {
					icmp_shared_dispatch(waiter->family, replies[slot], lengths[slot], &sources[slot]);
				}
			}
			thread_mutex_unlock(LOCK_ICMP);
		}

		thread_mutex_lock(LOCK_ICMP);
		shared->reading = FALSE;
	}

	answered = waiter->answered;

	/* Leaving with the socket idle: let a sleeping waiter take over. */
	icmp_shared_handoff(shared);
	thread_mutex_unlock(LOCK_ICMP);

	return answered;
}

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
	int    icmp_socket = -1;
	int    icmp_dgram;
	int    rc = HOST_DOWN;
	int    socket_errno = 0;
	int    icmp_use_shared = FALSE;
	icmp_waiter_t waiter;
	int    waiting = FALSE;

	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;

	struct sockaddr_in recvname;
	struct sockaddr_in fromname;
	char   socket_reply[BUFSIZE];
	int    retry_count;
	const char *cacti_msg = "cacti-monitoring-system\0";
	int    packet_len;
	socklen_t    fromlen;
	ssize_t    return_code;
	fd_set socket_fds;

	static   unsigned int seq = 0;
	struct   icmp  *icmp;
	unsigned char  *packet = NULL;

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
	icmp_dgram  = FALSE;
	icmp_socket = icmp_open_socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);

	if (icmp_socket != -1) {
		icmp_dgram = TRUE;
	} else if (icmp_shared.fd != -1) {
		icmp_socket     = icmp_shared.fd;
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
	memset(&fromname, 0, sizeof(struct sockaddr_in));
	memset(&recvname, 0, sizeof(struct sockaddr_in));

	icmp = (struct icmp*) packet;

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id   = getpid() & 0xFFFF;

	/* lock set/get the sequence and unlock */
	thread_mutex_lock(LOCK_GHBN);
	icmp->icmp_seq = seq++;
	thread_mutex_unlock(LOCK_GHBN);

	icmp->icmp_cksum = 0;
	memcpy(packet+ICMP_HDR_SIZE, cacti_msg, strlen(cacti_msg));
	icmp->icmp_cksum = get_checksum(packet, packet_len);

	/* hostname must be nonblank */
	if ((strlen(host->hostname) != 0) && (icmp_socket != -1)) {
		/* initialize variables */
		snprintf(ping->ping_status, 50, "down");
		snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

		/* get address of hostname */
		if (init_sockaddr(&fromname, host->hostname, 7)) {
			retry_count = 0;
			total_time  = 0;
			begin_time  = get_time_as_double();

			if (icmp_use_shared) {
				memset(&waiter, 0, sizeof(waiter));
				waiter.shared = &icmp_shared;
				waiter.family = AF_INET;
				waiter.id     = (uint16_t) (getpid() & 0xFFFF);
				waiter.seq    = icmp->icmp_seq;
				waiter.peer   = fromname.sin_addr;
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
							SPINE_LOG(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
						} else {
							SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
						}
						snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Device is Alive");
						snprintf(ping->ping_status, 50, "%.5f", total_time);
						rc = HOST_UP;
						goto cleanup;
					}

					retry_count++;
					continue;
				}

				/* decrement the timeout value by the total time */
				timeout.tv_sec  = rint((host_timeout - total_time) / 1000);
				timeout.tv_usec = ((int) (host_timeout - total_time) % 1000) * 1000;

				/* set the socket send and receive timeout */
				setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
				setsockopt(icmp_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

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
				FD_SET(icmp_socket,&socket_fds);
				return_code = select(icmp_socket + 1, &socket_fds, NULL, NULL, &timeout);

				/* record end time */
				end_time = get_time_as_double();

				/* calculate total time */
				total_time = (end_time - begin_time) * one_thousand;

				if (total_time < host_timeout) {
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
						const struct icmp  *reply_pkt = NULL;
						const struct icmp  *seen       = NULL;
						spine_icmp_reply_t  verdict;

						if (icmp_dgram) {
							verdict = spine_icmp_classify_dgram_reply((const unsigned char *) socket_reply,
								return_code, icmp->icmp_seq, &reply_pkt);
						} else {
							verdict = spine_icmp_classify_reply((const unsigned char *) socket_reply,
								return_code, (uint16_t)(getpid() & 0xFFFF), icmp->icmp_seq, &reply_pkt);
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

							SPINE_LOG_DEBUG(("DEBUG: Device[%i] Discarded ICMP reply, expected id:%d seq:%d, received id:%d seq:%d", host->id, (int)(getpid() & 0xFFFF), icmp->icmp_seq, seen->icmp_id, seen->icmp_seq));
						}

						if (verdict != SPINE_ICMP_REPLY_OK && verdict != SPINE_ICMP_REPLY_NOT_ECHO) {
							ICMP_DISCARD_PEEKED(icmp_socket, socket_reply);
							goto keep_listening;
						}

						if (fromname.sin_addr.s_addr == recvname.sin_addr.s_addr) {
							if (verdict == SPINE_ICMP_REPLY_OK) {

								if (is_debug_device(host->id)) {
									SPINE_LOG(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
								} else {
									SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
								}
								snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Device is Alive");
								snprintf(ping->ping_status, 50, "%.5f", total_time);
								rc = HOST_UP;
								goto cleanup;
							} else {
								/* received a response other than an echo reply */
								ICMP_DISCARD_PEEKED(icmp_socket, socket_reply);

								if (total_time > host_timeout) {
									retry_count++;
									total_time = 0;
								}

								continue;
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

	memset(&hints, 0, sizeof(hints));

	/* AI_ADDRCONFIG is deliberately omitted: it hides IPv6 results on hosts
	 * that only carry a loopback address, which is exactly where a ::1 test
	 * has to work */
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_DGRAM;

	retry_count = 0;
	hostinfo    = NULL;

	while (TRUE) {
		rv = getaddrinfo(hostname, NULL, &hints, &hostinfo);

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
static int ping_icmp_ipv6(const host_t *host, ping_t *ping) {
	int    icmp_socket;
	int    socket_errno = 0;
	int    icmp_use_shared = FALSE;
	icmp_waiter_t waiter;
	int    waiting = FALSE;

	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;

	struct sockaddr_in6 recvname;
	struct sockaddr_in6 fromname;
	char   socket_reply[BUFSIZE];
	int    retry_count;
	const char *cacti_msg = icmp6_payload;
	size_t msg_len;
	int    packet_len;
	socklen_t    fromlen;
	ssize_t    return_code;
	fd_set socket_fds;
	int    result;

	static   unsigned int seq = 0;

	struct   icmp6_hdr *icmp6;
	unsigned char  *packet;
	uint16_t our_id;
	uint16_t our_seq;
	int      icmp_dgram;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering ICMPv6 Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering ICMPv6 Ping", host->id));
	}

	result      = HOST_DOWN;
	packet      = NULL;
	icmp_socket = -1;
	retry_count = 0;
	msg_len     = strlen(cacti_msg);

	/* net.ipv4.ping_group_range governs IPPROTO_ICMPV6 datagram sockets as
	 * well, so the unprivileged path is worth trying here too.  The kernel
	 * rewrites the echo id on such a socket, which the reply match below
	 * accounts for. */
	icmp_dgram  = FALSE;
	icmp_socket = icmp_open_socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);

	if (icmp_socket != -1) {
		icmp_dgram = TRUE;
	} else if (icmp6_shared.fd != -1) {
		icmp_socket     = icmp6_shared.fd;
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

	icmp6->icmp6_type  = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code  = 0;
	icmp6->icmp6_id    = htons(our_id);
	icmp6->icmp6_seq   = htons(our_seq);
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
	total_time  = 0;
	begin_time  = get_time_as_double();

	if (icmp_use_shared) {
		memset(&waiter, 0, sizeof(waiter));
		waiter.shared = &icmp6_shared;
		waiter.family = AF_INET6;
		waiter.id     = htons(our_id);
		waiter.seq    = htons(our_seq);
		waiter.peer6  = fromname.sin6_addr;
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
					SPINE_LOG(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
				}

				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Device is Alive");
				snprintf(ping->ping_status, 50, "%.5f", total_time);

				result = HOST_UP;
				goto cleanup;
			}

			retry_count++;
			continue;
		}

		/* decrement the timeout value by the total time */
		timeout.tv_sec  = rint((host_timeout - total_time) / 1000);
		timeout.tv_usec = ((int) (host_timeout - total_time) % 1000) * 1000;

		/* set the socket send and receive timeout */
		setsockopt(icmp_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
		setsockopt(icmp_socket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

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
		FD_SET(icmp_socket,&socket_fds);
		return_code = select(icmp_socket + 1, &socket_fds, NULL, NULL, &timeout);

		/* record end time */
		end_time = get_time_as_double();

		/* calculate total time */
		total_time = (end_time - begin_time) * one_thousand;

		if ((return_code > 0) && (total_time < host_timeout)) {
			fromlen     = sizeof(recvname);
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
					SPINE_LOG(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
				} else {
					SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMPv6 Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
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

/*! \fn int ping_udp(const host_t *host, ping_t *ping)
 *  \brief ping a host using an UDP datagram
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using UDP.  The UDP datagram contains a marker
 *  to the "Cacti" application so that firewall's can be configured to allow.
 *  It will modify the ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
static int ping_down(ping_t *ping, const char *message) {
	snprintf(ping->ping_status, 50, "down");
	strncopy(ping->ping_response, message, SMALL_BUFSIZE);
	return HOST_DOWN;
}

/* UDP reachability is established by the existing ICMP port-error contract;
 * receiving an application datagram alone does not establish that result. */
static int ping_udp_response(int fd, double deadline) {
	char response[BUFSIZE];
	for (;;) {
		int ready = spine_wait_readable(fd, deadline);
		if (ready <= 0) return ready;
		ssize_t received = recv(fd, response, sizeof(response), 0);
		if (received >= 0) continue;
		if (errno == EHOSTUNREACH || errno == ECONNRESET || errno == ECONNREFUSED) return 1;
		if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) return -1;
	}
}

int ping_udp(const host_t *host, ping_t *ping) {
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: Entering UDP Ping", host->id));
	if (host->hostname[0] == '\0') return ping_down(ping, "UDP: Destination address invalid or unable to create socket");
	struct sockaddr_in servername = {0};
	if (!init_sockaddr(&servername, host->hostname, host->availability.port)) return ping_down(ping, "UDP: Destination hostname invalid");
	if (host->availability.timeout <= 0 || host->availability.retries < 0) return ping_down(ping, "UDP: Ping timed out");
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) return ping_down(ping, "UDP: Destination address invalid or unable to create socket");
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
		connect(fd, (struct sockaddr *)&servername, sizeof(servername)) < 0) {
		close(fd);
		return ping_down(ping, "UDP: Cannot connect to host");
	}
	static const char request[] = "cacti-monitoring-system";
	double begin = spine_monotonic_time();
	for (unsigned int attempt = 0; ; attempt++) {
		double deadline = spine_monotonic_time() + (double)host->availability.timeout / 1000;
		ssize_t sent;
		do {
			sent = send(fd, request, sizeof(request) - 1, 0);
		} while (sent < 0 && errno == EINTR && spine_monotonic_time() < deadline);
		int result = sent == (ssize_t)(sizeof(request) - 1) ? ping_udp_response(fd, deadline) : -1;
		double elapsed = (spine_monotonic_time() - begin) * 1000;
		if (result > 0) {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] INFO: UDP Device Alive, Try Count:%u, Time:%.4f ms", host->id, attempt + 1, elapsed));
			strncopy(ping->ping_response, "UDP: Device is Alive", SMALL_BUFSIZE);
			snprintf(ping->ping_status, 50, "%.5f", elapsed);
			close(fd);
			return HOST_UP;
		}
		if (result < 0 || attempt >= (unsigned int)host->availability.retries) {
			close(fd);
			return ping_down(ping, result < 0 ? "UDP: Device is Down" : "UDP: Ping timed out");
		}
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: UDP Timeout, Try Count:%u, Time:%.4f ms", host->id, attempt + 1, elapsed));
	}
}


/*! \fn int ping_tcp(const host_t *host, ping_t *ping)
 *  \brief ping a host using an TCP syn
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using TCP.  The TCP socket contains a marker
 *  to the "Cacti" application so that firewall's can be configured to allow.
 *  It will modify the ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
/* Each retry owns a new nonblocking socket; a failed connect socket must not
 * be reused. SO_ERROR distinguishes completion from refused/timed-out peers. */
static int ping_tcp_complete(int fd, double deadline) {
	int ready = spine_wait_writable(fd, deadline);
	if (ready <= 0) return ready == 0 ? ETIMEDOUT : errno;
	int error = 0;
	socklen_t length = sizeof(error);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0) return errno;
	return error;
}

static int ping_tcp_attempt(int fd, const struct sockaddr_in *address, double deadline) {
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return errno;
	if (connect(fd, (const struct sockaddr *)address, sizeof(*address)) == 0) return 0;
	int error = errno;
	if (error != EINPROGRESS && error != EINTR) return error;
	return ping_tcp_complete(fd, deadline);
}

static int ping_tcp_connect(const struct sockaddr_in *address, double deadline) {
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) return errno;
	int error = ping_tcp_attempt(fd, address, deadline);
	close(fd);
	return error;
}

int ping_tcp(const host_t *host, ping_t *ping) {
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: Entering TCP Ping", host->id));
	if (host->hostname[0] == '\0') return ping_down(ping, "TCP: Destination address invalid or unable to create socket");
	struct sockaddr_in address = {0};
	if (!init_sockaddr(&address, host->hostname, host->availability.port)) return ping_down(ping, "TCP: Destination hostname invalid");
	if (host->availability.timeout <= 0 || host->availability.retries < 0) return ping_down(ping, "TCP: Cannot connect to host");
	double begin = spine_monotonic_time();
	for (unsigned int attempt = 0; ; attempt++) {
		double deadline = spine_monotonic_time() + (double)host->availability.timeout / 1000;
		int error = ping_tcp_connect(&address, deadline);
		if (error == 0 || (error == ECONNREFUSED && host->availability.ping_method == PING_TCP_CLOSED)) {
			double elapsed = (spine_monotonic_time() - begin) * 1000;
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] INFO: TCP Device Alive, Try Count:%u, Time:%.4f ms", host->id, attempt + 1, elapsed));
			strncopy(ping->ping_response, "TCP: Device is Alive", SMALL_BUFSIZE);
			snprintf(ping->ping_status, 50, "%.5f", elapsed);
			return HOST_UP;
		}
		/* Cygwin historically makes one attempt only. */
		#if defined(__CYGWIN__)
		return ping_down(ping, "TCP: Cannot connect to host");
		#else
		if (attempt >= (unsigned int)host->availability.retries) return ping_down(ping, "TCP: Cannot connect to host");
		#endif
	}
}

/*! \fn int get_address_type(host_t *host)
 *  \brief determines using getaddrinfo the iptype and returns the iptype
 *
 *  \return 1 - IPv4, 2 - IPv6, 0 - Unknown
 */
int get_address_type(host_t *host) {
	struct addrinfo hints;
	struct addrinfo *res_list;
	char addrstr[255];
	const void *ptr = NULL;
	int addr_found = FALSE;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags    = AI_CANONNAME | AI_ADDRCONFIG;
	int error;

	if ((error = getaddrinfo(host->hostname, NULL, &hints, &res_list)) != 0) {
		SPINE_LOG(("WARNING: Unable to determine address info for %s (%s)", host->hostname, gai_strerror(error)));
		return SPINE_NONE;
	}

	for (struct addrinfo *res = res_list; res != NULL; res = res->ai_next) {
		inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

		switch(res->ai_family) {
			case AF_INET:
				ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
				addr_found = TRUE;
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
				addr_found = TRUE;
				break;
			default:
				continue;
		}

		inet_ntop(res->ai_family, ptr, addrstr, 100);

		SPINE_LOG_HIGH(("Device[%d] IPv%d address %s (%s)", host->id, res->ai_family == PF_INET6 ? 6:4, addrstr, res->ai_canonname));

		if (res->ai_family != PF_INET6) {
			freeaddrinfo(res_list);

			return SPINE_IPV4;
		}
	}

	freeaddrinfo(res_list);

	if (addr_found) {
		return SPINE_IPV6;
	} else {
		return SPINE_NONE;
	}
}

/*! \fn int init_sockaddr(struct sockaddr_in *name, const char *hostname, int port)
 *  \brief converts a hostname to an internet address
 *
 *  \return TRUE if successful, FALSE otherwise.
 *
 */
int init_sockaddr(struct sockaddr_in *name, const char *hostname, int port) {
	if (port < 0 || port > 65535) return FALSE;
	struct addrinfo hints = {0};
	struct addrinfo *hostinfo = NULL;
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
	for (int attempt = 0; ; attempt++) {
		int status = getaddrinfo(hostname, NULL, &hints, &hostinfo);
		if (status == 0) break;
		if (status == EAI_AGAIN && attempt < 3) {
			SPINE_LOG(("WARNING: Temporary DNS error for host %s (%s), retrying", hostname, gai_strerror(status)));
			spine_sleep_usec(50000);
			continue;
		}
		SPINE_LOG(("WARNING: Error resolving host %s (%s)", hostname, gai_strerror(status)));
		return FALSE;
	}
	if (hostinfo == NULL) {
		SPINE_LOG(("WARNING: Unknown host %s", hostname));
		return FALSE;
	}
	name->sin_family = AF_INET;
	name->sin_addr = ((struct sockaddr_in *)hostinfo->ai_addr)->sin_addr;
	name->sin_port = htons((unsigned short)port);
	freeaddrinfo(hostinfo);
	return TRUE;
}

/*! \brief Parse a device hostname with an optional transport and port. */
name_t *get_namebyhost(const char *hostname, name_t *name) {
	if (name == NULL) {
		name = calloc(1, sizeof(*name));
		if (name == NULL) die("ERROR: Fatal malloc error: ping.c get_namebyhost->name");
	}
	/* IPv6 transport addresses are passed intact to the address resolver. */
	if (strchr(hostname, '[') != NULL || strstr(hostname, "::") != NULL || char_count(hostname, ':') > 2) {
		strncopy(name->hostname, hostname, sizeof(name->hostname));
		return name;
	}
	char *copy = strdup(hostname);
	if (copy == NULL) die("ERROR: Fatal malloc error: ping.c get_namebyhost->stack");
	char *saveptr = NULL;
	const char *token = strtok_r(copy, ":", &saveptr);
	static const char *const methods[] = {"TCP", "UDP", "TCP6", "UDP6"};
	if (token != NULL) {
		for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
			if (strcasecmp(token, methods[i]) == 0) {
				name->method = (int)i + 1;
				token = strtok_r(NULL, ":", &saveptr);
				break;
			}
		}
	}
	strncopy(name->hostname, token != NULL ? token : hostname, sizeof(name->hostname));
	token = strtok_r(NULL, ":", &saveptr);
	if (token != NULL) name->port = atoi(token);
	free(copy);
	return name;
}

/*! \fn unsigned short int get_checksum(void* buf, int len)
 *  \brief calculates a 16bit checksum of a packet buffer
 *  \param buf the input buffer to calculate the checksum of
 *  \param len the size of the input buffer
 *
 *  \return 16bit checksum of an input buffer of size len.
 *
 */
unsigned short int get_checksum(void* buf, int len) {
	int      nleft = len;
	int32_t  sum   = 0;
	unsigned short int answer;
	unsigned short int* w = (unsigned short int*)buf;
	unsigned short int odd_byte = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
   		*(unsigned char*)(&odd_byte) = *(unsigned char*)w;
   		sum += odd_byte;
	}

	sum    = (sum >> 16) + (sum & 0xffff);
	sum   += (sum >> 16);
	answer = (unsigned short int)((unsigned int)~sum & 0xffff); /* checksum truncation is intentional */

	return answer;
}

static bool host_requires_snmp(const host_t *host) {
	return host->snmp.profile.community[0] != '\0' || host->snmp.profile.version >= 3;
}

static void host_failure_message(host_t *host, const ping_t *ping, int method) {
	switch (method) {
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP_AND_PING:
			if (host_requires_snmp(host)) {
				snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s, %s", ping->snmp_response, ping->ping_response);
			} else {
				snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
			}
			break;
		case AVAIL_SNMP:
			snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", host_requires_snmp(host) ? ping->snmp_response : "Device does not require SNMP");
			break;
		default:
			snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
	}
}

static bool host_failure_transition(host_t *host, const char *date) {
	switch (host->state.status) {
		case HOST_UP:
			host->state.status_event_count++;
			if (host->state.status_event_count >= set.availability.ping_failure_count) {
				host->state.status = HOST_DOWN;
				if (set.availability.ping_failure_count == 1) snprintf(host->state.status_fail_date, sizeof(host->state.status_fail_date), "%s", date);
				return TRUE;
			}
			if (host->state.status_event_count == 1) snprintf(host->state.status_fail_date, sizeof(host->state.status_fail_date), "%s", date);
			return FALSE;
		case HOST_RECOVERING:
			host->state.status_event_count = 1;
			host->state.status = HOST_DOWN;
			return FALSE;
		case HOST_UNKNOWN:
			host->state.status = HOST_DOWN;
			host->state.status_event_count = 0;
			return FALSE;
		default:
			host->state.status_event_count++;
			return FALSE;
	}
}

static bool host_recovery_transition(host_t *host, const char *date) {
	if (host->state.status != HOST_DOWN && host->state.status != HOST_RECOVERING) {
		host->state.status = HOST_UP;
		host->state.status_event_count = 0;
		return FALSE;
	}
	if (host->state.status == HOST_DOWN) {
		host->state.status = HOST_RECOVERING;
		host->state.status_event_count = 1;
	} else {
		host->state.status_event_count++;
	}
	if (host->state.status_event_count >= set.availability.ping_recovery_count) {
		host->state.status = HOST_UP;
		if (set.availability.ping_recovery_count == 1) snprintf(host->state.status_rec_date, sizeof(host->state.status_rec_date), "%s", date);
		host->state.status_event_count = 0;
		return TRUE;
	}
	if (host->state.status_event_count == 1) snprintf(host->state.status_rec_date, sizeof(host->state.status_rec_date), "%s", date);
	return FALSE;
}

static double host_response_time(const host_t *host, const ping_t *ping, int method) {
	switch (method) {
		case AVAIL_SNMP_AND_PING:
			return host_requires_snmp(host) ? (atof(ping->snmp_status) + atof(ping->ping_status)) / 2 : atof(ping->ping_status);
		case AVAIL_SNMP:
			return host_requires_snmp(host) ? atof(ping->snmp_status) : 0.0;
		case AVAIL_NONE:
			return 0.0;
		default:
			return atof(ping->ping_status);
	}
}

static void host_response_statistics(host_t *host, double ping_time) {
	host->statistics.cur_time = ping_time;
	if (ping_time > host->statistics.max_time) host->statistics.max_time = ping_time;
	if (ping_time < host->statistics.min_time) host->statistics.min_time = ping_time;
	host->statistics.avg_time = (((host->statistics.total_polls - 1 - host->statistics.failed_polls) * host->statistics.avg_time) + ping_time) / (host->statistics.total_polls - host->statistics.failed_polls);
}

static void log_host_availability(const host_t *host, const ping_t *ping, int method) {
	if (set.logging.log_level < POLLER_VERBOSITY_HIGH) return;
	bool up = host->state.status == HOST_UP || host->state.status == HOST_RECOVERING;
	if (method == AVAIL_SNMP_AND_PING || (method == AVAIL_SNMP_OR_PING && up)) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING Result: %s", host->id, ping->ping_response));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
	} else if (method == AVAIL_SNMP) {
		const char *message = up && !host_requires_snmp(host) ? "Device does not require SNMP" : ping->snmp_response;
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] SNMP Result: %s", host->id, message));
	} else if (method == AVAIL_NONE) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] No Device Availability Method Selected", host->id));
	} else if (up) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING: Result %s", host->id, ping->ping_response));
	} else {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING Result: %s", host->id, ping->ping_response));
	}
}

/*! Update availability statistics and apply failure/recovery thresholds. */
void update_host_status(int status, host_t *host, const ping_t *ping, int availability_method) {
	char current_date[40];
	snprintf(current_date, sizeof(current_date), "%lu", time(NULL));
	bool issue_log_message;
	host->statistics.total_polls++;
	if (status == HOST_DOWN) {
		host->statistics.failed_polls++;
		host_failure_message(host, ping, availability_method);
		issue_log_message = host_failure_transition(host, current_date);
	} else {
		host_response_statistics(host, host_response_time(host, ping, availability_method));
		issue_log_message = host_recovery_transition(host, current_date);
	}
	host->statistics.availability = 100.0 * (host->statistics.total_polls - host->statistics.failed_polls) / host->statistics.total_polls;
	log_host_availability(host, ping, availability_method);
	if (!issue_log_message) return;
	if (host->state.status == HOST_DOWN) {
		SPINE_LOG(("Device[%i] Hostname[%s] ERROR: HOST EVENT: Device is DOWN Message: %s", host->id, host->hostname, host->state.status_last_error));
	} else {
		SPINE_LOG(("Device[%i] Hostname[%s] NOTICE: HOST EVENT: Device Returned from DOWN State", host->id, host->hostname));
	}
}
