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

#include "internal/common.h"
#include "app/spine.h"
#include "ping_internal.h"
#include <fcntl.h>

/*! \fn static void ping_wait_left(double deadline, struct timeval *timeout)
 *  \brief converts the time left before a monotonic deadline to a timeval
 *
 *  Each ICMP attempt owns a deadline of its own.  Measuring from the first
 *  attempt left every retry with an already spent budget, so one lost packet
 *  marked the device down, and rint(ms / 1000) plus the millisecond remainder
 *  stretched a 1500 ms timeout to 2.5 s.
 */
void ping_wait_left(double deadline, struct timeval *timeout) {
	double remaining = deadline - spine_monotonic_time();

	if (remaining < 0) {
		remaining = 0;
	}

	timeout->tv_sec = (time_t) remaining;
	timeout->tv_usec = (suseconds_t) ((remaining - (double) timeout->tv_sec) * 1000000);
}

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
	size_t ihl;
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
const char icmp6_payload[] = "cacti-monitoring-system";

/*! \fn static int icmp6_reply_matches(const unsigned char *reply, ssize_t len, uint16_t id, uint16_t seq, int check_id)
 *  \brief decides whether an ICMPv6 message answers our echo request
 *
 *  ICMPv6 sockets deliver the message without the IPv6 header.  id and seq
 *  are in network order, as written into the request.  A datagram socket
 *  rewrites the echo id, so its caller passes check_id FALSE.
 */
int icmp6_reply_matches(const unsigned char *reply, ssize_t len, uint16_t id, uint16_t seq, int check_id) {
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
/* A reader empties the queue in batches read without LOCK_ICMP held, so a
 * flood delays neither registrations nor the waiters being woken.  The bound
 * on one pass keeps the reader's own deadline check running.  Matching needs
 * only the IP header, the ICMP header and the payload marker, so each slot
 * keeps the first ICMP_SHARED_SNAPLEN bytes.  The queue itself is sized for
 * every poller thread rather than one. */
#define ICMP_SHARED_DRAIN_MAX 1024
#define ICMP_SHARED_BATCH 64
#define ICMP_SHARED_SNAPLEN 128
#define ICMP_SHARED_RCVBUF (4 * 1024 * 1024)

#if defined(__linux__)
#ifndef SOL_RAW
#define SOL_RAW 255
#endif
#ifndef ICMP_FILTER
#define ICMP_FILTER 1
#endif
#endif

icmp_shared_t icmp_shared = {-1, FALSE};
#ifdef SPINE_HAVE_ICMPV6
icmp_shared_t icmp6_shared = {-1, FALSE};
#endif
static icmp_waiter_t *icmp_waiters = NULL;

/*! \fn static int icmp_open_socket(int family, int type, int protocol)
 *  \brief opens an ICMP socket that PHP and script children cannot inherit
 *
 *  Poller threads posix_spawn() scripts while others ping, so the flag is set
 *  atomically where SOCK_CLOEXEC exists; elsewhere fcntl() narrows the window.
 */
int icmp_open_socket(int family, int type, int protocol) {
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

void icmp_shared_register(icmp_waiter_t *waiter) {
	pthread_cond_init(&waiter->wake, NULL);

	thread_mutex_lock(LOCK_ICMP);
	waiter->answered = FALSE;
	waiter->sleeping = FALSE;
	waiter->next = icmp_waiters;
	icmp_waiters = waiter;
	thread_mutex_unlock(LOCK_ICMP);
}

void icmp_shared_unregister(icmp_waiter_t *waiter) {
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

			if (memcmp(source->sin6_addr.s6_addr, waiter->peer6.s6_addr, sizeof(waiter->peer6.s6_addr)) != 0 ||
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
int icmp_shared_await(icmp_waiter_t *waiter, double deadline) {
	icmp_shared_t *shared = waiter->shared;
	unsigned char replies[ICMP_SHARED_BATCH][ICMP_SHARED_SNAPLEN];
	struct sockaddr_storage sources[ICMP_SHARED_BATCH];
	ssize_t lengths[ICMP_SHARED_BATCH];
	socklen_t fromlen;
	ssize_t received;
	struct timeval wait;
	struct timespec until;
	fd_set fds;
	double now;
	double remaining;
	int readable;
	int drained;
	int count;
	int slot;
	int answered;

	until.tv_sec = (time_t) deadline;
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

		remaining = deadline - now;
		wait.tv_sec = (time_t) remaining;
		wait.tv_usec = (suseconds_t) ((remaining - (double) wait.tv_sec) * 1000000.0);

		FD_ZERO(&fds);
		FD_SET(shared->fd, &fds);
		readable = select(shared->fd + 1, &fds, NULL, NULL, &wait) > 0;

		/* Empty the queue: under a flood, one reply per pass falls behind
		 * and the kernel drops the replies that matter. */
		for (drained = 0; readable && drained < ICMP_SHARED_DRAIN_MAX; drained += count) {
			for (count = 0; count < ICMP_SHARED_BATCH;) {
				fromlen = sizeof(sources[count]);
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
