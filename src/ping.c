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
#include "platform/platform_socket.h"
#include "platform/platform_icmp.h"
#ifdef _WIN32
#include <icmpapi.h>
#else
#  include <fcntl.h>
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <sys/types.h>
#  include <netinet/ip.h>
#  include <netinet/ip_icmp.h>
#  include <netinet/icmp6.h>
#  include <stddef.h>
#endif

#ifndef _WIN32
/* Set FD_CLOEXEC on a raw descriptor. The raw ICMP sockets are
 * long-lived and occasionally leak into nft_popen'd poll scripts
 * without this guard; the children should never see a privileged
 * ICMP fd they did not open. */
static void spine_fd_set_cloexec(int fd) {
	if (fd < 0) return;
	int fl = fcntl(fd, F_GETFD);
	if (fl >= 0) {
		(void) fcntl(fd, F_SETFD, fl | FD_CLOEXEC);
	}
}
#endif

#if defined(__linux__)
#  include <sys/random.h>
#endif

#if defined(__linux__) && defined(HAVE_LIBCAP)
#  include <sys/capability.h>
#endif

#include "ping_wire.h"

/* XORed into every ICMP echo id so a same-PID spine restart does not
 * reuse the previous run's identifiers. Set once at program start. */
static uint16_t icmp_id_mask = 0;

/* ICMP sequence counters need 16-bit wraparound semantics (the on-wire
 * field is 16 bits) and lock-free concurrent increment across poller
 * threads. Prefer C11 _Atomic with memory_order_relaxed; fall back to
 * the GCC/Clang __atomic builtin on unsigned int when <stdatomic.h>
 * isn't available. The fallback keeps the old wider counter and relies
 * on the existing uint16_t cast at the call sites. */
#if !defined(__STDC_NO_ATOMICS__) && defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#  include <stdatomic.h>
#  define SPINE_PING_SEQ_T   _Atomic uint16_t
#  define SPINE_PING_SEQ_NEXT(s) atomic_fetch_add_explicit(&(s), (uint16_t)1, memory_order_relaxed)
#else
#  define SPINE_PING_SEQ_T   unsigned int
#  define SPINE_PING_SEQ_NEXT(s) ((uint16_t)__atomic_fetch_add(&(s), 1, __ATOMIC_RELAXED))
#endif

void ping_init(void) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__sun) || defined(__sun__)
	/* arc4random is in libc on the BSDs (Free/Open/Net/DragonFly), macOS,
	 * and illumos/Solaris 11.4+. */
	icmp_id_mask = (uint16_t)(arc4random() & 0xFFFF);
#elif defined(__linux__)
	unsigned int seed = 0;
	if (getrandom(&seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) {
		/* Log the degraded path so operators can see when the kernel
		 * entropy pool is uninitialized (early boot) or getrandom is
		 * filtered by seccomp. icmp_id_mask is not security-critical,
		 * but silent weak entropy is a common source of surprise. */
		SPINE_LOG_DEBUG(("DEBUG: PING: getrandom() failed (errno=%d); using time^pid seed", errno));
		seed = (unsigned int)time(NULL) ^ (unsigned int)getpid();
	}
	icmp_id_mask = (uint16_t)(seed & 0xFFFF);
#else
	/* AIX and other Unixes without arc4random: try /dev/urandom, fall back
	 * to time^pid. The id only needs to be hard to guess across spine
	 * restarts, not cryptographically random. */
	unsigned int seed = 0;
	FILE *urand = fopen("/dev/urandom", "rb");
	if (urand != NULL) {
		size_t n = fread(&seed, sizeof(seed), 1, urand);
		fclose(urand);
		if (n == 1) {
			icmp_id_mask = (uint16_t)(seed & 0xFFFF);
			return;
		}
	}
	SPINE_LOG_DEBUG(("DEBUG: PING: /dev/urandom unavailable; using time^pid seed"));
	icmp_id_mask = (uint16_t)(((unsigned int)time(NULL) ^ (unsigned int)getpid()) & 0xFFFF);
#endif
}

/* Populate the payload signature that rides inside every echo we send.
 * Made public-ish so unit tests can compose identical packets without
 * threading concerns. */
static void build_ping_payload(spine_ping_payload_t *p) {
	struct timeval tv;
	p->magic = SPINE_PING_MAGIC;
	p->pid_mask = (uint32_t) icmp_id_mask;
	if (gettimeofday(&tv, NULL) == 0) {
		p->timestamp_us = (uint32_t) tv.tv_sec;
	} else {
		p->timestamp_us = 0;
	}
}

/* Validator lives in src/ping_validate.c so unit tests can link just
 * that object without the full spine runtime dependency chain. */
extern int spine_ping_validate_payload(const void *buf, size_t len,
                                       uint32_t expect_pid_mask);

#ifndef _WIN32
/* Implemented in src/ping_ipv6_scope.c so the unit test can link
 * against it without the full spine runtime. */
extern int spine_apply_ipv6_scope_id(struct sockaddr_in6 *sin6, const char *ifname);
#endif

/* Drop Linux capabilities after we have opened the raw sockets we
 * need. With libcap this shrinks the blast radius of a later exploit;
 * without libcap (or on non-Linux) it is a no-op. NOTE: spine opens
 * its raw sockets on demand per ping, so the current invocation is
 * guarded by a one-shot flag and logs only. A future refactor that
 * opens sockets once at startup should call this unconditionally. */
#if defined(__GNUC__) || defined(__clang__)
#  define SPINE_MAYBE_UNUSED __attribute__((unused))
#else
#  define SPINE_MAYBE_UNUSED
#endif

#if defined(__linux__) && defined(HAVE_LIBCAP)
SPINE_MAYBE_UNUSED static void spine_drop_caps_once(void) {
	static int dropped = 0;
	cap_t empty;
	if (dropped) return;
	dropped = 1;
	empty = cap_init();
	if (empty == NULL) return;
	if (cap_set_proc(empty) == 0) {
		SPINE_LOG_DEBUG(("DEBUG: Dropped all capabilities after raw socket open"));
	}
	cap_free(empty);
}
#else
SPINE_MAYBE_UNUSED static void spine_drop_caps_once(void) {
	/* no-op: libcap not available, non-Linux, or spine uses per-call
	 * socket lifetime and cannot drop CAP_NET_RAW without breaking
	 * subsequent pings. Kept as a stable hook for a future refactor
	 * that opens a single persistent raw socket at startup. */
}
#endif

/* Heuristic: host string is a numeric IP literal if it contains ':'
 * (IPv6) or is made up entirely of digits and dots (IPv4). We pass
 * AI_NUMERICHOST when this is the case so getaddrinfo() cannot be
 * steered into DNS lookups by a hostile hostname that looks numeric.
 * Conservative -- if in doubt, do not set the flag. */
static int hostname_is_numeric(const char *hostname) {
	if (hostname == NULL || hostname[0] == '\0') {
		return 0;
	}
	if (strchr(hostname, ':') != NULL) {
		return 1;
	}
	{
		size_t n = strlen(hostname);
		if (strspn(hostname, "0123456789.") == n && strchr(hostname, '.') != NULL) {
			return 1;
		}
	}
	return 0;
}

static int resolve_sockaddr(struct sockaddr_storage *address, socklen_t *address_len, int family, const char *hostname, unsigned short int port) {
	struct addrinfo hints, *hostinfo;
	char service[16];
	int rv, retry_count;

	memset(&hints, 0, sizeof(hints));
	memset(address, 0, sizeof(*address));

	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;

	/* Skip the DNS resolver path entirely for numeric literals. Saves
	 * an unbounded wait on a misconfigured resolv.conf and prevents a
	 * crafted hostname that parses as an address from triggering DNS. */
	if (hostname_is_numeric(hostname)) {
		hints.ai_flags |= AI_NUMERICHOST;
	}

	snprintf(service, sizeof(service), "%u", port);

	retry_count = 0;
	hostinfo = NULL;

	while (TRUE) {
		rv = getaddrinfo(hostname, service, &hints, &hostinfo);

		if (rv == 0) {
			break;
		}

		switch (rv) {
			case EAI_AGAIN:
				if (retry_count < 3) {
					SPINE_LOG(("WARNING: EAGAIN received resolving after 3 retryies for host %s (%s)", hostname, gai_strerror(rv)));
					if (hostinfo != NULL) {
						freeaddrinfo(hostinfo);
						hostinfo = NULL;
					}

					retry_count++;
					spine_platform_sleep_us(50000);
					continue;
				} else {
					SPINE_LOG(("WARNING: Error resolving after 3 retryies for host %s (%s)", hostname, gai_strerror(rv)));
					if (hostinfo != NULL) {
						freeaddrinfo(hostinfo);
					}
					return FALSE;
				}
			case EAI_FAIL:
				SPINE_LOG(("WARNING: DNS Server reported permanent error for host %s (%s)", hostname, gai_strerror(rv)));
				if (hostinfo != NULL) {
					freeaddrinfo(hostinfo);
				}
				return FALSE;
			case EAI_MEMORY:
				SPINE_LOG(("WARNING: Out of memory trying to resolve host %s (%s)", hostname, gai_strerror(rv)));
				if (hostinfo != NULL) {
					freeaddrinfo(hostinfo);
				}
				return FALSE;
			default:
				SPINE_LOG(("WARNING: Unknown error while resolving host %s (%s)", hostname, gai_strerror(rv)));
				if (hostinfo != NULL) {
					freeaddrinfo(hostinfo);
				}
				return FALSE;
		}
	}

	if (hostinfo == NULL) {
		SPINE_LOG(("WARNING: Unknown host %s", hostname));
		return FALSE;
	}

	memcpy(address, hostinfo->ai_addr, hostinfo->ai_addrlen);
	*address_len = (socklen_t) hostinfo->ai_addrlen;

	freeaddrinfo(hostinfo);
	return TRUE;
}

#ifdef _WIN32
static int ping_icmp_windows(host_t *host, ping_t *ping, int family) {
	struct sockaddr_storage destination;
	socklen_t destination_len;
	int retry_count;
	DWORD timeout_ms;
	static const char payload[] = "cacti-monitoring-system";

	if (strlen(host->hostname) == 0) {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Destination address not specified");
		snprintf(ping->ping_status, 50, "down");
		return HOST_DOWN;
	}

	if (!resolve_sockaddr(&destination, &destination_len, family, host->hostname, 0)) {
		snprintf(ping->ping_response, SMALL_BUFSIZE, family == AF_INET6 ? "ICMPv6: Destination hostname invalid" : "ICMP: Destination hostname invalid");
		snprintf(ping->ping_status, 50, "down");
		return HOST_DOWN;
	}

	timeout_ms = host->ping_timeout > 0 ? (DWORD) host->ping_timeout : 1000;
	if (timeout_ms == 0) {
		timeout_ms = 1000;
	}

	for (retry_count = 0; retry_count <= host->ping_retries; retry_count++) {
		double begin_time;
		double end_time;
		double total_time;
		DWORD status = IP_REQ_TIMED_OUT;
		DWORD round_trip_time = 0;
		HANDLE icmp_handle;
		void *reply_buffer = NULL;
		DWORD reply_size = 0;
		DWORD replies = 0;

		begin_time = get_time_as_double();

		if (family == AF_INET6) {
			struct sockaddr_in6 source_address;
			struct sockaddr_in6 *target_address;
			PICMPV6_ECHO_REPLY reply;

			icmp_handle = Icmp6CreateFile();
			if (icmp_handle == INVALID_HANDLE_VALUE) {
				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Ping handle open failed");
				snprintf(ping->ping_status, 50, "down");
				return HOST_DOWN;
			}

			memset(&source_address, 0, sizeof(source_address));
			source_address.sin6_family = AF_INET6;

			target_address = (struct sockaddr_in6 *) &destination;
			reply_size = (DWORD) (sizeof(ICMPV6_ECHO_REPLY) + sizeof(payload) + 32U);
			reply_buffer = calloc(1, reply_size);

			if (reply_buffer == NULL) {
				IcmpCloseHandle(icmp_handle);
				die("ERROR: Fatal calloc error: ping.c ping_icmp_windows reply_buffer");
			}

			replies = Icmp6SendEcho2(
				icmp_handle,
				NULL,
				NULL,
				NULL,
				&source_address,
				target_address,
				payload,
				(WORD) strlen(payload),
				NULL,
				reply_buffer,
				reply_size,
				timeout_ms
			);

			if (replies > 0) {
				reply = (PICMPV6_ECHO_REPLY) reply_buffer;
				status = reply->Status;
				round_trip_time = reply->RoundTripTime;
			} else {
				status = GetLastError();
			}

			free(reply_buffer);
			IcmpCloseHandle(icmp_handle);
		} else {
			struct sockaddr_in *target_address;
			PICMP_ECHO_REPLY reply;

			icmp_handle = IcmpCreateFile();
			if (icmp_handle == INVALID_HANDLE_VALUE) {
				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Ping handle open failed");
				snprintf(ping->ping_status, 50, "down");
				return HOST_DOWN;
			}

			target_address = (struct sockaddr_in *) &destination;
			reply_size = (DWORD) (sizeof(ICMP_ECHO_REPLY) + sizeof(payload) + 32U);
			reply_buffer = calloc(1, reply_size);

			if (reply_buffer == NULL) {
				IcmpCloseHandle(icmp_handle);
				die("ERROR: Fatal calloc error: ping.c ping_icmp_windows reply_buffer");
			}

			replies = IcmpSendEcho(
				icmp_handle,
				target_address->sin_addr.s_addr,
				payload,
				(WORD) strlen(payload),
				NULL,
				reply_buffer,
				reply_size,
				timeout_ms
			);

			if (replies > 0) {
				reply = (PICMP_ECHO_REPLY) reply_buffer;
				status = reply->Status;
				round_trip_time = reply->RoundTripTime;
			} else {
				status = GetLastError();
			}

			free(reply_buffer);
			IcmpCloseHandle(icmp_handle);
		}

		end_time = get_time_as_double();
		total_time = (end_time - begin_time) * 1000.00;

		if (replies > 0 && status == IP_SUCCESS) {
			if (is_debug_device(host->id)) {
				SPINE_LOG(("Device[%i] INFO: %s Device Alive, Try Count:%i, Time:%.4f ms", host->id, family == AF_INET6 ? "ICMPv6" : "ICMP", retry_count + 1, round_trip_time > 0 ? (double) round_trip_time : total_time));
			} else {
				SPINE_LOG_MEDIUM(("Device[%i] INFO: %s Device Alive, Try Count:%i, Time:%.4f ms", host->id, family == AF_INET6 ? "ICMPv6" : "ICMP", retry_count + 1, round_trip_time > 0 ? (double) round_trip_time : total_time));
			}

			snprintf(ping->ping_response, SMALL_BUFSIZE, "%s: Device is Alive", family == AF_INET6 ? "ICMPv6" : "ICMP");
			snprintf(ping->ping_status, 50, "%.5f", round_trip_time > 0 ? (double) round_trip_time : total_time);
			return HOST_UP;
		}

		if (status != IP_REQ_TIMED_OUT && status != IP_DEST_HOST_UNREACHABLE && status != IP_DEST_NET_UNREACHABLE) {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "%s: Ping failed with status %lu", family == AF_INET6 ? "ICMPv6" : "ICMP", (unsigned long) status);
			snprintf(ping->ping_status, 50, "down");
			return HOST_DOWN;
		}

		#ifndef SOLAR_THREAD
		spine_platform_sleep_us(1000);
		#endif
	}

	snprintf(ping->ping_response, SMALL_BUFSIZE, "%s: Ping timed out", family == AF_INET6 ? "ICMPv6" : "ICMP");
	snprintf(ping->ping_status, 50, "down");
	return HOST_DOWN;
}
#else
static int ping_icmp_ipv6(host_t *host, ping_t *ping) {
	spine_socket_t icmp_socket;
	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;
	struct sockaddr_in6 recvname;
	struct sockaddr_in6 fromname;
	char socket_reply[BUFSIZE];
	int retry_count;
	int packet_len;
	socklen_t fromlen;
	ssize_t return_code;
	static SPINE_PING_SEQ_T seq = 0;
	struct icmp6_hdr *icmp6;
	struct icmp6_hdr *reply;
	unsigned char *packet;
	uint16_t our_id;
	uint16_t our_seq;
	int ret = HOST_DOWN;

	retry_count = 0;
	icmp_socket = (spine_socket_t)-1;
	while (TRUE) {
		if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
			thread_mutex_lock(LOCK_SETEUID);
			if (seteuid(0) == -1) {
				SPINE_LOG_DEBUG(("WARNING: Spine unable to obtain root privileges."));
			}
		}

		icmp_socket = spine_socket_open(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
		if (!spine_socket_is_valid(icmp_socket)) {
			spine_platform_sleep_us(500000);
			retry_count++;

			if (retry_count > 4) {
				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Ping unable to create ICMP Socket");
				snprintf(ping->ping_status, 50, "down");
				if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
					if (seteuid(getuid()) == -1) {
						SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
					}
					thread_mutex_unlock(LOCK_SETEUID);
				}

				return HOST_DOWN;
			}
		} else {
			break;
		}
	}

	if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
		if (seteuid(getuid()) == -1) {
			SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
		}
		thread_mutex_unlock(LOCK_SETEUID);
	}

	/* RFC 3542 / RFC 4443 hardening on the raw ICMPv6 socket.
	 * Each sockopt is best-effort -- failure is logged but not fatal,
	 * because older kernels and non-root sandboxes may reject them. */
	{
#ifdef ICMP6_FILTER
		struct icmp6_filter filter;
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
		if (setsockopt(icmp_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0) {
			SPINE_LOG_DEBUG(("DEBUG: ICMP6_FILTER not supported: %s", strerror(errno)));
		}
#endif
#ifdef IPV6_CHECKSUM
		{
			/* Kernel computes the ICMPv6 checksum at this offset on
			 * raw sockets. Required by RFC 3542 for correct delivery. */
			int cksum_offset = (int) offsetof(struct icmp6_hdr, icmp6_cksum);
			if (setsockopt(icmp_socket, IPPROTO_IPV6, IPV6_CHECKSUM, &cksum_offset, sizeof(cksum_offset)) < 0) {
				SPINE_LOG_DEBUG(("DEBUG: IPV6_CHECKSUM not supported: %s", strerror(errno)));
			}
		}
#endif
#ifdef IPV6_UNICAST_HOPS
		{
			int hops = 64;
			if (setsockopt(icmp_socket, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0) {
				SPINE_LOG_DEBUG(("DEBUG: IPV6_UNICAST_HOPS not supported: %s", strerror(errno)));
			}
		}
#endif
	}

	host_timeout = host->ping_timeout;
	packet_len = (int) sizeof(struct icmp6_hdr) + (int) sizeof(spine_ping_payload_t);

	if (!(packet = malloc(packet_len))) {
		die("ERROR: Fatal malloc error: ping.c ping_icmp_ipv6!");
	}
	memset(packet, 0, packet_len);
	memset(&fromname, 0, sizeof(fromname));
	memset(&recvname, 0, sizeof(recvname));

	our_id = (uint16_t)((spine_platform_process_id() & 0xFFFF) ^ icmp_id_mask);
	our_seq = (uint16_t) SPINE_PING_SEQ_NEXT(seq);

	icmp6 = (struct icmp6_hdr *) packet;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id   = htons(our_id);
	icmp6->icmp6_seq  = htons(our_seq);

	{
		spine_ping_payload_t sig;
		build_ping_payload(&sig);
		memcpy(packet + sizeof(struct icmp6_hdr), &sig, sizeof(sig));
	}

	if ((strlen(host->hostname) == 0) || !resolve_sockaddr((struct sockaddr_storage *) &fromname, &fromlen, AF_INET6, host->hostname, 7)) {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Destination hostname invalid");
		snprintf(ping->ping_status, 50, "down");
		ret = HOST_DOWN;
		goto cleanup;
	}

	/* Link-local destinations need a scope_id. Auto-detect when the
	 * kernel did not set one (it does not for numeric literals without
	 * a %zone suffix). Non-fatal if resolution fails -- caller gets
	 * the usual kernel error. */
	if (IN6_IS_ADDR_LINKLOCAL(&fromname.sin6_addr) && fromname.sin6_scope_id == 0) {
		if (spine_apply_ipv6_scope_id(&fromname, NULL) != 0) {
			SPINE_LOG_DEBUG(("DEBUG: Could not resolve IPv6 scope_id for link-local target"));
		}
	}

	snprintf(ping->ping_status, 50, "down");
	snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

	retry_count = 0;
	total_time  = 0;
	begin_time  = get_time_as_double();

	while (1) {
		if (retry_count > host->ping_retries) {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Ping timed out");
			snprintf(ping->ping_status, 50, "down");
			ret = HOST_DOWN;
			goto cleanup;
		}

		timeout.tv_sec  = rint((host_timeout - total_time) / 1000);
		timeout.tv_usec = ((int) (host_timeout - total_time) % 1000) * 1000;
		spine_socket_set_timeout(icmp_socket, &timeout);

		return_code = spine_socket_sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, fromlen);
		(void) return_code;

keep_listening_ipv6:
		if (!spine_socket_is_valid(icmp_socket)) {
			snprintf(ping->ping_status, 50, "down");
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: invalid socket");
			ret = HOST_DOWN;
			goto cleanup;
		}

		return_code = spine_socket_wait_readable(icmp_socket, &timeout);
		end_time = get_time_as_double();
		total_time = (end_time - begin_time) * one_thousand;

		if (return_code > 0 && total_time < host_timeout) {
			fromlen = sizeof(recvname);
			return_code = spine_socket_recvfrom(icmp_socket, socket_reply, BUFSIZE, 0, (struct sockaddr *) &recvname, &fromlen);

			if (return_code < 0) {
				if (spine_socket_error_is_interrupted(spine_socket_last_error())) {
					goto keep_listening_ipv6;
				}
			} else {
				/* Bounds-check before casting to struct. An undersized
				 * raw recv cannot legally be an ICMPv6 echo reply, but
				 * a hostile sender (or a kernel bug) could deliver one;
				 * treat it as noise and keep listening. */
				if ((size_t) return_code < sizeof(struct icmp6_hdr) + sizeof(spine_ping_payload_t)) {
					SPINE_LOG_DEBUG(("DEBUG: Discarding undersized ICMPv6 reply: %zd bytes", return_code));
					goto keep_listening_ipv6;
				}

				reply = (struct icmp6_hdr *) socket_reply;

				/* 1. Source must match the target we probed. The kernel
				 * does not verify this on AF_INET6 raw sockets. */
				if (memcmp(&fromname.sin6_addr, &recvname.sin6_addr, sizeof(struct in6_addr)) != 0) {
					SPINE_LOG_DEBUG(("DEBUG: Dropping ICMPv6 reply from unexpected source"));
					goto keep_listening_ipv6;
				}

				/* 2. Must be an echo reply with our id and seq. */
				if (reply->icmp6_type != ICMP6_ECHO_REPLY) {
					goto keep_listening_ipv6;
				}
				if (reply->icmp6_id != htons(our_id)) {
					SPINE_LOG_DEBUG(("DEBUG: Dropping ICMPv6 reply with foreign id"));
					goto keep_listening_ipv6;
				}
				if (reply->icmp6_seq != htons(our_seq)) {
					SPINE_LOG_DEBUG(("DEBUG: Dropping ICMPv6 reply with stale seq"));
					goto keep_listening_ipv6;
				}

				/* 3. Payload signature check (rejects unrelated traffic
				 * and cross-run leakage that happens to match id+seq). */
				if (!spine_ping_validate_payload(socket_reply + sizeof(struct icmp6_hdr),
				                                 (size_t) return_code - sizeof(struct icmp6_hdr),
				                                 (uint32_t) icmp_id_mask)) {
					SPINE_LOG_DEBUG(("DEBUG: Dropping ICMPv6 reply with invalid payload signature"));
					goto keep_listening_ipv6;
				}

				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMPv6: Device is Alive");
				snprintf(ping->ping_status, 50, "%.5f", total_time);
				ret = HOST_UP;
				goto cleanup;
			}
		}

		total_time = 0;
		retry_count++;
#ifndef SOLAR_THREAD
		spine_platform_sleep_us(1000);
#endif
	}

cleanup:
	SPINE_FREE(packet);
	if (spine_socket_is_valid(icmp_socket)) {
		spine_socket_close(icmp_socket);
	}
	return ret;
}
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
int ping_host(host_t *host, ping_t *ping) {
	int ping_result;
	int snmp_result;
	double snmp_start_time;
	double snmp_end_time;

	/* snmp pinging has been selected at a minimum */
	ping_result = 0;
	snmp_result = 0;

	/* icmp/tcp/udp ping test */
	if ((host->availability_method == AVAIL_SNMP_AND_PING) ||
		(host->availability_method == AVAIL_PING) ||
		(host->availability_method == AVAIL_SNMP_OR_PING)) {

		if (host->ping_method == PING_ICMP) {
			if (set.icmp_avail == FALSE) {
				SPINE_LOG(("Device[%i] DEBUG Falling back to UDP Ping Due to SetUID Issues", host->id));
				host->ping_method = PING_UDP;
			}
		}

		if (!strstr(host->hostname, "localhost")) {
			int address_type = get_address_type(host);

			if (address_type == SPINE_IPV4 || address_type == SPINE_IPV6) {
				if (host->ping_method == PING_ICMP) {
					ping_result = ping_icmp(host, ping);
				} else if (host->ping_method == PING_UDP) {
					ping_result = ping_udp(host, ping);
				} else if (host->ping_method == PING_TCP || host->ping_method == PING_TCP_CLOSED) {
					ping_result = ping_tcp(host, ping);
				}
			} else if (host->availability_method == AVAIL_PING) {
				snprintf(ping->ping_status, 50, "0.000");
				snprintf(ping->ping_response, SMALL_BUFSIZE, "PING: Device address is unknown. Please use the SNMP ping options only.");
				ping_result = HOST_DOWN;
			}
		} else {
			snprintf(ping->ping_status, 50, "0.000");
			snprintf(ping->ping_response, SMALL_BUFSIZE, "PING: Device does not require ping.");
			ping_result = HOST_UP;
		}
	}

	/* snmp test */
	if ((host->availability_method == AVAIL_SNMP) ||
		(host->availability_method == AVAIL_SNMP_GET_SYSDESC) ||
		(host->availability_method == AVAIL_SNMP_GET_NEXT) ||
		(host->availability_method == AVAIL_SNMP_AND_PING) ||
		(host->availability_method == AVAIL_SNMP_OR_PING)) {

		/* If we are in AND mode and already have a failed ping result, we don't need SNMP */
		if ((ping_result == HOST_DOWN) && (host->availability_method == AVAIL_SNMP_AND_PING)) {
			snmp_result = ping_result;
		} else {
			/* Lets assume the host is up because if we are in OR mode then we have already
			 * pinged the host successfully, or some when silly people have not entered an
			 * snmp_community under v1/2, we assume that this was successfully anyway */
			snmp_result = HOST_UP;
			if ((host->availability_method != AVAIL_SNMP_OR_PING) &&
				((strlen(host->snmp_community) > 0) || (host->snmp_version >= 3))) {
				snmp_start_time = get_time_as_double();
				snmp_result = ping_snmp(host, ping);
				snmp_end_time = get_time_as_double();

				if (snmp_result == HOST_UP) {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] INFO: SNMP Device Alive, Time:%.4f ms", host->id, snmp_end_time - snmp_start_time));
					} else {
						SPINE_LOG_MEDIUM(("Device[%i] INFO: SNMP Device Alive, Time:%.4f ms", host->id, snmp_end_time - snmp_start_time));
					}
				} else {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] INFO: SNMP Device Down, Time:%.4f ms", host->id, snmp_end_time - snmp_start_time));
					} else {
						SPINE_LOG_MEDIUM(("Device[%i] INFO: SNMP Device Down, Time:%.4f ms", host->id, snmp_end_time - snmp_start_time));
					}
				}
			}
		}
	}

	switch (host->availability_method) {
		case AVAIL_SNMP_AND_PING:
			return ((ping_result == HOST_UP) && (snmp_result == HOST_UP)) ? HOST_UP : HOST_DOWN;
		case AVAIL_SNMP_OR_PING:
			return ((ping_result == HOST_UP) || (snmp_result == HOST_UP)) ? HOST_UP : HOST_DOWN;
		case AVAIL_SNMP:
		case AVAIL_SNMP_GET_NEXT:
		case AVAIL_SNMP_GET_SYSDESC:
			return (snmp_result == HOST_UP) ? HOST_UP : HOST_DOWN;
		case AVAIL_PING:
			return (ping_result == HOST_UP) ? HOST_UP : HOST_DOWN;
		case AVAIL_NONE:
			return HOST_UP;
		default:
			return HOST_DOWN;
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
	char *poll_result = NULL;
	char *oid;
	double begin_time, end_time, total_time;
	double one_thousand = 1000.00;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering SNMP Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering SNMP Ping", host->id));
	}

	if (host->snmp_session) {
		if (strlen(host->snmp_community) != 0 || host->snmp_version == 3) {
			/* by default, we look at sysUptime */
			if (host->availability_method == AVAIL_SNMP_GET_NEXT) {
				oid = strdup(".1.3");
			} else if (host->availability_method == AVAIL_SNMP_GET_SYSDESC) {
				oid = strdup(".1.3.6.1.2.1.1.1.0");
			} else {
				oid = strdup(".1.3.6.1.2.1.1.3.0");
			}

			if (oid == NULL) die("ERROR: malloc(): strdup() oid ping.c failed");

			/* record start time */
			begin_time = get_time_as_double();

			if (host->availability_method == AVAIL_SNMP_GET_NEXT) {
				poll_result = snmp_getnext(host, oid);
			} else {
				poll_result = snmp_get(host, oid);
			}

			/* record end time */
			end_time = get_time_as_double();

			SPINE_FREE(oid);

			total_time = (end_time - begin_time) * one_thousand;

			/* do positive test cases first */
			if (host->snmp_status == SNMPERR_UNKNOWN_OBJID) {
				snprintf(ping->snmp_response, SMALL_BUFSIZE, "Device responded to SNMP");
				snprintf(ping->snmp_status, 50, "%.5f", total_time);

				SPINE_FREE(poll_result);

				return HOST_UP;
			} else if (host->snmp_status != SNMPERR_SUCCESS) {
				if (is_debug_device(host->id)) {
					if (host->snmp_status == STAT_TIMEOUT) {
						SPINE_LOG(("Device[%i] SNMP Ping Timeout", host->id));
					} else {
						SPINE_LOG(("Device[%i] SNMP Ping Unknown Error", host->id));
					}
				} else {
					if (host->snmp_status == STAT_TIMEOUT) {
						SPINE_LOG_HIGH(("Device[%i] SNMP Ping Timeout", host->id));
					} else {
						SPINE_LOG_HIGH(("Device[%i] SNMP Ping Unknown Error", host->id));
					}
				}

				snprintf(ping->snmp_response, SMALL_BUFSIZE, "Device did not respond to SNMP");

				SPINE_FREE(poll_result);

				return HOST_DOWN;
			} else {
				snprintf(ping->snmp_response, SMALL_BUFSIZE, "Device responded to SNMP");
				snprintf(ping->snmp_status, 50, "%.5f", total_time);

				SPINE_FREE(poll_result);

				return HOST_UP;
			}
		} else {
			snprintf(ping->snmp_status, 50, "0.00");
			snprintf(ping->snmp_response, SMALL_BUFSIZE, "Device does not require SNMP");

			return HOST_UP;
		}
	} else {
		snprintf(ping->snmp_status, 50, "0.00");
		snprintf(ping->snmp_response, SMALL_BUFSIZE, "Invalid SNMP Session");
		return HOST_DOWN;
	}
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
int ping_icmp(host_t *host, ping_t *ping) {
#ifdef _WIN32
	if (get_address_type(host) == SPINE_IPV6) {
		return ping_icmp_windows(host, ping, AF_INET6);
	}

	return ping_icmp_windows(host, ping, AF_INET);
#else
	spine_socket_t icmp_socket;

	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;

	struct sockaddr_in recvname;
	struct sockaddr_in fromname;
	char   socket_reply[BUFSIZE];
	int    retry_count;
	int    packet_len;
	socklen_t    fromlen;
	ssize_t    return_code;

	static SPINE_PING_SEQ_T seq = 0;
	struct   icmp  *icmp;
	struct   ip    *ip;
	struct   icmp  *pkt;
	unsigned char  *packet;
	uint16_t our_id;
	uint16_t our_seq;

	if (get_address_type(host) == SPINE_IPV6) {
		return ping_icmp_ipv6(host, ping);
	}

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering ICMP Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering ICMP Ping", host->id));
	}

	/* get ICMP socket */
	retry_count = 0;
	while (TRUE) {
		if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
			thread_mutex_lock(LOCK_SETEUID);
			if (seteuid(0) == -1) {
				SPINE_LOG_DEBUG(("WARNING: Spine unable to obtain root privileges."));
			}
		}

		if (!spine_socket_is_valid(icmp_socket = spine_socket_open(AF_INET, SOCK_RAW, IPPROTO_ICMP))) {
			spine_platform_sleep_us(500000);
			retry_count++;

			if (retry_count > 4) {
				snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Ping unable to create ICMP Socket");
				snprintf(ping->ping_status, 50, "down");
				if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
					if (seteuid(getuid()) == -1) {
						SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
					}
					thread_mutex_unlock(LOCK_SETEUID);
				}

				return HOST_DOWN;
			}
		} else {
			break;
		}
	}

	if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
		if (seteuid(getuid()) == -1) {
			SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
		}
		thread_mutex_unlock(LOCK_SETEUID);
	}

	/* convert the host timeout to a double precision number in seconds */
	host_timeout = host->ping_timeout;

	/* allocate the packet in memory */
	packet_len = ICMP_HDR_SIZE + (int) sizeof(spine_ping_payload_t);

	if (!(packet = malloc(packet_len))) {
		die("ERROR: Fatal malloc error: ping.c ping_icmp!");
	}
	memset(packet, 0, packet_len);

	/* set the memory of the ping address */
	memset(&fromname, 0, sizeof(struct sockaddr_in));
	memset(&recvname, 0, sizeof(struct sockaddr_in));

	our_id  = (uint16_t)((spine_platform_process_id() & 0xFFFF) ^ icmp_id_mask);
	our_seq = (uint16_t) SPINE_PING_SEQ_NEXT(seq);

	icmp = (struct icmp*) packet;

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id   = htons(our_id);
	icmp->icmp_seq  = htons(our_seq);

	{
		/* Carry a magic + pid_mask signature so a stray reply that
		 * happens to collide on id+seq can still be dropped. */
		spine_ping_payload_t sig;
		build_ping_payload(&sig);
		memcpy(packet + ICMP_HDR_SIZE, &sig, sizeof(sig));
	}
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = get_checksum(packet, packet_len);

	/* hostname must be nonblank */
	if ((strlen(host->hostname) != 0) && spine_socket_is_valid(icmp_socket)) {
		/* initialize variables */
		snprintf(ping->ping_status, 50, "down");
		snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

		/* get address of hostname */
		if (init_sockaddr(&fromname, host->hostname, 7)) {
			retry_count = 0;
			total_time  = 0;
			begin_time  = get_time_as_double();

			while (1) {
				if (retry_count > host->ping_retries) {
					snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Ping timed out");
					snprintf(ping->ping_status, 50, "down");
					SPINE_FREE(packet);
					spine_socket_close(icmp_socket);
					return HOST_DOWN;
				}

				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] DEBUG: Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, (int) our_seq, retry_count, host->ping_retries));
				} else {
					SPINE_LOG_DEBUG(("DEBUG: Device[%i] Attempting to ping %s, seq %d (Retry %d of %d)", host->id, host->hostname, (int) our_seq, retry_count, host->ping_retries));
				}

				/* decrement the timeout value by the total time */
				timeout.tv_sec  = rint((host_timeout - total_time) / 1000);
				timeout.tv_usec = ((int) (host_timeout - total_time) % 1000) * 1000;

				/* set the socket send and receive timeout */
				spine_socket_set_timeout(icmp_socket, &timeout);

				/* send packet to destination */
				return_code = spine_socket_sendto(icmp_socket, packet, packet_len, 0, (struct sockaddr *) &fromname, sizeof(fromname));

				fromlen = sizeof(fromname);

				/* wait for a response on the socket */
				/* reinitialize fd_set -- select(2) clears bits in place on return */
				keep_listening:
				if (!spine_socket_is_valid(icmp_socket)) {
					snprintf(ping->ping_status, 50, "down");
					snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: invalid socket");
					spine_socket_close(icmp_socket);
					return HOST_DOWN;
				}
				return_code = spine_socket_wait_readable(icmp_socket, &timeout);

				/* record end time */
				end_time = get_time_as_double();

				/* calculate total time */
				total_time = (end_time - begin_time) * one_thousand;

				if (total_time < host_timeout) {
					return_code = spine_socket_recvfrom(icmp_socket, socket_reply, BUFSIZE, spine_socket_ping_icmp_recv_flags(), (struct sockaddr *) &recvname, &fromlen);

					if (return_code < 0) {
						if (spine_socket_error_is_interrupted(spine_socket_last_error())) {
							/* call was interrupted by some system event */

							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] DEBUG: Received EINTR", host->id));
							} else {
								SPINE_LOG_DEBUG(("DEBUG: Device[%i] Received EINTR", host->id));
							}

							goto keep_listening;
						}
					} else {
						size_t ip_hl;
						/* Bounds check: raw AF_INET recv includes the IP header.
						 * Refuse anything too small to plausibly contain one. */
						if ((size_t) return_code < sizeof(struct ip)) {
							SPINE_LOG_DEBUG(("DEBUG: Discarding undersized IPv4 reply: %zd bytes", return_code));
							goto keep_listening;
						}
						ip = (struct ip *) socket_reply;
						ip_hl = (size_t)(ip->ip_hl) * 4U;
						if (ip_hl < sizeof(struct ip) || ip_hl > (size_t) return_code) {
							SPINE_LOG_DEBUG(("DEBUG: Invalid IPv4 header length in reply"));
							goto keep_listening;
						}
						if ((size_t) return_code < ip_hl + ICMP_HDR_SIZE) {
							SPINE_LOG_DEBUG(("DEBUG: Reply too short to contain ICMP header"));
							goto keep_listening;
						}
						pkt = (struct icmp *) (socket_reply + ip_hl);

						if (fromname.sin_addr.s_addr != recvname.sin_addr.s_addr) {
							/* another host responded */
							goto keep_listening;
						}

						if (pkt->icmp_type != ICMP_ECHOREPLY) {
							/* received a response other than an echo reply; the enclosing
							 * total_time < host_timeout branch means a retry bump here
							 * is unreachable. Drop and keep listening. */
							continue;
						}

						/* id/seq sanity: the kernel copies our outbound
						 * id back into the reply. ntohs()-compare to be
						 * byte-order independent on the wire. */
						if (pkt->icmp_id != htons(our_id)) {
							SPINE_LOG_DEBUG(("DEBUG: Dropping ICMP reply with foreign id"));
							goto keep_listening;
						}
						if (pkt->icmp_seq != htons(our_seq)) {
							SPINE_LOG_DEBUG(("DEBUG: Dropping ICMP reply with stale seq"));
							goto keep_listening;
						}

						/* Payload signature cross-check. Require the
						 * received ICMP payload to fit at least our
						 * signature struct. */
						{
							size_t payload_off = ip_hl + ICMP_HDR_SIZE;
							if ((size_t) return_code < payload_off + sizeof(spine_ping_payload_t)) {
								SPINE_LOG_DEBUG(("DEBUG: ICMP reply payload too short for signature"));
								goto keep_listening;
							}
							if (!spine_ping_validate_payload(socket_reply + payload_off,
							                                 (size_t) return_code - payload_off,
							                                 (uint32_t) icmp_id_mask)) {
								SPINE_LOG_DEBUG(("DEBUG: Dropping ICMP reply with invalid payload signature"));
								goto keep_listening;
							}
						}

						if (is_debug_device(host->id)) {
							SPINE_LOG(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
						} else {
							SPINE_LOG_MEDIUM(("Device[%i] INFO: ICMP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
						}
						snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Device is Alive");
						snprintf(ping->ping_status, 50, "%.5f", total_time);
						SPINE_FREE(packet);
						if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
							thread_mutex_lock(LOCK_SETEUID);
							if (seteuid(0) == -1) {
								SPINE_LOG_DEBUG(("WARNING: Spine unable to obtain root privileges."));
							}
						}
						spine_socket_close(icmp_socket);
						if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
							if (seteuid(getuid()) == -1) {
								SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
							}
							thread_mutex_unlock(LOCK_SETEUID);
						}

						return HOST_UP;
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
				spine_platform_sleep_us(1000);
				#endif
			}
		} else {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Destination hostname invalid");
			snprintf(ping->ping_status, 50, "down");
			SPINE_FREE(packet);
			if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
				thread_mutex_lock(LOCK_SETEUID);
				if (seteuid(0) == -1) {
					SPINE_LOG_DEBUG(("WARNING: Spine unable to obtain root privileges."));
				}
			}
			spine_socket_close(icmp_socket);
			if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
				if (seteuid(getuid()) == -1) {
					SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
				}
				thread_mutex_unlock(LOCK_SETEUID);
			}
			return HOST_DOWN;
		}
	} else {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "ICMP: Destination address not specified");
		snprintf(ping->ping_status, 50, "down");
		SPINE_FREE(packet);
		if (spine_socket_is_valid(icmp_socket)) {
			if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
				thread_mutex_lock(LOCK_SETEUID);
				if (seteuid(0) == -1) {
					SPINE_LOG_DEBUG(("WARNING: Spine unable to obtain root privileges."));
				}
			}
			spine_socket_close(icmp_socket);
			if (spine_socket_raw_icmp_needs_privileged_open() && hasCaps() != TRUE) {
				if (seteuid(getuid()) == -1) {
					SPINE_LOG_DEBUG(("WARNING: Spine unable to drop from root to local user."));
				}
				thread_mutex_unlock(LOCK_SETEUID);
			}
		}
		return HOST_DOWN;
	}
#endif
}

/*! \fn int ping_udp(host_t *host, ping_t *ping)
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
int ping_udp(host_t *host, ping_t *ping) {
	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;
	spine_socket_t udp_socket;
	struct sockaddr_storage servername;
	socklen_t servername_len;
	char   socket_reply[BUFSIZE];
	int    retry_count;
	char   request[BUFSIZE];
	int    request_len;
	int    return_code;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering UDP Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering UDP Ping", host->id));
	}

	/* set total time */
	total_time = 0;

	begin_time = get_time_as_double();

	/* convert the host timeout to a double precision number in seconds */
	host_timeout = host->ping_timeout;

	/* initialize the socket */
	udp_socket = SPINE_INVALID_SOCKET_HANDLE;

	/* hostname must be nonblank */
	if (strlen(host->hostname) != 0) {
		/* initialize variables */
		snprintf(ping->ping_status, 50, "down");
		snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

		/* get address of hostname */
		if (resolve_sockaddr(&servername, &servername_len, AF_UNSPEC, host->hostname, host->ping_port)) {
			udp_socket = spine_socket_open(((struct sockaddr *) &servername)->sa_family, SOCK_DGRAM, IPPROTO_UDP);
			if (!spine_socket_is_valid(udp_socket)) {
				snprintf(ping->ping_status, 50, "down");
				snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Unable to create socket");
				return HOST_DOWN;
			}

			if (spine_socket_connect(udp_socket, (struct sockaddr *) &servername, servername_len) < 0) {
				snprintf(ping->ping_status, 50, "down");
				snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Cannot connect to host");
				spine_socket_close(udp_socket);
				return HOST_DOWN;
			}

			/* format packet */
			snprintf(request, BUFSIZE, "cacti-monitoring-system"); /* the actual test data */
			request_len = strlen(request);

			retry_count = 0;

			while (1) {
				if (retry_count > host->ping_retries) {
					snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Ping timed out");
					snprintf(ping->ping_status, 50, "down");
					spine_socket_close(udp_socket);
					return HOST_DOWN;
				}

				/* record start time */
				if (total_time == 0) {
					/* establish timeout value */
					timeout.tv_sec  = rint(host_timeout / 1000);
					timeout.tv_usec = rint((int) host_timeout % 1000) * 1000;

					/* set the socket send and receive timeout */
					spine_socket_set_timeout(udp_socket, &timeout);
				} else {
					/* decrement the timeout value by the total time */
					timeout.tv_sec  = rint((host_timeout - total_time) / 1000);
					timeout.tv_usec = ((int) (host_timeout - total_time) % 1000) * 1000;

					/* set the socket send and receive timeout */
					spine_socket_set_timeout(udp_socket, &timeout);
				}

				/* send packet to destination */
				spine_socket_send(udp_socket, request, request_len, 0);

				/* wait for a response on the socket */
				wait_more:
				return_code = spine_socket_wait_readable(udp_socket, &timeout);

				/* record end time */
				end_time = get_time_as_double();

				/* calculate total time */
				total_time = (end_time - begin_time) * one_thousand;

				/* check to see which socket talked */
				if (return_code > 0) {
					return_code = spine_socket_recv(udp_socket, socket_reply, BUFSIZE, 0);

					if (return_code == -1 && (
						spine_socket_error_is_host_unreachable(spine_socket_last_error()) ||
						spine_socket_error_is_conn_reset(spine_socket_last_error()) ||
						spine_socket_error_is_conn_refused(spine_socket_last_error()))) {
							if (is_debug_device(host->id)) {
								SPINE_LOG(("Device[%i] INFO: UDP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
							} else {
								SPINE_LOG_MEDIUM(("Device[%i] INFO: UDP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
							}
							snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Device is Alive");
							snprintf(ping->ping_status, 50, "%.5f", total_time);
							spine_socket_close(udp_socket);
							return HOST_UP;
					}
				} else if (return_code == -1) {
					if (spine_socket_error_is_interrupted(spine_socket_last_error())) {
						/* interrupted, try again */
						spine_platform_sleep_us(10000);
						goto wait_more;
					} else {
						snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Device is Down");
						snprintf(ping->ping_status, 50, "%.5f", total_time);
						spine_socket_close(udp_socket);
						return HOST_DOWN;
					}
				} else {
					/* timeout */
				}

				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] DEBUG: UDP Timeout, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
				} else {
					SPINE_LOG_DEBUG(("DEBUG: Device[%i] UDP Timeout, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
				}

				retry_count++;
				#ifndef SOLAR_THREAD
				spine_platform_sleep_us(1000);
				#endif
			}
		} else {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Destination hostname invalid");
			snprintf(ping->ping_status, 50, "down");
			if (spine_socket_is_valid(udp_socket)) {
				spine_socket_close(udp_socket);
			}
			return HOST_DOWN;
		}
	} else {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "UDP: Destination address invalid or unable to create socket");
		snprintf(ping->ping_status, 50, "down");
		if (spine_socket_is_valid(udp_socket)) spine_socket_close(udp_socket);
		return HOST_DOWN;
	}
}


/*! \fn int ping_tcp(host_t *host, ping_t *ping)
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
int ping_tcp(host_t *host, ping_t *ping) {
	double begin_time, end_time, total_time;
	double host_timeout;
	double one_thousand = 1000.00;
	struct timeval timeout;
	spine_socket_t tcp_socket;
	struct sockaddr_storage servername;
	socklen_t servername_len;
	int    retry_count;
	int    return_code;

	if (is_debug_device(host->id)) {
		SPINE_LOG(("Device[%i] DEBUG: Entering TCP Ping", host->id));
	} else {
		SPINE_LOG_DEBUG(("DEBUG: Device[%i] Entering TCP Ping", host->id));
	}

	/* convert the host timeout to a double precision number in seconds */
	host_timeout = host->ping_timeout;

	/* initialize the socket */
	tcp_socket = SPINE_INVALID_SOCKET_HANDLE;

	/* initialize total time */
	total_time = 0;

	/* initialize begin time */
	begin_time = get_time_as_double();

	/* hostname must be nonblank */
	if (strlen(host->hostname) != 0) {
		/* initialize variables */
		snprintf(ping->ping_status, 50, "down");
		snprintf(ping->ping_response, SMALL_BUFSIZE, "default");

		/* get address of hostname */
		if (resolve_sockaddr(&servername, &servername_len, AF_UNSPEC, host->hostname, host->ping_port)) {
			tcp_socket = spine_socket_open(((struct sockaddr *) &servername)->sa_family, SOCK_STREAM, IPPROTO_TCP);
			if (!spine_socket_is_valid(tcp_socket)) {
				snprintf(ping->ping_status, 50, "down");
				snprintf(ping->ping_response, SMALL_BUFSIZE, "TCP: Unable to create socket");
				return HOST_DOWN;
			}

			/* first attempt a connect */
			retry_count = 0;

			while (1) {
				/* establish timeout value */
				timeout.tv_sec  = rint(host_timeout / 1000);
				timeout.tv_usec = ((int) host_timeout % 1000) * 1000;

				/* set the socket send and receive timeout */
				spine_socket_set_timeout(tcp_socket, &timeout);

				/* make the connection */
				return_code = spine_socket_connect(tcp_socket, (struct sockaddr *) &servername, servername_len);

				/* record end time */
				end_time = get_time_as_double();

				/* calculate total time */
				total_time = (end_time - begin_time) * one_thousand;

				if ((return_code == -1 && spine_socket_error_is_conn_refused(spine_socket_last_error()) && host->ping_method == PING_TCP_CLOSED) || return_code == 0) {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] INFO: TCP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
					} else {
						SPINE_LOG_MEDIUM(("Device[%i] INFO: TCP Device Alive, Try Count:%i, Time:%.4f ms", host->id, retry_count+1, (total_time)));
					}
					snprintf(ping->ping_response, SMALL_BUFSIZE, "TCP: Device is Alive");
					snprintf(ping->ping_status, 50, "%.5f", total_time);
					spine_socket_close(tcp_socket);
					return HOST_UP;
				} else {
					if (!spine_socket_ping_tcp_supports_retries() || retry_count > host->ping_retries) {
						snprintf(ping->ping_status, 50, "down");
						snprintf(ping->ping_response, SMALL_BUFSIZE, "TCP: Cannot connect to host");
						spine_socket_close(tcp_socket);
						return HOST_DOWN;
					} else {
						retry_count++;
					}
				}
			}
		} else {
			snprintf(ping->ping_response, SMALL_BUFSIZE, "TCP: Destination hostname invalid");
			snprintf(ping->ping_status, 50, "down");
			if (spine_socket_is_valid(tcp_socket)) {
				spine_socket_close(tcp_socket);
			}
			return HOST_DOWN;
		}
	} else {
		snprintf(ping->ping_response, SMALL_BUFSIZE, "TCP: Destination address invalid or unable to create socket");
		snprintf(ping->ping_status, 50, "down");
		if (spine_socket_is_valid(tcp_socket)) spine_socket_close(tcp_socket);
		return HOST_DOWN;
	}
}

/*! \fn int get_address_type(host_t *host)
 *  \brief determines using getaddrinfo the iptype and returns the iptype
 *
 *  \return 1 - IPv4, 2 - IPv6, 0 - Unknown
 */
int get_address_type(host_t *host) {
	struct addrinfo hints, *res, *res_list;
	char addrstr[255];
	void *ptr = NULL;
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

	for (res = res_list; res != NULL; res = res->ai_next) {
		switch(res->ai_family) {
			case AF_INET:
				ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
				addr_found = TRUE;
				break;
			case AF_INET6:
				ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
				addr_found = TRUE;
				break;
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

/*! \fn int init_sockaddr(struct sockaddr_in *name, const char *hostname, unsigned short int port)
 *  \brief converts a hostname to an internet address
 *
 *  \return TRUE if successful, FALSE otherwise.
 *
 */
int init_sockaddr(struct sockaddr_in *name, const char *hostname, unsigned short int port) {
	struct sockaddr_storage address;
	socklen_t address_len;

	if (!resolve_sockaddr(&address, &address_len, AF_INET, hostname, port)) {
		return FALSE;
	}

	if (address_len < sizeof(struct sockaddr_in)) {
		return FALSE;
	}

	memcpy(name, &address, sizeof(struct sockaddr_in));
	return TRUE;
}

/*! \fn name_t *get_namebyhost(char *hostname, name_t *name)
 *  \brief splits the hostname into method, name and port
 *
 *  \return name_t containing a trimmed hostname, port, and optional method
 *
 */
name_t *get_namebyhost(char *hostname, name_t *name) {
	if (name == NULL) {
		SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Allocating name_t", hostname));

		if (!(name = (name_t *) malloc(sizeof(name_t)))) {
			die("ERROR: Fatal malloc error: ping.c get_namebyhost->name");
		}

		memset(name, '\0', sizeof(name_t));
	}

	int tokens = 0;
	char *stack = NULL;
	char *token = NULL;

	if (!(stack = (char *) malloc(strlen(hostname)+1))) {
		die("ERROR: Fatal malloc error: ping.c get_namebyhost->stack");
	}

	memset(stack, '\0', strlen(hostname)+1);
	strncopy(stack, hostname, strlen(hostname) + 1);

	/* Preserve raw IPv6 literals like "::1". They contain ':' but are not
	 * method-prefixed host:port strings, and tokenizing them would lose data. */
	if (hostname[0] != '[' &&
		strncasecmp(hostname, "TCP:", 4) != 0 &&
		strncasecmp(hostname, "UDP:", 4) != 0 &&
		strncasecmp(hostname, "TCP6:", 5) != 0 &&
		strncasecmp(hostname, "UDP6:", 5) != 0 &&
		strchr(hostname, ':') != NULL &&
		strchr(strchr(hostname, ':') + 1, ':') != NULL) {
		SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - IPv6 literal detected, preserving hostname", hostname));
		strncopy(name->hostname, hostname, sizeof(name->hostname));
		free(stack);
		return name;
	}

	token = strtok(stack, ":");

	if (token == NULL) {
		SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - No delimiter, assume full hostname", hostname));
		strncopy(name->hostname, hostname, SMALL_BUFSIZE);
	}

	while (token != NULL && tokens <= 3) {
		tokens++;
		SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Token #%i - %s", hostname, tokens, token));
		if (tokens == 1) {
			if (strlen(token) && token[0] == '[') {
				SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Have TCPv6 method", hostname));
				/* strncopy guarantees NUL termination even on truncation;
				 * the raw strncpy path used to leave an unterminated buffer
				 * on hostnames >= sizeof(name->hostname). */
				strncopy(name->hostname, hostname, sizeof(name->hostname));
				break;
			} else if (strlen(token) == 3) {
				if (strncasecmp(token, "TCP", 3) == 0) {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Have TCPv4 method", hostname));
					name->method = 1;
				} else if (strncasecmp(token, "UDP", 3) == 0) {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Have UDPv4 method", hostname));
					name->method = 2;
				} else {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - No matching method for 3 chars: %s", hostname, token));
					// assume we have had a method
					tokens++;
				}
			} else if (strlen(token) == 4) {
				if (strncasecmp(token, "TCP6", 4) == 0) {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Have TCPv6 method", hostname));
					name->method = 3;
				} else if (strncasecmp(token, "UDP6", 4) == 0) {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Have UDPv6 method", hostname));
					name->method = 4;
				} else {
					SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - No matching method for 4 chars: %s", hostname, token));

					// assume we have had a method
					tokens++;
				}
			} else {
				SPINE_LOG_DEBUG(("DEBUG: get_hostbyname(%s) - No matching method for %li chars: %s", hostname, strlen(token), token));

				// assume we have had a method
				tokens++;
			}
		}

		if (tokens == 2) {
			SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Setting hostname: %s", hostname, token));
			/* The previous strncpy + hostname[strlen(token)] = '\0' poke
			 * wrote past the buffer on tokens >= sizeof(name->hostname).
			 * strncopy truncates at the buffer bound and always NUL-terminates. */
			strncopy(name->hostname, token, sizeof(name->hostname));
		}

		if (tokens == 3 && strlen(token)) {
			SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Setting port: %s", hostname, token));
			name->port = atoi(token);
		}

		if (tokens > 3) {
			SPINE_LOG_DEBUG(("DEBUG: get_namebyhost(%s) - Unexpected token: %i", hostname, tokens));
		}
		token = strtok(NULL, ":");
	}

	if (stack != NULL) {
		free(stack);
		stack = NULL;
	}

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
	answer = ~sum;				/* truncate to 16 bits */

	return answer;
}

/*! \fn void update_host_status(int status, host_t *host, ping_t *ping, int availability_method)
 *  \brief update the host table in Cacti with the result of the ping of the host.
 *  \param status the current poll status of the host, either HOST_UP, or HOST_DOWN
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *  \param availability_method the method that was used to poll the host
 *
 *  This function will determine if the host is UP, DOWN, or RECOVERING based upon
 *  the ping result and it's current status.  It will update the Cacti database
 *  with the calculated status.
 *
 */
void update_host_status(int status, host_t *host, ping_t *ping, int availability_method) {
	int    issue_log_message = FALSE;
	double ping_time;
 	double hundred_percent = 100.00;
	char   current_date[40];

	snprintf(current_date, 40, "%lu", time(NULL));

	/* host is down */
	if (status == HOST_DOWN) {
		/* update total polls, failed polls and availability */
		host->failed_polls = host->failed_polls + 1;
		host->total_polls = host->total_polls + 1;
		host->availability = hundred_percent * (host->total_polls - host->failed_polls) / host->total_polls;

		/*determine the error message to display */
		switch (availability_method) {
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP_AND_PING:
			if (strlen(host->snmp_community) == 0 && host->snmp_version < 3) {
				snprintf(host->status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
			} else {
				snprintf(host->status_last_error, BUFSIZE * 2 + 1, "%s, %s", ping->snmp_response, ping->ping_response);
			}
			break;
		case AVAIL_SNMP:
			if (strlen(host->snmp_community) == 0 && host->snmp_version < 3) {
				snprintf(host->status_last_error, BUFSIZE * 2 + 1, "%s", "Device does not require SNMP");
			} else {
				snprintf(host->status_last_error, BUFSIZE * 2 + 1, "%s", ping->snmp_response);
			}
			break;
		default:
			snprintf(host->status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
		}

		/* determine if to send an alert and update remainder of statistics */
		if (host->status == HOST_UP) {
			/* increment the event failure count */
			host->status_event_count++;

			/* if it's time to issue an error message, indicate so */
			if (host->status_event_count >= set.ping_failure_count) {
				/* host is now down, flag it that way */
				host->status = HOST_DOWN;

				issue_log_message = TRUE;

				/* update the failure date only if the failure count is 1 */
				if (set.ping_failure_count == 1) {
					snprintf(host->status_fail_date, 40, "%s", current_date);
				}
			} else {
				/* host down for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_fail_date, 40, "%s", current_date);
				}
			}
		} else if (host->status == HOST_RECOVERING) {
			/* host is recovering, put back in failed state */
			host->status_event_count = 1;
			host->status = HOST_DOWN;
		} else if (host->status == HOST_UNKNOWN) {
			/* host was unknown and now is down */
			host->status = HOST_DOWN;
			host->status_event_count = 0;
		} else {
			host->status_event_count++;
		}
	} else {
		/* host is up!! */

		/* update total polls and availability */
		host->total_polls = host->total_polls + 1;
		host->availability = hundred_percent * (host->total_polls - host->failed_polls) / host->total_polls;

		/* determine the ping statistic to set and do so */
		if (availability_method == AVAIL_SNMP_AND_PING) {
			if (strlen(host->snmp_community) == 0 && host->snmp_version < 3) {
				ping_time = atof(ping->ping_status);
			} else {
				/* calculate the average of the two times */
				ping_time = (atof(ping->snmp_status) + atof(ping->ping_status)) / 2;
			}
		} else if (availability_method == AVAIL_SNMP) {
			if (strlen(host->snmp_community) == 0 && host->snmp_version < 3) {
				ping_time = 0.000;
			} else {
				ping_time = atof(ping->snmp_status);
			}
		} else if (availability_method == AVAIL_NONE) {
			ping_time = 0.000;
		} else {
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
		if ((host->status == HOST_DOWN) || (host->status == HOST_RECOVERING)) {
			/* just up, change to recovering */
			if (host->status == HOST_DOWN) {
				host->status = HOST_RECOVERING;
				host->status_event_count = 1;
			} else {
				host->status_event_count++;
			}

			/* if it's time to issue a recovery message, indicate so */
			if (host->status_event_count >= set.ping_recovery_count) {
				/* host is up, flag it that way */
				host->status = HOST_UP;

				issue_log_message = TRUE;

				/* update the recovery date only if the recovery count is 1 */
				if (set.ping_recovery_count == 1) {
					snprintf(host->status_rec_date, 40, "%s", current_date);
				}

				/* reset the event counter */
				host->status_event_count = 0;
			} else {
				/* host recovering for the first time, set event date */
				if (host->status_event_count == 1) {
					snprintf(host->status_rec_date, 40, "%s", current_date);
				}
			}
		} else if (host->status_event_count > 0) {
			/* host was unknown and now is up */
			host->status = HOST_UP;
			host->status_event_count = 0;
		} else {
			/* host was unknown and now is up */
			host->status = HOST_UP;
			host->status_event_count = 0;
		}
	}

	/* if the user wants a flood of information then flood them */
	if (set.log_level >= POLLER_VERBOSITY_HIGH) {
		if ((host->status == HOST_UP) || (host->status == HOST_RECOVERING)) {
			/* log ping result if we are to use a ping for reachability testing */
			if (availability_method == AVAIL_SNMP_AND_PING) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG_HIGH(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				}
			} else if (availability_method == AVAIL_SNMP_OR_PING) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG_HIGH(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				}
			} else if (availability_method == AVAIL_SNMP) {
				if ((strlen(host->snmp_community) == 0) && (host->snmp_version < 3)) {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] SNMP Result: Device does not require SNMP", host->id));
					} else {
						SPINE_LOG_HIGH(("Device[%i] SNMP Result: Device does not require SNMP", host->id));
					}
				} else {
					if (is_debug_device(host->id)) {
						SPINE_LOG(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
					} else {
						SPINE_LOG_HIGH(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
					}
				}
			} else if (availability_method == AVAIL_NONE) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] No Device Availability Method Selected", host->id));
				} else {
					SPINE_LOG_HIGH(("Device[%i] No Device Availability Method Selected", host->id));
				}
			} else {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] PING: Result %s", host->id, ping->ping_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] PING: Result %s", host->id, ping->ping_response));
				}
			}
		} else {
			if (availability_method == AVAIL_SNMP_AND_PING) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] PING Result: %s", host->id, ping->ping_response));
					SPINE_LOG_HIGH(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				}
			} else if (availability_method == AVAIL_SNMP) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
				}
			} else if (availability_method == AVAIL_NONE) {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] No Device Availability Method Selected", host->id));
				} else {
					SPINE_LOG_HIGH(("Device[%i] No Device Availability Method Selected", host->id));
				}
			} else {
				if (is_debug_device(host->id)) {
					SPINE_LOG(("Device[%i] PING Result: %s", host->id, ping->ping_response));
				} else {
					SPINE_LOG_HIGH(("Device[%i] PING Result: %s", host->id, ping->ping_response));
				}
			}
		}
	}

	/* if there is supposed to be an event generated, do it */
	if (issue_log_message) {
		if (host->status == HOST_DOWN) {
			SPINE_LOG(("Device[%i] Hostname[%s] ERROR: HOST EVENT: Device is DOWN Message: %s", host->id, host->hostname, host->status_last_error));
		} else {
			SPINE_LOG(("Device[%i] Hostname[%s] NOTICE: HOST EVENT: Device Returned from DOWN State", host->id, host->hostname));
		}
	}
}

#ifndef _WIN32
/* Minimal numeric-address ICMPv4 oneshot used by the platform_icmp
 * facade. Opens a raw socket, sends one echo, waits once, validates.
 * Does not do the capability dance in ping_icmp() because callers of
 * the facade are expected to have already acquired CAP_NET_RAW (or
 * setuid-root). Returns 0 on call success; status in result->status. */
int ping_icmp_v4_posix_numeric(const char *ip, uint32_t timeout_ms,
                               const void *payload, size_t payload_len,
                               spine_icmp_result_t *result) {
	int sock = -1;
	unsigned char *packet = NULL;
	size_t pkt_len;
	struct sockaddr_in dst;
	struct sockaddr_in recvname;
	socklen_t recvlen;
	char recvbuf[BUFSIZE];
	struct timeval tv;
	fd_set rfds;
	ssize_t n;
	struct icmp *icp;
	uint16_t our_id;
	uint16_t our_seq;
	static SPINE_PING_SEQ_T facade_seq = 0;
	int ret = -1;
	double t0 = 0.0;
	double t1 = 0.0;
	int sig_payload = (payload == NULL);  /* we built the signature, so we own reply validation */

	if (result == NULL) return -1;
	result->status = SPINE_ICMP_ERROR;
	result->rtt_us = 0;
	result->system_errno = 0;

	if (ip == NULL) {
		result->system_errno = EINVAL;
		return -1;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) {
		result->system_errno = EINVAL;
		return -1;
	}

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
		result->system_errno = errno;
		return -1;
	}
	spine_fd_set_cloexec(sock);

	pkt_len = (size_t) ICMP_HDR_SIZE + (payload_len > 0 ? payload_len : sizeof(spine_ping_payload_t));
	packet = calloc(1, pkt_len);
	if (packet == NULL) {
		result->system_errno = ENOMEM;
		goto cleanup;
	}

	our_id  = (uint16_t)((spine_platform_process_id() & 0xFFFF) ^ icmp_id_mask);
	our_seq = (uint16_t) SPINE_PING_SEQ_NEXT(facade_seq);

	icp = (struct icmp *) packet;
	icp->icmp_type = ICMP_ECHO;
	icp->icmp_code = 0;
	icp->icmp_id   = htons(our_id);
	icp->icmp_seq  = htons(our_seq);

	if (payload != NULL && payload_len > 0) {
		memcpy(packet + ICMP_HDR_SIZE, payload, payload_len);
	} else {
		spine_ping_payload_t sig;
		build_ping_payload(&sig);
		memcpy(packet + ICMP_HDR_SIZE, &sig, sizeof(sig));
	}
	icp->icmp_cksum = 0;
	icp->icmp_cksum = get_checksum(packet, (int) pkt_len);

	t0 = get_time_as_double();
	if (sendto(sock, packet, pkt_len, 0, (struct sockaddr *) &dst, sizeof(dst)) < 0) {
		result->system_errno = errno;
		goto cleanup;
	}

	for (;;) {
		/* Recompute remaining timeout on every iteration so a flood
		 * of mismatched replies (wrong id/seq, spoofed source) cannot
		 * make us wait indefinitely. */
		double elapsed_ms = (get_time_as_double() - t0) * 1000.0;
		double remaining_ms = (double) timeout_ms - elapsed_ms;
		int sel;
		if (remaining_ms <= 0.0) {
			result->status = SPINE_ICMP_TIMEOUT;
			ret = 0;
			goto cleanup;
		}
		tv.tv_sec  = (long)(remaining_ms / 1000.0);
		tv.tv_usec = (long)((remaining_ms - (double) tv.tv_sec * 1000.0) * 1000.0);
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		sel = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR) continue;
			result->system_errno = errno;
			goto cleanup;
		}
		if (sel == 0) {
			result->status = SPINE_ICMP_TIMEOUT;
			ret = 0;
			goto cleanup;
		}
		recvlen = sizeof(recvname);
		n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &recvname, &recvlen);
		if (n < 0) {
			if (errno == EINTR) continue;
			result->system_errno = errno;
			goto cleanup;
		}
		if ((size_t) n < sizeof(struct ip) + ICMP_HDR_SIZE) {
			continue;
		}
		{
			struct ip *iph = (struct ip *) recvbuf;
			size_t iphl = (size_t) iph->ip_hl * 4U;
			struct icmp *pkt;
			if (iphl < sizeof(struct ip) || iphl > (size_t) n) continue;
			if ((size_t) n < iphl + ICMP_HDR_SIZE) continue;
			if (dst.sin_addr.s_addr != recvname.sin_addr.s_addr) continue;
			pkt = (struct icmp *) (recvbuf + iphl);
			if (pkt->icmp_type != ICMP_ECHOREPLY
			    || pkt->icmp_id != htons(our_id)
			    || pkt->icmp_seq != htons(our_seq)) {
				continue;
			}
			/* When we own payload composition, a LAN attacker who
			 * observed our probe cannot forge a matching reply
			 * without also reproducing the signed payload. */
			if (sig_payload) {
				size_t payload_off = iphl + ICMP_HDR_SIZE;
				if ((size_t) n < payload_off + sizeof(spine_ping_payload_t)) continue;
				if (!spine_ping_validate_payload(recvbuf + payload_off,
				                                  (size_t) n - payload_off,
				                                  (uint32_t) icmp_id_mask)) {
					continue;
				}
			}
			t1 = get_time_as_double();
			result->status = SPINE_ICMP_OK;
			result->rtt_us = (uint32_t)((t1 - t0) * 1000000.0);
			ret = 0;
			goto cleanup;
		}
	}

cleanup:
	SPINE_FREE(packet);
	if (sock >= 0) close(sock);
	return ret;
}

/* IPv6 counterpart. Same contract as v4. */
int ping_icmp_v6_posix_numeric(const char *ip, uint32_t timeout_ms,
                               const void *payload, size_t payload_len,
                               spine_icmp_result_t *result) {
	int sock = -1;
	unsigned char *packet = NULL;
	size_t pkt_len;
	struct sockaddr_in6 dst;
	struct sockaddr_in6 recvname;
	socklen_t recvlen;
	char recvbuf[BUFSIZE];
	struct timeval tv;
	fd_set rfds;
	ssize_t n;
	struct icmp6_hdr *icp;
	uint16_t our_id;
	uint16_t our_seq;
	static SPINE_PING_SEQ_T facade_seq6 = 0;
	int ret = -1;
	double t0 = 0.0;
	double t1 = 0.0;
	int sig_payload = (payload == NULL);  /* we built the signature, so we own reply validation */

	if (result == NULL) return -1;
	result->status = SPINE_ICMP_ERROR;
	result->rtt_us = 0;
	result->system_errno = 0;

	if (ip == NULL) {
		result->system_errno = EINVAL;
		return -1;
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin6_family = AF_INET6;
	if (inet_pton(AF_INET6, ip, &dst.sin6_addr) != 1) {
		result->system_errno = EINVAL;
		return -1;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&dst.sin6_addr) && dst.sin6_scope_id == 0) {
		(void) spine_apply_ipv6_scope_id(&dst, NULL);
	}

	sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock < 0) {
		result->system_errno = errno;
		return -1;
	}
	spine_fd_set_cloexec(sock);

#ifdef ICMP6_FILTER
	{
		struct icmp6_filter filter;
		ICMP6_FILTER_SETBLOCKALL(&filter);
		ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
		(void) setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter));
	}
#endif
#ifdef IPV6_CHECKSUM
	{
		int cksum_offset = (int) offsetof(struct icmp6_hdr, icmp6_cksum);
		(void) setsockopt(sock, IPPROTO_IPV6, IPV6_CHECKSUM, &cksum_offset, sizeof(cksum_offset));
	}
#endif

	pkt_len = sizeof(struct icmp6_hdr) + (payload_len > 0 ? payload_len : sizeof(spine_ping_payload_t));
	packet = calloc(1, pkt_len);
	if (packet == NULL) {
		result->system_errno = ENOMEM;
		goto cleanup;
	}

	our_id  = (uint16_t)((spine_platform_process_id() & 0xFFFF) ^ icmp_id_mask);
	our_seq = (uint16_t) SPINE_PING_SEQ_NEXT(facade_seq6);

	icp = (struct icmp6_hdr *) packet;
	icp->icmp6_type = ICMP6_ECHO_REQUEST;
	icp->icmp6_code = 0;
	icp->icmp6_id   = htons(our_id);
	icp->icmp6_seq  = htons(our_seq);

	if (payload != NULL && payload_len > 0) {
		memcpy(packet + sizeof(struct icmp6_hdr), payload, payload_len);
	} else {
		spine_ping_payload_t sig;
		build_ping_payload(&sig);
		memcpy(packet + sizeof(struct icmp6_hdr), &sig, sizeof(sig));
	}

	t0 = get_time_as_double();
	if (sendto(sock, packet, pkt_len, 0, (struct sockaddr *) &dst, sizeof(dst)) < 0) {
		result->system_errno = errno;
		goto cleanup;
	}

	for (;;) {
		/* Same remaining-timeout computation as the v4 helper: a
		 * flood of unrelated ICMPv6 traffic must not extend our
		 * deadline. */
		double elapsed_ms = (get_time_as_double() - t0) * 1000.0;
		double remaining_ms = (double) timeout_ms - elapsed_ms;
		int sel;
		if (remaining_ms <= 0.0) {
			result->status = SPINE_ICMP_TIMEOUT;
			ret = 0;
			goto cleanup;
		}
		tv.tv_sec  = (long)(remaining_ms / 1000.0);
		tv.tv_usec = (long)((remaining_ms - (double) tv.tv_sec * 1000.0) * 1000.0);
		FD_ZERO(&rfds);
		FD_SET(sock, &rfds);
		sel = select(sock + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR) continue;
			result->system_errno = errno;
			goto cleanup;
		}
		if (sel == 0) {
			result->status = SPINE_ICMP_TIMEOUT;
			ret = 0;
			goto cleanup;
		}
		recvlen = sizeof(recvname);
		n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *) &recvname, &recvlen);
		if (n < 0) {
			if (errno == EINTR) continue;
			result->system_errno = errno;
			goto cleanup;
		}
		if ((size_t) n < sizeof(struct icmp6_hdr)) continue;
		if (memcmp(&dst.sin6_addr, &recvname.sin6_addr, sizeof(struct in6_addr)) != 0) continue;
		{
			struct icmp6_hdr *r = (struct icmp6_hdr *) recvbuf;
			if (r->icmp6_type != ICMP6_ECHO_REPLY
			    || r->icmp6_id != htons(our_id)
			    || r->icmp6_seq != htons(our_seq)) {
				continue;
			}
			if (sig_payload) {
				size_t payload_off = sizeof(struct icmp6_hdr);
				if ((size_t) n < payload_off + sizeof(spine_ping_payload_t)) continue;
				if (!spine_ping_validate_payload(recvbuf + payload_off,
				                                  (size_t) n - payload_off,
				                                  (uint32_t) icmp_id_mask)) {
					continue;
				}
			}
			t1 = get_time_as_double();
			result->status = SPINE_ICMP_OK;
			result->rtt_us = (uint32_t)((t1 - t0) * 1000000.0);
			ret = 0;
			goto cleanup;
		}
	}

cleanup:
	SPINE_FREE(packet);
	if (sock >= 0) close(sock);
	return ret;
}
#endif /* !_WIN32 */
