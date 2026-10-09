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

#ifndef SPINE_PING_INTERNAL_H
#define SPINE_PING_INTERNAL_H

#include "common.h"
#include "spine.h"
typedef struct {
	int fd;
	int reading;
} icmp_shared_t;

typedef struct icmp_waiter {
	struct icmp_waiter *next;
	icmp_shared_t *shared;
	pthread_cond_t wake;
	int family;
	uint16_t id;
	uint16_t seq;
	struct in_addr peer;
#ifdef SPINE_HAVE_ICMPV6
	struct in6_addr peer6;
#endif
	int answered;
	int sleeping;
} icmp_waiter_t;

extern icmp_shared_t icmp_shared;
int icmp_open_socket(int family, int type, int protocol);
void icmp_shared_register(icmp_waiter_t *waiter);
void icmp_shared_unregister(icmp_waiter_t *waiter);
int icmp_shared_await(icmp_waiter_t *waiter, double deadline);
void ping_wait_left(double deadline, struct timeval *timeout);
const char *ping_address(const char *hostname, char *address, size_t capacity);
#ifdef SPINE_HAVE_ICMPV6
extern icmp_shared_t icmp6_shared;
extern const char icmp6_payload[];
int icmp6_reply_matches(const unsigned char *reply, ssize_t length, uint16_t id, uint16_t seq, int check_id);
int ping_icmp_ipv6(const host_t *host, ping_t *ping);
#endif
#endif
