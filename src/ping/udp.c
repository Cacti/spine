/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
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
#include "ping/ping_internal.h"
#include <fcntl.h>

static int ping_udp_response(int fd, double deadline) {
	char response[BUFSIZE];
	for (;;) {
		int ready = spine_wait_readable(fd, deadline);
		if (ready <= 0) return ready;
		ssize_t received = recv(fd, response, sizeof(response), 0);
		if (received >= 0) return 1;
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
		connect(fd, (struct sockaddr *) &servername, sizeof(servername)) < 0) {
		close(fd);
		return ping_down(ping, "UDP: Cannot connect to host");
	}
	static const char request[] = "cacti-monitoring-system";
	double begin = spine_monotonic_time();
	for (unsigned int attempt = 0;; attempt++) {
		double deadline = spine_monotonic_time() + (double) host->availability.timeout / 1000;
		ssize_t sent;
		do {
			sent = send(fd, request, sizeof(request) - 1, 0);
		} while (sent < 0 && errno == EINTR && spine_monotonic_time() < deadline);
		int result = sent == (ssize_t) (sizeof(request) - 1) ? ping_udp_response(fd, deadline) : -1;
		double elapsed = (spine_monotonic_time() - begin) * 1000;
		if (result > 0) {
			SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] INFO: UDP Device Alive, Try Count:%u, Time:%.4f ms", host->id, attempt + 1, elapsed));
			strncopy(ping->ping_response, "UDP: Device is Alive", SMALL_BUFSIZE);
			snprintf(ping->ping_status, 50, "%.5f", elapsed);
			close(fd);
			return HOST_UP;
		}
		if (result < 0 || attempt >= (unsigned int) host->availability.retries) {
			close(fd);
			return ping_down(ping, result < 0 ? "UDP: Device is Down" : "UDP: Ping timed out");
		}
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: UDP Timeout, Try Count:%u, Time:%.4f ms", host->id, attempt + 1, elapsed));
	}
}
