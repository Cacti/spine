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
	if (connect(fd, (const struct sockaddr *) address, sizeof(*address)) == 0) return 0;
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
	for (unsigned int attempt = 0;; attempt++) {
		double deadline = spine_monotonic_time() + (double) host->availability.timeout / 1000;
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
		if (attempt >= (unsigned int) host->availability.retries) return ping_down(ping, "TCP: Cannot connect to host");
#endif
	}
}
