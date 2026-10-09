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

/*! \fn int get_address_type(host_t *host)
 *  \brief determines using getaddrinfo the iptype and returns the iptype
 *
 *  \return 1 - IPv4, 2 - IPv6, 0 - Unknown
 */
int get_address_type(host_t *host) {
	struct addrinfo hints;
	struct addrinfo *res_list;
	char addrstr[255];
	char address[BUFSIZE];
	const void *ptr = NULL;
	int addr_found = FALSE;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
	int error;

	if ((error = getaddrinfo(ping_address(host->hostname, address, sizeof(address)), NULL, &hints, &res_list)) != 0) {
		SPINE_LOG(("WARNING: Unable to determine address info for %s (%s)", host->hostname, gai_strerror(error)));
		return SPINE_NONE;
	}

	for (struct addrinfo *res = res_list; res != NULL; res = res->ai_next) {
		inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, 100);

		switch (res->ai_family) {
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

		SPINE_LOG_HIGH(("Device[%d] IPv%d address %s (%s)", host->id, res->ai_family == PF_INET6 ? 6 : 4, addrstr, res->ai_canonname));

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
	char address[BUFSIZE];
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
	ping_address(hostname, address, sizeof(address));
	for (int attempt = 0;; attempt++) {
		int status = getaddrinfo(address, NULL, &hints, &hostinfo);
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
	name->sin_addr = ((struct sockaddr_in *) hostinfo->ai_addr)->sin_addr;
	name->sin_port = htons((unsigned short) port);
	freeaddrinfo(hostinfo);
	return TRUE;
}

/*! \fn static int split_host_spec(const char *spec, int *method, char *address, size_t capacity, int *port)
 *  \brief splits a "[transport:]host[:port]" device name into its parts
 *
 *  Cacti keeps Net-SNMP transport specifiers such as udp6:[2001:db8::1]:161
 *  in the hostname.  An IPv6 host is either bracketed, so that a port can
 *  follow it, or a bare literal in which every colon belongs to the address.
 *  A port that is not a plain number from 1 to 65535 is reported as 0.
 *
 *  \return TRUE if the host part is IPv6, FALSE otherwise
 */
static int split_host_spec(const char *spec, int *method, char *address, size_t capacity, int *port) {
	static const char *const methods[] = {"TCP", "UDP", "TCP6", "UDP6"};
	const char *host = spec;
	const char *colon;
	const char *end;
	const char *port_text = NULL;
	size_t length;
	size_t i;
	int ipv6 = FALSE;

	*method = 0;
	*port = 0;

	colon = strchr(spec, ':');

	if (colon != NULL) {
		for (i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
			length = strlen(methods[i]);

			if ((size_t) (colon - spec) == length && strncasecmp(spec, methods[i], length) == 0) {
				*method = (int) i + 1;
				host = colon + 1;
				break;
			}
		}
	}

	if (host[0] == '[' && (end = strchr(host, ']')) != NULL) {
		ipv6 = TRUE;
		host = host + 1;
		length = (size_t) (end - host);

		if (end[1] == ':') {
			port_text = end + 2;
		}
	} else if (char_count(host, ':') > 1 || host[0] == '[') {
		ipv6 = TRUE;
		length = strlen(host);
	} else if ((colon = strchr(host, ':')) != NULL) {
		length = (size_t) (colon - host);
		port_text = colon + 1;
	} else {
		length = strlen(host);
	}

	if (length >= capacity) {
		length = capacity - 1;
	}

	memcpy(address, host, length);
	address[length] = '\0';

	if (port_text != NULL && port_text[0] >= '0' && port_text[0] <= '9') {
		char *rest;
		long value;

		errno = 0;
		value = strtol(port_text, &rest, 10);

		if (errno == 0 && *rest == '\0' && value > 0 && value <= 65535) {
			*port = (int) value;
		}
	}

	return ipv6;
}

/*! \fn static const char *ping_address(const char *hostname, char *address, size_t capacity)
 *  \brief the bare address a network probe resolves for a device name
 */
const char *ping_address(const char *hostname, char *address, size_t capacity) {
	int method;
	int port;

	split_host_spec(hostname, &method, address, capacity, &port);

	return address;
}

/*! \fn name_t *get_namebyhost(const char *hostname, name_t *name)
 *  \brief parses a device hostname with an optional transport and port
 *
 *  An IPv6 name is returned whole: Net-SNMP needs the transport and the
 *  brackets to reach the agent, and the ping code strips them itself.
 */
name_t *get_namebyhost(const char *hostname, name_t *name) {
	char address[BUFSIZE];

	if (name == NULL) {
		name = calloc(1, sizeof(*name));
		if (name == NULL) die("ERROR: Fatal malloc error: ping.c get_namebyhost->name");
	}

	if (split_host_spec(hostname, &name->method, address, sizeof(address), &name->port)) {
		strncopy(name->hostname, hostname, sizeof(name->hostname));
	} else {
		strncopy(name->hostname, address, sizeof(name->hostname));
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
unsigned short int get_checksum(const void *buf, int len) {
	const unsigned char *bytes = buf;
	uint32_t sum = 0;
	uint16_t word;

	while (len > 1) {
		memcpy(&word, bytes, sizeof(word));
		sum += word;
		bytes += sizeof(word);
		len -= (int) sizeof(word);
	}
	if (len == 1) {
		word = 0;
		memcpy(&word, bytes, 1);
		sum += word;
	}
	sum = (sum >> 16) + (sum & UINT32_C(0xffff));
	sum += sum >> 16;
	return (unsigned short int) (~sum & UINT32_C(0xffff));
}
