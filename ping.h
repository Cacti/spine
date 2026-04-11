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

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#endif

#ifndef MSG_WAITALL
#define MSG_WAITALL 0x100
#endif

/* Host availability functions */
extern int ping_host(host_t *host, ping_t *ping);
extern int ping_snmp(host_t *host, ping_t *ping);
extern int ping_icmp(host_t *host, ping_t *ping);
extern int ping_udp(host_t *host, ping_t *ping);
extern int ping_tcp(host_t *host, ping_t *ping);
extern name_t *get_namebyhost(char *hostname, name_t *name);
extern void update_host_status(int status, host_t *host, ping_t *ping, int availability_method);
extern int init_sockaddr(struct sockaddr_in *name, const char *hostname, unsigned short int port);
extern int get_address_type(host_t *host);
extern unsigned short int get_checksum(void* buf, int len);
