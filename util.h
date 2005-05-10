/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

/* Cacti config reading utilities */
int read_config_options(config_t *set);
int read_cactid_config(char *file, config_t * set);
void config_defaults(config_t *);

/* Cacti logging utilities */
void cacti_log(char *logmessage);

/* Number validation tools */
int is_numeric(char *string);

/* String and file utilities */
char *clean_string(char *string);
char *add_win32_slashes(char *string, int arguments_2_strip);
int file_exists(char *filename);
char *strip_string_crlf(char *string);
char *strip_quotes(char *string);

/* Host availability functions */
int ping_host(host_t *host, ping_t *ping);
int ping_snmp(host_t *host, ping_t *ping);
int ping_icmp(host_t *host, ping_t *ping);
int ping_udp(host_t *host, ping_t *ping);
void update_host_status(int status, host_t *host, ping_t *ping, int availability_method);
void init_sockaddr (struct sockaddr_in *name, const char *hostname, unsigned short int port);
int init_socket();
unsigned short checksum(void* buf, int len);

