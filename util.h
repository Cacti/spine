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

int read_config_options(config_t *set);
int read_cactid_config(char *file, config_t * set);
void config_defaults(config_t *);
void timestamp(char *);
int file_exists(char *filename);
void cacti_log(char *logmessage);
int is_number(char *string);
char *clean_string(char *string_to_clean);
int ping_host(host_t *host, ping_t *ping);
int update_host_status(int status, host_t *host, ping_t *ping, int availability_method);
void init_sockaddr (struct sockaddr_in *name, const char *hostname, unsigned short int port);
int init_socket();
unsigned short checksum(void* buf, int len);
