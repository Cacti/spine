/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2017 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

extern void snmp_spine_init(void);
extern void snmp_spine_close(void);
extern void *snmp_host_init(int host_id, char *hostname, int snmp_version, char *snmp_community, char *snmp_username, char *snmp_password, char *snmp_auth_protocol, char *snmp_priv_passphrase, char *snmp_priv_protocol, char *snmp_context, char *snmp_engine_id, int snmp_port, int snmp_timeout);
extern void snmp_host_cleanup(void *snmp_session);
extern char *snmp_get(host_t *current_host, char *snmp_oid);
extern char *snmp_getnext(host_t *current_host, char *snmp_oid);
extern int snmp_count(host_t *current_host, char *snmp_oid);
extern void snmp_get_multi(host_t *current_host, snmp_oids_t *snmp_oids, int num_oids);
extern void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, struct variable_list *variable);
