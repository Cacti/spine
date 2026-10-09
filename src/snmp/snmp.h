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

#ifndef SPINE_SNMP_H
#define SPINE_SNMP_H
#define SNMP_SESSION_FREE(s) \
	{ \
		if (s != NULL) { \
			snmp_host_cleanup(s); \
			s = NULL; \
		} \
	}

extern void snmp_spine_init(void);
extern void snmp_spine_close(void);
/* Borrowed connection inputs; Net-SNMP clones the session before return. */
typedef struct {
	int host_id;
	char *hostname;
	int snmp_version;
	char *snmp_community;
	char *snmp_username;
	const char *snmp_password;
	char *snmp_auth_protocol;
	const char *snmp_priv_passphrase;
	char *snmp_priv_protocol;
	char *snmp_context;
	char *snmp_engine_id;
	int snmp_port;
	int snmp_timeout;
} snmp_connection_t;

extern void *snmp_host_init(const snmp_connection_t *options);
extern void snmp_host_cleanup(void *snmp_session);
extern char *snmp_get_base(host_t *current_host, char *snmp_oid, bool should_fail);
extern char *snmp_get(host_t *current_host, char *snmp_oid);
extern char *snmp_get_allow_fail(host_t *current_host, char *snmp_oid);
extern char *snmp_getnext(host_t *current_host, char *snmp_oid);
extern int spine_snmpv3_protocol_is_set(const char *value);
extern int spine_snmpv3_passphrase_is_set(const char *value);
extern int spine_snmpv3_security_level(const char *auth_protocol, const char *auth_password,
	const char *priv_protocol, const char *priv_passphrase);
extern int snmp_varbind_is_exception(const struct variable_list *vars);
extern int snmp_count(host_t *current_host, char *snmp_oid);
extern void snmp_get_multi(host_t *current_host, const target_t *poller_items, snmp_oids_t *snmp_oids, int num_oids);
extern void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, const struct variable_list *variable);

#endif /* SPINE_SNMP_H */
