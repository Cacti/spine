/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "internal/common.h"
#include "app/spine.h"
#include "snmp/response.h"

int snmp_format_scalar(char *output, const struct variable_list *variable, bool ascii) {
	char temporary[RESULTS_BUFFER] = {0};
	if (variable->name == NULL || snprint_value(temporary, sizeof(temporary), variable->name, variable->name_length, variable) < 0) {
		SET_UNDEFINED(output);
		return STAT_ERROR;
	}
	if (ascii) {
		if (snprint_asciistring(output, RESULTS_BUFFER, (unsigned char *) temporary, strlen(temporary)) < 0) {
			SET_UNDEFINED(output);
			return STAT_ERROR;
		}
	} else {
		strncopy(output, trim(temporary), RESULTS_BUFFER);
	}
	return STAT_SUCCESS;
}

int snmp_get_variable(const host_t *host, const char *text_oid, const struct variable_list *variable, char *output) {
	switch (variable->type) {
		case SNMP_NOSUCHOBJECT:
			if (strstr(text_oid, ".1.3.6.1.2.1.1.1.0") || strstr(text_oid, ".1.3.6.1.2.1.1.3.0")) {
				SPINE_LOG_HIGH(("DEBUG: OID '%s' for Device[%i], SNMP_NOSUCHOBJECT for sysDesc or sysUptime", text_oid, host->id));
				return snmp_format_scalar(output, variable, FALSE);
			}
			SPINE_LOG_DEBUG(("DEBUG: OID '%s' for Device[%i], SNMP_NOSUCHOBJECT not sysDesc or sysUptime", text_oid, host->id));
			break;
		case SNMP_NOSUCHINSTANCE:
			if (strstr(text_oid, ".1.3.6.1.6.3.10.2.1.3.0")) {
				SPINE_LOG_DEBUG(("NOTE: Legacy SNMP agent found! No per second Uptime oid '%s' for Device[%i]", text_oid, host->id));
			} else {
				SPINE_LOG_HIGH(("WARNING: No such Instance for oid '%s' for Device[%i]", text_oid, host->id));
			}
			break;
		case SNMP_ENDOFMIBVIEW:
			SPINE_LOG_HIGH(("ERROR: End of Mib for oid '%s' for Device[%i]", text_oid, host->id));
			break;
		default: return snmp_format_scalar(output, variable, FALSE);
	}
	SET_UNDEFINED(output);
	return STAT_ERROR;
}

void snmp_snprint_value(char *obuf, size_t buf_len, const oid *objid, size_t objidlen, const struct variable_list *variable) {
	(void) objid;
	(void) objidlen;
	if (obuf == NULL || buf_len == 0) return;
	u_char *buf = calloc(buf_len, sizeof(*buf));
	if (buf == NULL) {
		snprintf(obuf, buf_len, "%s", "U");
		return;
	}
	size_t scratch_capacity = buf_len;
	size_t out_len = 0;
	if (sprint_realloc_by_type(&buf, &scratch_capacity, &out_len, 0, variable, NULL, NULL, NULL)) {
		snprintf(obuf, buf_len, "%s", buf);
	} else {
		snprintf(obuf, buf_len, "%s", "U");
	}
	free(buf);
}

int snmp_varbind_is_exception(const struct variable_list *vars) {
	if (vars == NULL) {
		return FALSE;
	}

	return (vars->type == SNMP_NOSUCHOBJECT ||
		vars->type == SNMP_NOSUCHINSTANCE ||
		vars->type == SNMP_ENDOFMIBVIEW);
}
