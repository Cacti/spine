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
#include "poller/poller_internal.h"
#include <limits.h>

static void host_metadata_defaults(host_t *host) {
	/* initialize variables first */
	host->id = 0; // 0
	host->hostname[0] = '\0'; // 1
	host->snmp.session = NULL; // -
	host->snmp.profile.community[0] = '\0'; // 2
	host->snmp.profile.version = 1; // 3
	host->snmp.profile.username[0] = '\0'; // 4
	host->snmp.profile.password[0] = '\0'; // 5
	host->snmp.profile.auth_protocol[0] = '\0'; // 6
	host->snmp.profile.priv_passphrase[0] = '\0'; // 7
	host->snmp.profile.priv_protocol[0] = '\0'; // 8
	host->snmp.profile.context[0] = '\0'; // 9
	host->snmp.profile.engine_id[0] = '\0'; // 10
	host->snmp.profile.port = 161; // 11
	host->snmp.profile.timeout = 500; // 12
	host->snmp.retries = set.snmp.snmp_retries; // -
	host->snmp.max_oids = 10; // 13
	host->availability.method = 0; // 14
	host->availability.ping_method = 0; // 15
	host->availability.port = 23; // 16
	host->availability.timeout = 500; // 17
	host->availability.retries = 2; // 18
	host->state.status = HOST_UP; // 19
	host->state.status_event_count = 0; // 20
	host->state.status_fail_date[0] = '\0'; // 21
	host->state.status_rec_date[0] = '\0'; // 22
	host->state.status_last_error[0] = '\0'; // 23
	host->statistics.min_time = 0; // 24
	host->statistics.max_time = 0; // 25
	host->statistics.cur_time = 0; // 26
	host->statistics.avg_time = 0; // 27
	host->statistics.total_polls = 0; // 28
	host->statistics.failed_polls = 0; // 29
	host->statistics.availability = 100; // 30
	host->system.snmp_sysUpTimeInstance = 0; // 31
	host->system.snmp_sysDescr[0] = '\0'; // 32
	host->system.snmp_sysObjectID[0] = '\0'; // 33
	host->system.snmp_sysContact[0] = '\0'; // 34
	host->system.snmp_sysName[0] = '\0'; // 35
	host->system.snmp_sysLocation[0] = '\0'; // 36
}

static void host_metadata_connection(host_t *host, MYSQL_ROW row) {
	/* populate host structure */
	host->ignore_host = FALSE;
	if (row[0] != NULL) host->id = atoi(row[0]);

	if (row[1] != NULL) {
		name_t *name = get_namebyhost(row[1], NULL);
		STRNCOPY(host->hostname, name->hostname);
		host->availability.port = name->port;
		SPINE_FREE(name);
	}

	if (row[2] != NULL) STRNCOPY(host->snmp.profile.community, row[2]);

	if (row[3] != NULL) host->snmp.profile.version = atoi(row[3]);

	if (row[4] != NULL) STRNCOPY(host->snmp.profile.username, row[4]);
	if (row[5] != NULL) STRNCOPY(host->snmp.profile.password, row[5]);
	if (row[6] != NULL) STRNCOPY(host->snmp.profile.auth_protocol, row[6]);
	if (row[7] != NULL) STRNCOPY(host->snmp.profile.priv_passphrase, row[7]);
	if (row[8] != NULL) STRNCOPY(host->snmp.profile.priv_protocol, row[8]);
	if (row[9] != NULL) STRNCOPY(host->snmp.profile.context, row[9]);
	if (row[10] != NULL) STRNCOPY(host->snmp.profile.engine_id, row[10]);

	if (row[11] != NULL) host->snmp.profile.port = atoi(row[11]);
	if (row[12] != NULL) host->snmp.profile.timeout = atoi(row[12]);
	if (row[13] != NULL) host->snmp.max_oids = atoi(row[13]);
}

static void host_metadata_status(host_t *host, MYSQL_ROW row) {
	if (row[14] != NULL) host->availability.method = atoi(row[14]);
	if (row[15] != NULL) host->availability.ping_method = atoi(row[15]);
	if (row[16] != NULL) host->availability.port = atoi(row[16]);
	if (row[17] != NULL) host->availability.timeout = atoi(row[17]);
	if (row[18] != NULL) host->availability.retries = atoi(row[18]);

	if (row[19] != NULL) host->state.status = atoi(row[19]);
	if (row[20] != NULL) host->state.status_event_count = atoi(row[20]);

	if (row[21] != NULL) STRNCOPY(host->state.status_fail_date, row[21]);
	if (row[22] != NULL) STRNCOPY(host->state.status_rec_date, row[22]);

	if (row[23] != NULL) STRNCOPY(host->state.status_last_error, row[23]);
}

static void host_metadata_statistics(host_t *host, MYSQL_ROW row) {
	if (row[24] != NULL) host->statistics.min_time = atof(row[24]);
	if (row[25] != NULL) host->statistics.max_time = atof(row[25]);
	if (row[26] != NULL) host->statistics.cur_time = atof(row[26]);
	if (row[27] != NULL) host->statistics.avg_time = atof(row[27]);
	if (row[28] != NULL) host->statistics.total_polls = atoi(row[28]);
	if (row[29] != NULL) host->statistics.failed_polls = atoi(row[29]);
	if (row[30] != NULL) host->statistics.availability = atof(row[30]);
}

static void host_metadata_system(host_t *host, MYSQL_ROW row, MYSQL *mysql) {
	if (row[31] != NULL) host->system.snmp_sysUpTimeInstance = atoll(row[31]);
	if (row[32] != NULL) db_escape(mysql, host->system.snmp_sysDescr, sizeof(host->system.snmp_sysDescr), row[32]);
	if (row[33] != NULL) db_escape(mysql, host->system.snmp_sysObjectID, sizeof(host->system.snmp_sysObjectID), row[33]);
	if (row[34] != NULL) db_escape(mysql, host->system.snmp_sysContact, sizeof(host->system.snmp_sysContact), row[34]);
	if (row[35] != NULL) db_escape(mysql, host->system.snmp_sysName, sizeof(host->system.snmp_sysName), row[35]);
	if (row[36] != NULL) db_escape(mysql, host->system.snmp_sysLocation, sizeof(host->system.snmp_sysLocation), row[36]);
}



void load_host_metadata(MYSQL *mysql, MYSQL_ROW row, host_t *host, const poller_thread_t *work) {
	host_metadata_defaults(host);
	host_metadata_connection(host, row);
	host_metadata_status(host, row);
	host_metadata_statistics(host, row);
	host_metadata_system(host, row, mysql);

	/* correct max_oid bounds issues */
	if ((host->snmp.max_oids == 0) || (host->snmp.max_oids > 100)) {
		SPINE_LOG(("Device[%i] HT[%i] WARNING: Max OIDS is out of range with value of '%i'.  Resetting to default of 5", work->host_id, work->host_thread, host->snmp.max_oids));
		host->snmp.max_oids = 5;
	}
}

void initialize_host_snmp(host_t *host) {
	if (((host->snmp.profile.version >= 1) && (host->snmp.profile.version <= 2) &&
			(strlen(host->snmp.profile.community) > 0)) ||
		(host->snmp.profile.version == 3)) {
		host->snmp.session = snmp_host_init(&(snmp_connection_t){
			.host_id = host->id,
			.hostname = host->hostname,
			.snmp_version = host->snmp.profile.version,
			.snmp_community = host->snmp.profile.community,
			.snmp_username = host->snmp.profile.username,
			.snmp_password = host->snmp.profile.password,
			.snmp_auth_protocol = host->snmp.profile.auth_protocol,
			.snmp_priv_passphrase = host->snmp.profile.priv_passphrase,
			.snmp_priv_protocol = host->snmp.profile.priv_protocol,
			.snmp_context = host->snmp.profile.context,
			.snmp_engine_id = host->snmp.profile.engine_id,
			.snmp_port = host->snmp.profile.port,
			.snmp_timeout = host->snmp.profile.timeout,
		});
	} else {
		host->snmp.session = NULL;
	}
}

bool refresh_host_availability(MYSQL *mysql, host_t *host, ping_t *ping, int host_thread) {
	if (host->availability.method == AVAIL_SNMP && strlen(host->snmp.profile.community) == 0 && host->snmp.profile.version < 3) {
		host->ignore_host = FALSE;
		update_host_status(HOST_UP, host, ping, host->availability.method);
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM, ("Device[%i] HT[%i] No host availability check possible for '%s'", host->id, host_thread, host->hostname));
		return FALSE;
	}
	if (host->availability.method == AVAIL_STREAM) {
		update_host_status(HOST_UP, host, ping, host->availability.method);
		return FALSE;
	}
	bool alive = ping_host(host, ping) == HOST_UP;
	host->ignore_host = !alive;
	if (host_thread != 1) return FALSE;
	update_host_status(alive ? HOST_UP : HOST_DOWN, host, ping, host->availability.method);
	if (!alive || host->availability.method == AVAIL_PING || host->availability.method == AVAIL_NONE || host->snmp.session == NULL || !set.snmp.mibs) return FALSE;
	get_system_information(host, mysql, 1);
	return TRUE;
}
