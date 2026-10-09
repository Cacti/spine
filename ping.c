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

#include "common.h"
#include "spine.h"
#include "src/ping/ping_internal.h"

/*! \fn int ping_host(host_t *host, ping_t *ping)
 *  \brief ping a host to determine if it is reachable for polling
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using the method specified within the system
 *  configuration and then returns the host status to the calling function.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 */
static int ping_network(host_t *host, ping_t *ping) {
	if (host->availability.ping_method == PING_ICMP && !set.availability.icmp_avail) {
		SPINE_LOG(("Device[%i] DEBUG Falling back to UDP Ping Due to SetUID Issues", host->id));
		host->availability.ping_method = PING_UDP;
	}
	if (strstr(host->hostname, "localhost")) {
		STRNCOPY(ping->ping_status, "0.000");
		STRNCOPY(ping->ping_response, "PING: Device does not require ping.");
		return HOST_UP;
	}
	int address_type = get_address_type(host);
	#ifdef SPINE_HAVE_ICMPV6
	if (address_type == SPINE_IPV6 && host->availability.ping_method == PING_ICMP) {
		return ping_icmp_ipv6(host, ping);
	}
	#endif
	if (address_type != SPINE_IPV4) {
		if (host->availability.method == AVAIL_PING) {
			STRNCOPY(ping->ping_status, "0.000");
			STRNCOPY(ping->ping_response, "PING: Device is Unknown or is IPV6.  Please use the SNMP ping options only.");
		}
		return HOST_DOWN;
	}
	switch (host->availability.ping_method) {
		case PING_ICMP: return ping_icmp(host, ping);
		case PING_UDP: return ping_udp(host, ping);
		case PING_TCP:
		case PING_TCP_CLOSED: return ping_tcp(host, ping);
		default: return HOST_DOWN;
	}
}

static int ping_snmp_availability(host_t *host, ping_t *ping, int ping_result) {
	if (host->availability.method == AVAIL_SNMP_AND_PING && ping_result != HOST_UP) return HOST_DOWN;
	if (host->availability.method == AVAIL_SNMP_OR_PING && ping_result == HOST_UP) return HOST_UP;
	/* Preserve the configured no-SNMP contract for v1/v2 without a community. */
	if (host->snmp.profile.community[0] == '\0' && host->snmp.profile.version < 3) return HOST_UP;
	double begin = get_time_as_double();
	int result = ping_snmp(host, ping);
	double elapsed = (get_time_as_double() - begin) * 1000.0;
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_MEDIUM,
		("Device[%i] INFO: SNMP Device %s, Time:%.4f ms", host->id, result == HOST_UP ? "Alive" : "Down", elapsed));
	return result;
}

int ping_host(host_t *host, ping_t *ping) {
	int network_result = HOST_DOWN;
	if (host->availability.method == AVAIL_SNMP_AND_PING ||
		host->availability.method == AVAIL_PING ||
		host->availability.method == AVAIL_SNMP_OR_PING) {
		network_result = ping_network(host, ping);
	}
	switch (host->availability.method) {
		case AVAIL_SNMP_AND_PING:
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP:
		case AVAIL_SNMP_GET_NEXT:
		case AVAIL_SNMP_GET_SYSDESC:
			return ping_snmp_availability(host, ping, network_result);
		case AVAIL_PING: return network_result;
		case AVAIL_NONE: return HOST_UP;
		default: return HOST_DOWN;
	}
}

/*! \fn int ping_snmp(host_t *host, ping_t *ping)
 *  \brief ping a host using snmp sysUptime
 *  \param host a pointer to the current host structure
 *  \param ping a pointer to the current hosts ping structure
 *
 *  This function pings a host using snmp.  It polls sysUptime by default.
 *  It will modify the ping structure to include the specifics of the ping results.
 *
 *  \return HOST_UP if the host is reachable, HOST_DOWN otherwise.
 *
 */
int ping_snmp(host_t *host, ping_t *ping) {
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_DEBUG, ("Device[%i] DEBUG: Entering SNMP Ping", host->id));
	if (!host->snmp.session) {
		STRNCOPY(ping->snmp_status, "0.00");
		STRNCOPY(ping->snmp_response, "Invalid SNMP Session");
		return HOST_DOWN;
	}
	if (host->snmp.profile.community[0] == '\0' && host->snmp.profile.version != 3) {
		STRNCOPY(ping->snmp_status, "0.00");
		STRNCOPY(ping->snmp_response, "Device does not require SNMP");
		return HOST_UP;
	}
	char oid[32];
	switch (host->availability.method) {
		case AVAIL_SNMP_GET_NEXT: STRNCOPY(oid, ".1.3"); break;
		case AVAIL_SNMP_GET_SYSDESC: STRNCOPY(oid, ".1.3.6.1.2.1.1.1.0"); break;
		default: STRNCOPY(oid, ".1.3.6.1.2.1.1.3.0"); break;
	}
	double begin = get_time_as_double();
	char *result = host->availability.method == AVAIL_SNMP_GET_NEXT ? snmp_getnext(host, oid) : snmp_get(host, oid);
	double elapsed = (get_time_as_double() - begin) * 1000.0;
	SPINE_FREE(result);
	if (host->snmp.status == SNMPERR_SUCCESS || host->snmp.status == SNMPERR_UNKNOWN_OBJID) {
		STRNCOPY(ping->snmp_response, "Device responded to SNMP");
		spine_snprintf(ping->snmp_status, sizeof(ping->snmp_status), "%.5f", elapsed);
		return HOST_UP;
	}
	SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH,
		("Device[%i] SNMP Ping %s", host->id, host->snmp.status == STAT_TIMEOUT ? "Timeout" : "Unknown Error"));
	STRNCOPY(ping->snmp_response, "Device did not respond to SNMP");
	return HOST_DOWN;
}



static bool host_requires_snmp(const host_t *host) {
	return host->snmp.profile.community[0] != '\0' || host->snmp.profile.version >= 3;
}

static void host_failure_message(host_t *host, const ping_t *ping, int method) {
	switch (method) {
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP_AND_PING:
			if (host_requires_snmp(host)) {
				snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s, %s", ping->snmp_response, ping->ping_response);
			} else {
				snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
			}
			break;
		case AVAIL_SNMP:
			snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", host_requires_snmp(host) ? ping->snmp_response : "Device does not require SNMP");
			break;
		default:
			snprintf(host->state.status_last_error, BUFSIZE * 2 + 1, "%s", ping->ping_response);
	}
}

static bool host_failure_transition(host_t *host, const char *date) {
	switch (host->state.status) {
		case HOST_UP:
			host->state.status_event_count++;
			if (host->state.status_event_count >= set.availability.ping_failure_count) {
				host->state.status = HOST_DOWN;
				if (set.availability.ping_failure_count == 1) snprintf(host->state.status_fail_date, sizeof(host->state.status_fail_date), "%s", date);
				return TRUE;
			}
			if (host->state.status_event_count == 1) snprintf(host->state.status_fail_date, sizeof(host->state.status_fail_date), "%s", date);
			return FALSE;
		case HOST_RECOVERING:
			host->state.status_event_count = 1;
			host->state.status = HOST_DOWN;
			return FALSE;
		case HOST_UNKNOWN:
			host->state.status = HOST_DOWN;
			host->state.status_event_count = 0;
			return FALSE;
		default:
			host->state.status_event_count++;
			return FALSE;
	}
}

static bool host_recovery_transition(host_t *host, const char *date) {
	if (host->state.status != HOST_DOWN && host->state.status != HOST_RECOVERING) {
		host->state.status = HOST_UP;
		host->state.status_event_count = 0;
		return FALSE;
	}
	if (host->state.status == HOST_DOWN) {
		host->state.status = HOST_RECOVERING;
		host->state.status_event_count = 1;
	} else {
		host->state.status_event_count++;
	}
	if (host->state.status_event_count >= set.availability.ping_recovery_count) {
		host->state.status = HOST_UP;
		if (set.availability.ping_recovery_count == 1) snprintf(host->state.status_rec_date, sizeof(host->state.status_rec_date), "%s", date);
		host->state.status_event_count = 0;
		return TRUE;
	}
	if (host->state.status_event_count == 1) snprintf(host->state.status_rec_date, sizeof(host->state.status_rec_date), "%s", date);
	return FALSE;
}

static double host_response_time(const host_t *host, const ping_t *ping, int method) {
	switch (method) {
		case AVAIL_SNMP_AND_PING:
			return host_requires_snmp(host) ? (atof(ping->snmp_status) + atof(ping->ping_status)) / 2 : atof(ping->ping_status);
		case AVAIL_SNMP:
			return host_requires_snmp(host) ? atof(ping->snmp_status) : 0.0;
		case AVAIL_NONE:
			return 0.0;
		default:
			return atof(ping->ping_status);
	}
}

static void host_response_statistics(host_t *host, double ping_time) {
	host->statistics.cur_time = ping_time;
	if (ping_time > host->statistics.max_time) host->statistics.max_time = ping_time;
	if (ping_time < host->statistics.min_time) host->statistics.min_time = ping_time;
	host->statistics.avg_time = (((host->statistics.total_polls - 1 - host->statistics.failed_polls) * host->statistics.avg_time) + ping_time) / (host->statistics.total_polls - host->statistics.failed_polls);
}

static void log_host_availability(const host_t *host, const ping_t *ping, int method) {
	if (set.logging.log_level < POLLER_VERBOSITY_HIGH) return;
	bool up = host->state.status == HOST_UP || host->state.status == HOST_RECOVERING;
	if (method == AVAIL_SNMP_AND_PING || (method == AVAIL_SNMP_OR_PING && up)) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING Result: %s", host->id, ping->ping_response));
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] SNMP Result: %s", host->id, ping->snmp_response));
	} else if (method == AVAIL_SNMP) {
		const char *message = up && !host_requires_snmp(host) ? "Device does not require SNMP" : ping->snmp_response;
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] SNMP Result: %s", host->id, message));
	} else if (method == AVAIL_NONE) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] No Device Availability Method Selected", host->id));
	} else if (up) {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING: Result %s", host->id, ping->ping_response));
	} else {
		SPINE_LOG_DEVICE(host->id, POLLER_VERBOSITY_HIGH, ("Device[%i] PING Result: %s", host->id, ping->ping_response));
	}
}

/*! Update availability statistics and apply failure/recovery thresholds. */
void update_host_status(int status, host_t *host, const ping_t *ping, int availability_method) {
	char current_date[40];
	snprintf(current_date, sizeof(current_date), "%lu", time(NULL));
	bool issue_log_message;
	host->statistics.total_polls++;
	if (status == HOST_DOWN) {
		host->statistics.failed_polls++;
		host_failure_message(host, ping, availability_method);
		issue_log_message = host_failure_transition(host, current_date);
	} else {
		host_response_statistics(host, host_response_time(host, ping, availability_method));
		issue_log_message = host_recovery_transition(host, current_date);
	}
	host->statistics.availability = 100.0 * (host->statistics.total_polls - host->statistics.failed_polls) / host->statistics.total_polls;
	log_host_availability(host, ping, availability_method);
	if (!issue_log_message) return;
	if (host->state.status == HOST_DOWN) {
		SPINE_LOG(("Device[%i] Hostname[%s] ERROR: HOST EVENT: Device is DOWN Message: %s", host->id, host->hostname, host->state.status_last_error));
	} else {
		SPINE_LOG(("Device[%i] Hostname[%s] NOTICE: HOST EVENT: Device Returned from DOWN State", host->id, host->hostname));
	}
}
