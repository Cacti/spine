#include "common.h"
#include "spine.h"
#include "availability_policy.h"

AvailabilityDecision availability_policy_decide(const AvailabilityInput *input) {
	AvailabilityDecision decision;
	double ping_time = 0.0;

	memset(&decision, 0, sizeof(decision));
	decision.next_status = input->host_status;
	decision.next_status_event_count = input->host_status_event_count;

	if (input->poll_status == HOST_DOWN) {
		switch (input->availability_method) {
		case AVAIL_SNMP_OR_PING:
		case AVAIL_SNMP_AND_PING:
			if (!input->has_snmp_community && input->snmp_version < 3) {
				snprintf(decision.status_last_error, sizeof(decision.status_last_error),
					"%s", input->ping_response ? input->ping_response : "");
			} else {
				snprintf(decision.status_last_error, sizeof(decision.status_last_error),
					"%s, %s",
					input->snmp_response ? input->snmp_response : "",
					input->ping_response ? input->ping_response : "");
			}
			break;
		case AVAIL_SNMP:
			if (!input->has_snmp_community && input->snmp_version < 3) {
				snprintf(decision.status_last_error, sizeof(decision.status_last_error),
					"%s", "Device does not require SNMP");
			} else {
				snprintf(decision.status_last_error, sizeof(decision.status_last_error),
					"%s", input->snmp_response ? input->snmp_response : "");
			}
			break;
		default:
			snprintf(decision.status_last_error, sizeof(decision.status_last_error),
				"%s", input->ping_response ? input->ping_response : "");
			break;
		}
	} else {
		if (input->availability_method == AVAIL_SNMP_AND_PING) {
			if (!input->has_snmp_community && input->snmp_version < 3) {
				ping_time = atof(input->ping_status ? input->ping_status : "0");
			} else {
				ping_time = (atof(input->snmp_status ? input->snmp_status : "0") +
					atof(input->ping_status ? input->ping_status : "0")) / 2.0;
			}
		} else if (input->availability_method == AVAIL_SNMP) {
			if (!input->has_snmp_community && input->snmp_version < 3) {
				ping_time = 0.0;
			} else {
				ping_time = atof(input->snmp_status ? input->snmp_status : "0");
			}
		} else if (input->availability_method == AVAIL_NONE) {
			ping_time = 0.0;
		} else {
			ping_time = atof(input->ping_status ? input->ping_status : "0");
		}
	}

	decision.effective_ping_time = ping_time;
	return decision;
}
