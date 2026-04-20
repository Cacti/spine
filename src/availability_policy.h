#ifndef SPINE_AVAILABILITY_POLICY_H
#define SPINE_AVAILABILITY_POLICY_H

#include "common.h"
#include "spine.h"

typedef struct AvailabilityInput {
	int host_status;
	int host_status_event_count;
	int poll_status;
	int availability_method;
	int ping_failure_count;
	int ping_recovery_count;
	int snmp_version;
	int has_snmp_community;
	const char *snmp_status;
	const char *ping_status;
	const char *snmp_response;
	const char *ping_response;
} AvailabilityInput;

typedef struct AvailabilityDecision {
	int next_status;
	int next_status_event_count;
	int issue_log_message;
	double effective_ping_time;
	char status_last_error[BUFSIZE * 2 + 2];
} AvailabilityDecision;

AvailabilityDecision availability_policy_decide(const AvailabilityInput *input);

#endif
