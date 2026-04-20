#include "common.h"
#include "spine.h"
#include "host_status_service.h"

void host_status_service_apply(spine_spine_host_t *host, const AvailabilityDecision *decision) {
	if (host == NULL || decision == NULL) {
		return;
	}

	host->status = decision->next_status;
	host->status_event_count = decision->next_status_event_count;

	if (decision->status_last_error[0] != '\0') {
		snprintf(host->status_last_error, sizeof(host->status_last_error), "%s", decision->status_last_error);
	}
}
