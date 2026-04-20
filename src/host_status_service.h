#ifndef SPINE_HOST_STATUS_SERVICE_H
#define SPINE_HOST_STATUS_SERVICE_H

#include "common.h"
#include "spine.h"
#include "availability_policy.h"

void host_status_service_apply(spine_spine_host_t *host, const AvailabilityDecision *decision);

#endif
