#ifndef SPINE_HOST_POLLING_STAGES_H
#define SPINE_HOST_POLLING_STAGES_H

#include "common.h"
#include "spine.h"
#include "host_polling_service.h"

ResultCode host_polling_stage_load_work_items(const HostPollingRequest *request, HostPollingStageOutput *output);
ResultCode host_polling_stage_check_availability(const HostPollingRequest *request, HostPollingStageOutput *output);
ResultCode host_polling_stage_persist_results(const HostPollingRequest *request, HostPollingStageOutput *output);
ResultCode host_polling_stage_update_host_state(const HostPollingRequest *request, HostPollingStageOutput *output);

#endif
