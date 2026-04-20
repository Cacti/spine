#include "common.h"
#include "spine.h"
#include "host_polling_stages.h"

ResultCode host_polling_stage_load_work_items(const HostPollingRequest *request, HostPollingStageOutput *output) {
	if (request == NULL || request->host_errors == NULL || output == NULL) {
		return RESULT_CODE_ERROR;
	}

	*request->host_errors = 0;
	output->host_errors = 0;
	output->retryable = 0;
	return RESULT_CODE_OK;
}

ResultCode host_polling_stage_check_availability(const HostPollingRequest *request, HostPollingStageOutput *output) {
	if (request == NULL || output == NULL) {
		return RESULT_CODE_ERROR;
	}

	if (request->host_id <= 0) {
		SPINE_LOG(("WARNING: Invalid host_id %d, skipping host poll pipeline", request->host_id));
		output->retryable = 0;
		return RESULT_CODE_ERROR;
	}

	output->retryable = 0;
	return RESULT_CODE_OK;
}

ResultCode host_polling_stage_persist_results(const HostPollingRequest *request, HostPollingStageOutput *output) {
	if (request == NULL || output == NULL) {
		return RESULT_CODE_ERROR;
	}

	output->host_errors = request->host_errors ? *request->host_errors : 0;
	output->retryable = 0;
	return RESULT_CODE_OK;
}

ResultCode host_polling_stage_update_host_state(const HostPollingRequest *request, HostPollingStageOutput *output) {
	if (request == NULL || output == NULL) {
		return RESULT_CODE_ERROR;
	}

	output->host_errors = request->host_errors ? *request->host_errors : 0;
	output->retryable = 0;
	return RESULT_CODE_OK;
}
