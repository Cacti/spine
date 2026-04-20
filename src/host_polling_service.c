#include "common.h"
#include "spine.h"
#include "host_polling_service.h"

typedef struct HostPollingStagePlan {
	HostPollingStage stage;
	int retries_allowed;
} HostPollingStagePlan;

static HostPollingStageFn host_polling_stage_fn(const HostPollingRequest *request, HostPollingStage stage) {
	switch (stage) {
	case HOST_POLL_STAGE_LOAD_WORK_ITEMS:
		return request->on_load_work_items;
	case HOST_POLL_STAGE_CHECK_AVAILABILITY:
		return request->on_check_availability;
	case HOST_POLL_STAGE_POLL_ITEMS:
		return request->on_poll_items;
	case HOST_POLL_STAGE_PERSIST_RESULTS:
		return request->on_persist_results;
	case HOST_POLL_STAGE_UPDATE_HOST_STATE:
		return request->on_update_host_state;
	default:
		return NULL;
	}
}

static ResultCode host_polling_execute_stage(const HostPollingRequest *request, HostPollingStage stage,
	HostPollingResult *result, int retries_allowed) {
	HostPollingStageFn fn;
	HostPollingStageOutput output;
	int attempt = 0;

	fn = host_polling_stage_fn(request, stage);
	if (fn == NULL) {
		return RESULT_CODE_OK;
	}

	memset(&output, 0, sizeof(output));

	do {
		memset(&output, 0, sizeof(output));
		output.code = fn(request, &output);
		if (output.code == RESULT_CODE_OK) {
			if (output.host_errors > 0) {
				result->host_errors = output.host_errors;
			}
			return RESULT_CODE_OK;
		}

		if (!output.retryable || attempt >= retries_allowed) {
			result->failed_stage = stage;
			return RESULT_CODE_ERROR;
		}

		attempt++;
		result->retries_used++;
	} while (1);
}

HostPollingResult host_polling_service_run(const HostPollingRequest *request) {
	static const HostPollingStagePlan stage_plan[] = {
		{ HOST_POLL_STAGE_LOAD_WORK_ITEMS, 0 },
		{ HOST_POLL_STAGE_CHECK_AVAILABILITY, 0 },
		{ HOST_POLL_STAGE_POLL_ITEMS, -1 },
		{ HOST_POLL_STAGE_PERSIST_RESULTS, 0 },
		{ HOST_POLL_STAGE_UPDATE_HOST_STATE, 0 }
	};
	HostPollingResult result = {0};
	size_t i;

	result.failed_stage = HOST_POLL_STAGE_UPDATE_HOST_STATE;

	if (request == NULL) {
		result.code = RESULT_CODE_ERROR;
		result.host_errors = 1;
		result.failed_stage = HOST_POLL_STAGE_LOAD_WORK_ITEMS;
		return result;
	}

	for (i = 0; i < sizeof(stage_plan) / sizeof(stage_plan[0]); i++) {
		int retries_allowed = stage_plan[i].retries_allowed;
		if (retries_allowed < 0) {
			retries_allowed = request->max_retries;
		}

		if (host_polling_execute_stage(request, stage_plan[i].stage, &result, retries_allowed) != RESULT_CODE_OK) {
			result.code = RESULT_CODE_ERROR;
			return result;
		}
	}

	result.code = RESULT_CODE_OK;
	return result;
}
