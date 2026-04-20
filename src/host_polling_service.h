#ifndef SPINE_HOST_POLLING_SERVICE_H
#define SPINE_HOST_POLLING_SERVICE_H

#include "common.h"
#include "spine.h"

typedef enum ResultCode {
	RESULT_CODE_OK = 0,
	RESULT_CODE_ERROR = 1
} ResultCode;

typedef enum HostPollingStage {
	HOST_POLL_STAGE_LOAD_WORK_ITEMS = 0,
	HOST_POLL_STAGE_CHECK_AVAILABILITY = 1,
	HOST_POLL_STAGE_POLL_ITEMS = 2,
	HOST_POLL_STAGE_PERSIST_RESULTS = 3,
	HOST_POLL_STAGE_UPDATE_HOST_STATE = 4
} HostPollingStage;

typedef struct HostPollingStageOutput {
	ResultCode code;
	int host_errors;
	int retryable;
} HostPollingStageOutput;

struct HostPollingRequest;
typedef ResultCode (*HostPollingStageFn)(const struct HostPollingRequest *request, HostPollingStageOutput *output);

typedef struct HostPollingRequest {
	int device_counter;
	int host_id;
	int spine_host_thread;
	int spine_host_threads;
	int host_data_ids;
	char *spine_host_time;
	int *host_errors;
	double spine_host_time_double;
	void *user_data;
	int max_retries;
	HostPollingStageFn on_load_work_items;
	HostPollingStageFn on_check_availability;
	HostPollingStageFn on_poll_items;
	HostPollingStageFn on_persist_results;
	HostPollingStageFn on_update_host_state;
} HostPollingRequest;

typedef struct HostPollingResult {
	ResultCode code;
	int host_errors;
	HostPollingStage failed_stage;
	int retries_used;
} HostPollingResult;

HostPollingResult host_polling_service_run(const HostPollingRequest *request);

#endif
