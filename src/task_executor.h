#ifndef SPINE_TASK_EXECUTOR_H
#define SPINE_TASK_EXECUTOR_H

#include "task_types.h"

/**
 * Dispatch an OID task to the libuv event loop.
 */
void spine_executor_dispatch(uv_loop_t *loop, spine_task_t *task);

/**
 * Single, explicit completion path for all scheduled tasks.
 * Releases governor tokens, manages retries, and fires user callbacks.
 */
void spine_executor_complete_task(spine_task_t *task, int status, void *result);

#endif
