#include "task_executor.h"
#include "task_governor.h"
#include "task_scheduler.h"
#include <stdlib.h>
#include <errno.h>

/* Use UV_ETIMEDOUT if available, else a standard negative error code */
#ifndef UV_ETIMEDOUT
#define UV_ETIMEDOUT -110 /* ETIMEDOUT */
#endif

static void on_timeout(uv_timer_t *timer) {
    spine_task_t *task = (spine_task_t *)timer->data;
    /* Cancel I/O handle if active (e.g., uv_udp_recv_stop) */
    /* For now, just trigger completion with timeout error */
    spine_executor_complete_task(task, UV_ETIMEDOUT, NULL);
}

void spine_executor_dispatch(uv_loop_t *loop, spine_task_t *task) {
    task->state = STATE_INFLIGHT;
    
    /* 1. Arm Timeout inline within the task structure */
    uv_timer_init(loop, &task->timer);
    task->timer.data = task;
    
    uint32_t timeout = task->timeout_ms > 0 ? task->timeout_ms : 1000;
    uv_timer_start(&task->timer, on_timeout, timeout, 0);
    
    /* 2. Dispatch I/O (Pseudo dispatch for mock testing and gradual cutover) */
    /* In actual integration, uv_udp_send / SNMP payload logic goes here */
    if (task->payload) {
        /* Pseudo-execute immediately for test runner compatibility */
    }
}

/* ONLY called via uv_close callback to ensure safe memory teardown */
static void on_timer_closed(uv_handle_t *handle) {
    spine_task_t *task = (spine_task_t *)handle->data;
    
    /* CRITICAL FIX: Do not retry if the failure was a deliberate teardown cancellation */
    if (task->final_status == -125) {
        task->state = STATE_FAILED;
        if (task->on_complete) task->on_complete(task, task->final_status, task->final_result);
        spine_task_free(task);
        return;
    }


    /* Proceed with final completion ONLY after libuv releases the handle */
    if (task->final_status != 0 && task->retry_count < task->max_retries) {
        
        /* 4. SNMP Batch Slicing / tooBig handling hook */
        if (task->on_retry_prepare) {
            if (!task->on_retry_prepare(task)) {
                /* Task is unsalvageable (e.g. payload couldn't be split) */
                task->state = STATE_FAILED;
                if (task->on_complete) task->on_complete(task, task->final_status, task->final_result);
                spine_task_free(task);
                return;
            }
        }
        
        task->retry_count++;
        spine_scheduler_inc_retries();
        spine_scheduler_enqueue(task);
    } else {
        task->state = (task->final_status == 0) ? STATE_COMPLETED : STATE_FAILED;
        if (task->on_complete) {
            task->on_complete(task, task->final_status, task->final_result);
        }
        /* Now it is safely freed back into the Slab Allocator pool */
        spine_task_free(task);
    }
}

void spine_executor_complete_task(spine_task_t *task, int status, void *result) {
    if (task->state != STATE_INFLIGHT) return; /* Prevent double-completion */
    
    task->final_status = status;
    task->final_result = result;
    
    /* 1. Release Governor Tokens IMMEDIATELY so other tasks can dispatch */
    spine_governor_release(task, (status == 0));
    
    /* 2. Remove from global inflight tracker */
    spine_scheduler_inflight_remove(task);
    
    /* 3. Stop and close. Logic continues in on_timer_closed to prevent Use-After-Free */
    uv_timer_stop(&task->timer);
    uv_close((uv_handle_t *)&task->timer, on_timer_closed);
}
