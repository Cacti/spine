#ifndef SPINE_TASK_TYPES_H
#define SPINE_TASK_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <uv.h>

typedef enum {
    STATE_IDLE       = 0,
    STATE_QUEUED     = 1,
    STATE_INFLIGHT   = 2,
    STATE_COMPLETED  = 3,
    STATE_FAILED     = 4
} spine_task_state_e;

typedef struct spine_task_s spine_task_t;

struct spine_task_s {
    /* Identity */
    uint32_t task_id;
    uint32_t host_id;
    uint32_t subnet_id;
    
    /* Payload (Pre-batched OIDs) */
    void *payload;
    size_t payload_len;
    
    /* Scheduling Metadata */
    spine_task_state_e state;
    uint8_t retry_count;
    uint8_t max_retries;
    uint32_t timeout_ms;
    uint64_t deadline_ns;
    
    /* Intrusive Pointers */
    spine_task_t *next;
    spine_task_t *prev_inflight;
    spine_task_t *next_inflight;
    
    /* Libuv State (Allocated inline to avoid hot-path mallocs) */
    uv_timer_t timer;
    void *io_handle; /* e.g., uv_udp_send_t */
    
    /* Completion State (Safe across uv_close boundary) */
    int final_status;
    void *final_result;
    void *parent_ctx; /* Pointer to poll_context_t */
    
    /* Hooks */
    bool (*on_retry_prepare)(spine_task_t *task);
    void (*on_complete)(spine_task_t *task, int status, void *result);
};

#endif
