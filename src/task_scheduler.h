#ifndef SPINE_TASK_SCHEDULER_H
#define SPINE_TASK_SCHEDULER_H

#include "task_types.h"

/**
 * Initialize the global Weighted Round-Robin (WRR) queue scheduler.
 */
void spine_scheduler_init(void);

/**
 * Clean up scheduler state and queued tasks.
 */
void spine_scheduler_destroy(void);

/**
 * Enqueue a task into the correct lane for dispatching.
 */
void spine_scheduler_enqueue(spine_task_t *task);

/**
 * Attempt to dequeue tasks and dispatch them to the executor.
 * Respects all multi-layer concurrency governors and WRR weights.
 * Should be called frequently by the libuv event loop.
 */
void spine_scheduler_tick(uv_loop_t *loop);

/**
 * Returns the number of currently active hosts in the scheduler.
 */
uint32_t spine_scheduler_get_active_hosts(void);

/**
 * Returns the total number of tasks currently queued across all hosts.
 */
uint32_t spine_scheduler_get_queued_count(void);

#endif
