#ifndef SPINE_TASK_GOVERNOR_H
#define SPINE_TASK_GOVERNOR_H

#include "task_types.h"

/**
 * Initialize the governors with global concurrency constraints.
 */
void spine_governor_init(uint32_t max_global);

/**
 * Clean up governor state and hash tables.
 */
void spine_governor_destroy(void);

/**
 * Check if global concurrency allows dispatch.
 */
bool spine_governor_global_allow(void);

/**
 * Check if the host concurrency limits allow dispatch.
 */
bool spine_governor_host_allow(uint32_t host_id);

/**
 * Check if the subnet concurrency limits allow dispatch.
 */
bool spine_governor_subnet_allow(uint32_t subnet_id);

/**
 * Consume a token (dispatching a task).
 */
void spine_governor_consume(spine_task_t *task);

/**
 * Release a token (task completed). Adjusts adaptive host limits.
 */
void spine_governor_release(spine_task_t *task, bool success);

/**
 * Returns the current global inflight task count.
 */
uint32_t spine_governor_get_global_inflight(void);

#endif
