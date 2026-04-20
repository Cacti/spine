#ifndef SPINE_ASYNC_BATCH_H
#define SPINE_ASYNC_BATCH_H

#include <uv.h>
#include <mysql.h>

typedef struct {
    int pending_count;
    int active_queries;
    int max_pending;
    unsigned long dropped_queries;
    unsigned long enqueue_failures;
    unsigned long submitted_queries;
} spine_async_batch_stats_t;

/**
 * Initialize the asynchronous SQL batching system.
 * This starts the periodic flush timer on the main loop.
 */
int spine_async_batch_init(uv_loop_t *runtime_loop, MYSQL *mysql, int max_batch_size, int flush_interval_ms);

/**
 * Enqueue a SQL query to be executed as part of the next batch.
 * The query string must be null-terminated.
 */
int spine_async_batch_enqueue(const char *query);

/**
 * Force an immediate flush of the current batch queue.
 * Useful during shutdown.
 */
void spine_async_batch_flush(void);

/**
 * Tear down the batching system and close the timer handle.
 */
void spine_async_batch_cleanup(void);

/**
 * Retrieve queue/backpressure stats for observability.
 */
int spine_async_batch_get_stats(spine_async_batch_stats_t *out_stats);

#endif
