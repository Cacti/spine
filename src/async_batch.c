#include "common.h"
#include "spine.h"
#include "async_mysql.h"
#include "async_batch.h"

#include <errno.h>

typedef struct async_batch_item {
    char *query;
    struct async_batch_item *next;
} async_batch_item_t;

typedef struct {
    uv_loop_t *loop;
    MYSQL *mysql;
    uv_timer_t flush_timer;
    async_batch_item_t *head;
    async_batch_item_t *tail;
    int pending_count;
    int max_pending;
    int flush_interval_ms;
    int active_queries;
    unsigned long dropped_queries;
    unsigned long enqueue_failures;
    unsigned long submitted_queries;
    bool initialized;
    bool closing;
} async_batch_ctx_t;

static async_batch_ctx_t g_batch_ctx = {0};

static void dispatch_next(void);

static void batch_query_cb(MYSQL *mysql, int status, void *data) {
    async_batch_item_t *item = (async_batch_item_t *)data;
    (void)mysql;

    if (status != 0) {
        SPINE_LOG(("ERROR: Async batch flush failed with status %d", status));
    } else {
        SPINE_LOG_DEVDBG(("DEBUG: Async batch flush succeeded"));
    }

    if (item != NULL) {
        free(item->query);
        free(item);
    }

    g_batch_ctx.active_queries--;
    if (!g_batch_ctx.closing) {
        dispatch_next();
    }
}

static int queue_push(const char *query) {
    async_batch_item_t *item;

    if (query == NULL || *query == '\0') {
        return -EINVAL;
    }

    if ((g_batch_ctx.pending_count + g_batch_ctx.active_queries) >= g_batch_ctx.max_pending) {
        g_batch_ctx.enqueue_failures++;
        g_batch_ctx.dropped_queries++;
        return -EAGAIN;
    }

    item = (async_batch_item_t *)calloc(1, sizeof(*item));
    if (item == NULL) {
        g_batch_ctx.enqueue_failures++;
        return -ENOMEM;
    }

    item->query = strdup(query);
    if (item->query == NULL) {
        free(item);
        g_batch_ctx.enqueue_failures++;
        return -ENOMEM;
    }

    item->next = NULL;
    if (g_batch_ctx.tail != NULL) {
        g_batch_ctx.tail->next = item;
    } else {
        g_batch_ctx.head = item;
    }
    g_batch_ctx.tail = item;
    g_batch_ctx.pending_count++;
    return 0;
}

static async_batch_item_t *queue_pop(void) {
    async_batch_item_t *item = g_batch_ctx.head;
    if (item == NULL) {
        return NULL;
    }

    g_batch_ctx.head = item->next;
    if (g_batch_ctx.head == NULL) {
        g_batch_ctx.tail = NULL;
    }
    item->next = NULL;
    g_batch_ctx.pending_count--;
    return item;
}

static void dispatch_next(void) {
    async_batch_item_t *item;
    int r;

    if (!g_batch_ctx.initialized || g_batch_ctx.closing || g_batch_ctx.active_queries > 0) {
        return;
    }

    item = queue_pop();
    if (item == NULL) {
        return;
    }

    g_batch_ctx.active_queries++;
    r = spine_async_mysql_query(g_batch_ctx.loop, g_batch_ctx.mysql, item->query, batch_query_cb, item);
    if (r != 0) {
        SPINE_LOG(("ERROR: Async DB submit failed with status %d", r));
        g_batch_ctx.active_queries--;
        free(item->query);
        free(item);
        g_batch_ctx.enqueue_failures++;
        return;
    }

    g_batch_ctx.submitted_queries++;
}

static void on_flush_timer(uv_timer_t *handle) {
    (void)handle;
    dispatch_next();
}

int spine_async_batch_init(uv_loop_t *runtime_loop, MYSQL *mysql, int max_batch_size, int flush_interval_ms) {
    if (g_batch_ctx.initialized) return 0;
    if (!runtime_loop || !mysql) return -1;

    g_batch_ctx.loop = runtime_loop;
    g_batch_ctx.mysql = mysql;
    g_batch_ctx.max_pending = max_batch_size > 0 ? max_batch_size : 256;
    g_batch_ctx.flush_interval_ms = flush_interval_ms;
    g_batch_ctx.head = NULL;
    g_batch_ctx.tail = NULL;
    g_batch_ctx.pending_count = 0;
    g_batch_ctx.active_queries = 0;
    g_batch_ctx.dropped_queries = 0;
    g_batch_ctx.enqueue_failures = 0;
    g_batch_ctx.submitted_queries = 0;
    g_batch_ctx.closing = false;

    uv_timer_init(g_batch_ctx.loop, &g_batch_ctx.flush_timer);
    uv_timer_start(&g_batch_ctx.flush_timer, on_flush_timer, flush_interval_ms, flush_interval_ms);

    g_batch_ctx.initialized = true;
    return 0;
}

int spine_async_batch_enqueue(const char *query) {
    int rc;
    if (!g_batch_ctx.initialized || g_batch_ctx.closing) return -EINVAL;

    rc = queue_push(query);
    if (rc == 0) {
        dispatch_next();
    }
    return rc;
}

void spine_async_batch_flush(void) {
    if (!g_batch_ctx.initialized) return;
    dispatch_next();
}

static void on_batch_close(uv_handle_t *handle) {
    (void)handle;
    g_batch_ctx.loop = NULL;
    g_batch_ctx.initialized = false;
    g_batch_ctx.closing = false;
}

void spine_async_batch_cleanup(void) {
    async_batch_item_t *item;
    if (!g_batch_ctx.initialized) return;

    g_batch_ctx.closing = true;
    uv_timer_stop(&g_batch_ctx.flush_timer);
    uv_close((uv_handle_t *)&g_batch_ctx.flush_timer, on_batch_close);

    while ((item = queue_pop()) != NULL) {
        free(item->query);
        free(item);
    }
}

int spine_async_batch_get_stats(spine_async_batch_stats_t *out_stats) {
    if (out_stats == NULL) {
        return -EINVAL;
    }

    out_stats->pending_count = g_batch_ctx.pending_count;
    out_stats->active_queries = g_batch_ctx.active_queries;
    out_stats->max_pending = g_batch_ctx.max_pending;
    out_stats->dropped_queries = g_batch_ctx.dropped_queries;
    out_stats->enqueue_failures = g_batch_ctx.enqueue_failures;
    out_stats->submitted_queries = g_batch_ctx.submitted_queries;
    return 0;
}
