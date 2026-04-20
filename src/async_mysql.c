#include "common.h"
#include "spine.h"
#include "async_mysql.h"
#include <errno.h>

#ifdef HAVE_MYSQL_ASYNC

typedef struct {
    MYSQL *mysql;
    async_mysql_cb callback;
    void *data;
    int ret;
    uv_poll_t poll;
    int fd;
} async_mysql_ctx_t;

typedef struct async_mysql_active {
    MYSQL *mysql;
    struct async_mysql_active *next;
} async_mysql_active_t;

static async_mysql_active_t *g_active_mysql = NULL;

/* Shutdown fence. Once set, new async queries are refused so the MYSQL
 * handles can be safely torn down without a late callback dereferencing
 * freed state. In-flight queries continue through their existing
 * uv_poll callback chain; the uv_run drain flushes them.
 *
 * Declared _Atomic with release/acquire ordering so worker threads on
 * weakly-ordered architectures (ARM, POWER) see the flag promptly; a
 * plain volatile int is not a sufficient memory barrier across thread
 * boundaries. */
#include <stdatomic.h>
static atomic_int g_async_mysql_shutting_down = 0;

void spine_async_mysql_shutdown_begin(void) {
    atomic_store_explicit(&g_async_mysql_shutting_down, 1,
                          memory_order_release);
}

static int async_mysql_mark_active(MYSQL *mysql) {
    async_mysql_active_t *node;
    async_mysql_active_t *cursor = g_active_mysql;

    while (cursor != NULL) {
        if (cursor->mysql == mysql) {
            return -EALREADY;
        }
        cursor = cursor->next;
    }

    node = (async_mysql_active_t *)calloc(1, sizeof(*node));
    if (node == NULL) {
        return -ENOMEM;
    }
    node->mysql = mysql;
    node->next = g_active_mysql;
    g_active_mysql = node;
    return 0;
}

static void async_mysql_unmark_active(MYSQL *mysql) {
    async_mysql_active_t **cursor = &g_active_mysql;
    while (*cursor != NULL) {
        async_mysql_active_t *node = *cursor;
        if (node->mysql == mysql) {
            *cursor = node->next;
            free(node);
            return;
        }
        cursor = &node->next;
    }
}

static void on_mysql_close(uv_handle_t* handle) {
    async_mysql_ctx_t *ctx = (async_mysql_ctx_t *)handle->data;
    if (ctx != NULL) {
        async_mysql_unmark_active(ctx->mysql);
    }
    free(handle->data);
}

static void mysql_poll_cb(uv_poll_t* handle, int status, int events) {
    async_mysql_ctx_t *ctx = (async_mysql_ctx_t *)handle->data;
    if (ctx == NULL) {
        return;
    }

    if (status < 0) {
        uv_poll_stop(handle);
        ctx->callback(ctx->mysql, -EIO, ctx->data);
        uv_close((uv_handle_t*)handle, on_mysql_close);
        return;
    }

    int mysql_status = 0;
    if (events & UV_READABLE) mysql_status |= MYSQL_WAIT_READ;
    if (events & UV_WRITABLE) mysql_status |= MYSQL_WAIT_WRITE;

    int next_mask = mysql_real_query_cont(&ctx->ret, ctx->mysql, mysql_status);

    if (next_mask == 0) {
        uv_poll_stop(handle);
        ctx->callback(ctx->mysql, ctx->ret, ctx->data);
        uv_close((uv_handle_t*)handle, on_mysql_close);
    } else {
        int new_uv_events = 0;
        if (next_mask & MYSQL_WAIT_READ) new_uv_events |= UV_READABLE;
        if (next_mask & MYSQL_WAIT_WRITE) new_uv_events |= UV_WRITABLE;
        uv_poll_start(handle, new_uv_events, mysql_poll_cb);
    }
}

int spine_async_mysql_query(uv_loop_t *runtime_loop, MYSQL *mysql, const char *query, async_mysql_cb cb, void *data) {
    int mark_rc;

    if (!runtime_loop || !mysql || !query || !cb) {
        return -EINVAL;
    }
    if (atomic_load_explicit(&g_async_mysql_shutting_down,
                             memory_order_acquire)) {
        return -ESHUTDOWN;
    }

    async_mysql_ctx_t *ctx = calloc(1, sizeof(async_mysql_ctx_t));
    if (ctx == NULL) {
        return -ENOMEM;
    }

    mark_rc = async_mysql_mark_active(mysql);
    if (mark_rc != 0) {
        free(ctx);
        return mark_rc;
    }

    ctx->mysql = mysql;
    ctx->callback = cb;
    ctx->data = data;
    ctx->fd = mysql_get_socket(mysql);
    if (ctx->fd < 0) {
        async_mysql_unmark_active(mysql);
        free(ctx);
        return -EINVAL;
    }

    int status = mysql_real_query_start(&ctx->ret, mysql, query, strlen(query));

    if (status == 0) {
        cb(mysql, ctx->ret, data);
        async_mysql_unmark_active(mysql);
        free(ctx);
    } else {
        int rc = uv_poll_init(runtime_loop, &ctx->poll, ctx->fd);
        if (rc != 0) {
            async_mysql_unmark_active(mysql);
            free(ctx);
            return rc;
        }
        ctx->poll.data = ctx;
        int new_uv_events = 0;
        if (status & MYSQL_WAIT_READ) new_uv_events |= UV_READABLE;
        if (status & MYSQL_WAIT_WRITE) new_uv_events |= UV_WRITABLE;
        rc = uv_poll_start(&ctx->poll, new_uv_events, mysql_poll_cb);
        if (rc != 0) {
            uv_close((uv_handle_t *)&ctx->poll, on_mysql_close);
            return rc;
        }
    }

    return 0;
}

#else

int spine_async_mysql_query(uv_loop_t *runtime_loop, MYSQL *mysql, const char *query, async_mysql_cb cb, void *data) {
    (void)runtime_loop;
    if (!mysql || !query || !cb) return -EINVAL;
    /* Avoid silently blocking the event loop when async C API support
     * is unavailable in the linked client library. */
    return -ENOTSUP;
}

/* Shutdown fence is a no-op when the async path is compiled out; the
 * symbol exists so spine.c can call it unconditionally. */
void spine_async_mysql_shutdown_begin(void) {
}

#endif
