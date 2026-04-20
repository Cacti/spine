#include "common.h"
#include "spine.h"
#include "async_exec.h"

/*
 * Async process exec via libuv. Callback fires exactly once; handles
 * are torn down deterministically through a three-handle close count
 * with a terminal flag to prevent double-callback/double-free races.
 *
 * Commands are spawned argv-only (no shell).
 */

typedef struct {
    uv_process_t process;
    uv_pipe_t    stdout_pipe;
    uv_timer_t   timer;
    char        *result_buffer;
    size_t       buffer_pos;
    async_exec_cb callback;
    void        *data;
    int          exit_status;
    int          term_signal;
    bool         timed_out;
    bool         callback_fired;
    bool         process_started;
    int          pending_closes;
    char       **argv;
} async_exec_ctx_t;

static void async_exec_free_argv(char **argv) {
    size_t i;

    if (argv == NULL) {
        return;
    }

    for (i = 0; argv[i] != NULL; i++) {
        free(argv[i]);
    }

    free(argv);
}

static void async_exec_fire_callback(async_exec_ctx_t *ctx) {
    if (ctx->callback_fired || !ctx->callback) return;
    ctx->callback_fired = true;

    if (ctx->timed_out) {
        ctx->callback(NULL, -1, SIGKILL, ctx->data);
    } else {
        ctx->callback(ctx->result_buffer, ctx->exit_status, ctx->term_signal, ctx->data);
    }
}

static void on_close(uv_handle_t *handle) {
    async_exec_ctx_t *ctx = (async_exec_ctx_t *)handle->data;
    if (!ctx) return;

    if (--ctx->pending_closes == 0) {
        async_exec_fire_callback(ctx);
        async_exec_free_argv(ctx->argv);
        free(ctx->result_buffer);
        free(ctx);
    }
}

static void async_exec_close_all(async_exec_ctx_t *ctx) {
    /* Close each still-live handle exactly once. If uv_is_closing is
     * true, the handle has an on_close already queued by a prior path
     * (typical: on_timeout already asked for close). That on_close
     * will still fire and decrement pending_closes. Double-closing OR
     * decrementing here in the else branch both overcounts and drives
     * pending_closes negative, producing a use-after-free when a later
     * on_close runs past zero.
     *
     * The counter is authoritative: it is set once in spine_async_exec
     * to the exact number of handles we initialized, and on_close is
     * the only site that decrements it. */
    if (ctx->process_started && !uv_is_closing((uv_handle_t *)&ctx->process)) {
        uv_close((uv_handle_t *)&ctx->process, on_close);
    }
    if (!uv_is_closing((uv_handle_t *)&ctx->stdout_pipe)) {
        uv_close((uv_handle_t *)&ctx->stdout_pipe, on_close);
    }
    if (!uv_is_closing((uv_handle_t *)&ctx->timer)) {
        uv_close((uv_handle_t *)&ctx->timer, on_close);
    }
}

static void on_stdout_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    async_exec_ctx_t *ctx = (async_exec_ctx_t *)stream->data;

    if (nread > 0 && ctx) {
        size_t available = RESULTS_BUFFER - ctx->buffer_pos - 1;
        size_t to_copy   = (size_t)nread < available ? (size_t)nread : available;
        if (to_copy > 0) {
            memcpy(ctx->result_buffer + ctx->buffer_pos, buf->base, to_copy);
            ctx->buffer_pos += to_copy;
            ctx->result_buffer[ctx->buffer_pos] = '\0';
        }
    }

    if (buf->base) {
        free(buf->base);
    }
}

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len  = buf->base ? suggested_size : 0;
}

static void on_process_exit(uv_process_t *process, int64_t exit_status, int term_signal) {
    async_exec_ctx_t *ctx = (async_exec_ctx_t *)process->data;
    if (!ctx) return;

    /* Record outcome but do NOT fire the callback yet; it fires once
     * from the last on_close so every handle is torn down first. */
    if (!ctx->timed_out) {
        ctx->exit_status = (int)exit_status;
        ctx->term_signal = term_signal;
    }

    uv_timer_stop(&ctx->timer);
    uv_read_stop((uv_stream_t *)&ctx->stdout_pipe);

    async_exec_close_all(ctx);
}

static void on_timeout(uv_timer_t *handle) {
    async_exec_ctx_t *ctx = (async_exec_ctx_t *)handle->data;
    if (!ctx || ctx->timed_out) return;

    ctx->timed_out = true;
    /* Ask the process to exit. on_process_exit will then tear handles
     * down via async_exec_close_all; the callback fires once from the
     * last on_close with the timed_out flag producing the -1 result. */
    if (ctx->process_started) {
        uv_process_kill(&ctx->process, SIGKILL);
    } else {
        async_exec_close_all(ctx);
    }
}

int spine_async_exec(uv_loop_t *runtime_loop, const char *command, uint64_t timeout_ms, async_exec_cb cb, void *data) {
    if (!runtime_loop || !command || !cb) return -EINVAL;

    async_exec_ctx_t *ctx = calloc(1, sizeof(async_exec_ctx_t));
    if (!ctx) return -ENOMEM;

    ctx->result_buffer = malloc(RESULTS_BUFFER);
    if (!ctx->result_buffer) {
        free(ctx);
        return -ENOMEM;
    }
    ctx->result_buffer[0] = '\0';
    ctx->callback        = cb;
    ctx->data            = data;
    ctx->pending_closes  = 3;

    /* Always spawn via /bin/sh -c. The sync poller path (nft_popen.c)
     * runs every command through sh -c; poller items in the Cacti DB
     * may legitimately contain |, >, redirects, $VAR expansion, and
     * other shell constructs. A naive argv tokenizer would break
     * those, and a metachar-detecting hybrid creates a behaviour
     * split (same command runs differently depending on quoting that
     * the admin does not control). Keep the shell boundary identical
     * to the sync path. */
    ctx->argv = (char **)calloc(4, sizeof(char *));
    if (ctx->argv == NULL) {
        free(ctx->result_buffer);
        free(ctx);
        return -ENOMEM;
    }
    ctx->argv[0] = strdup("/bin/sh");
    ctx->argv[1] = strdup("-c");
    ctx->argv[2] = strdup(command);
    ctx->argv[3] = NULL;
    if (!ctx->argv[0] || !ctx->argv[1] || !ctx->argv[2]) {
        async_exec_free_argv(ctx->argv);
        free(ctx->result_buffer);
        free(ctx);
        return -ENOMEM;
    }

    uv_pipe_init(runtime_loop, &ctx->stdout_pipe, 0);
    ctx->stdout_pipe.data = ctx;

    uv_timer_init(runtime_loop, &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, on_timeout, timeout_ms, 0);

    uv_stdio_container_t stdio[3];
    stdio[0].flags       = UV_IGNORE;
    stdio[1].flags       = UV_CREATE_PIPE | UV_WRITABLE_PIPE;
    stdio[1].data.stream = (uv_stream_t *)&ctx->stdout_pipe;
    stdio[2].flags       = UV_IGNORE;

    uv_process_options_t options = {0};
    options.exit_cb     = on_process_exit;
    options.file        = ctx->argv[0];
    options.args        = ctx->argv;
    options.stdio_count = 3;
    options.stdio       = stdio;

    ctx->process.data = ctx;
    int r = uv_spawn(runtime_loop, &ctx->process, &options);
    if (r) {
        /* Spawn failed: process handle was not installed. Release pipe
         * and timer, then the ctx. No callback — caller sees r. */
        ctx->process_started = false;
        uv_timer_stop(&ctx->timer);
        ctx->pending_closes = 2;
        uv_close((uv_handle_t *)&ctx->stdout_pipe, on_close);
        uv_close((uv_handle_t *)&ctx->timer, on_close);
        /* Suppress callback since the caller already gets r. */
        ctx->callback_fired = true;
        return r;
    }
    ctx->process_started = true;

    uv_read_start((uv_stream_t *)&ctx->stdout_pipe, on_alloc, on_stdout_read);
    return 0;
}
