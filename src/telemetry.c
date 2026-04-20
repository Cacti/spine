#include "common.h"
#include "spine.h"
#include "telemetry.h"
#include "task_governor.h"
#include "task_scheduler.h"

// Note: Ensure your telemetry endpoint format exports these values.
void spine_telemetry_get_metrics(void) {
    uint32_t global_inflight = spine_governor_get_global_inflight();
    uint32_t queued_count = spine_scheduler_get_queued_count();
    uint32_t active_hosts = spine_scheduler_get_active_hosts();
    /* Telemetry formatting logic omitted here, assume it writes to buffer */
    (void)global_inflight;
    (void)queued_count;
    (void)active_hosts;
}

typedef struct {
    uint64_t total_polls;
    double avg_latency_ms;
    int queue_depth;
} spine_metrics_t;

static spine_metrics_t g_metrics = {0};
static uv_pipe_t g_server_pipe;
static uv_loop_t *g_loop = NULL;
static bool g_server_initialized = false;

typedef struct {
    uv_write_t req;
    char *payload;
    uv_pipe_t *client;
} telemetry_write_req_t;

static void on_telemetry_close(uv_handle_t* handle) {
    (void)handle;
}

static void on_write(uv_write_t* req, int status) {
    telemetry_write_req_t *wreq = (telemetry_write_req_t *)req;
    (void)status;
    if (wreq == NULL) {
        return;
    }

    if (wreq->client != NULL && !uv_is_closing((uv_handle_t *)wreq->client)) {
        uv_close((uv_handle_t *)wreq->client, (uv_close_cb)free);
    }

    free(wreq->payload);
    free(wreq);
}

static void on_new_connection(uv_stream_t* server, int status) {
    if (status < 0) return;

    uv_pipe_t* client = malloc(sizeof(uv_pipe_t));
    if (!client) return;

    if (g_loop == NULL) {
        free(client);
        return;
    }

    if (uv_pipe_init(g_loop, client, 0) != 0) {
        free(client);
        return;
    }

    if (uv_accept(server, (uv_stream_t*)client) == 0) {
        char buffer[512];
        snprintf(buffer, sizeof(buffer), 
            "{\"status\":\"ok\",\"polls\":%llu,\"latency_avg\":%.2f,\"queue\":%d}\n",
            g_metrics.total_polls, g_metrics.avg_latency_ms, g_metrics.queue_depth);
        
        char *payload = strdup(buffer);
        if (!payload) {
            uv_close((uv_handle_t*)client, (uv_close_cb)free);
            return;
        }

        uv_buf_t res = uv_buf_init(payload, strlen(payload));
        telemetry_write_req_t *wreq = calloc(1, sizeof(*wreq));
        if (!wreq) {
            free(payload);
            uv_close((uv_handle_t*)client, (uv_close_cb)free);
            return;
        }
        wreq->payload = payload;
        wreq->client = client;
        if (uv_write(&wreq->req, (uv_stream_t*)client, &res, 1, on_write) != 0) {
            uv_close((uv_handle_t*)client, (uv_close_cb)free);
            free(wreq->payload);
            free(wreq);
            return;
        }
    } else {
        uv_close((uv_handle_t*)client, (uv_close_cb)free);
    }
}

int spine_telemetry_init(uv_loop_t *runtime_loop, const char *path) {
    if (runtime_loop == NULL || path == NULL || *path == '\0') {
        return UV_EINVAL;
    }

    g_loop = runtime_loop;
    if (uv_pipe_init(g_loop, &g_server_pipe, 0) != 0) {
        g_loop = NULL;
        return -1;
    }

    unlink(path);
    int r = uv_pipe_bind(&g_server_pipe, path);
    if (r) {
        uv_close((uv_handle_t *)&g_server_pipe, on_telemetry_close);
        g_loop = NULL;
        return r;
    }

    r = uv_listen((uv_stream_t*)&g_server_pipe, 128, on_new_connection);
    if (r == 0) {
        g_server_initialized = true;
        return 0;
    }

    uv_close((uv_handle_t *)&g_server_pipe, on_telemetry_close);
    g_loop = NULL;
    return r;
}

void spine_telemetry_record_latency(int stage, double ms) {
    (void)stage;
    g_metrics.avg_latency_ms = (g_metrics.avg_latency_ms + ms) / 2.0;
}

void spine_telemetry_add_completed(void) {
    g_metrics.total_polls++;
}

void spine_telemetry_cleanup(void) {
    if (!g_server_initialized) {
        return;
    }

    g_server_initialized = false;
    if (!uv_is_closing((uv_handle_t *)&g_server_pipe)) {
        uv_close((uv_handle_t*)&g_server_pipe, on_telemetry_close);
    }
    g_loop = NULL;
}
