#include "common.h"
#include "spine.h"
#include "async_php.h"
#include "platform/platform_process.h"
#include <sys/socket.h>

extern char **environ;

typedef struct {
    char *command;
    async_php_cb callback;
    void *data;
} async_php_request_t;

typedef struct {
    uv_loop_t *loop;
    php_t *workers;
    int num_workers;
    bool initialized;
} async_php_pool_t;

static async_php_pool_t g_php_pool = {0};

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle;
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    php_t *worker = (php_t *)stream->data;
    async_php_request_t *req = (async_php_request_t *)worker->pending_request;

    if (nread > 0 && req) {
        /* Script server output usually ends with a newline. 
         * For this prototype, we assume we get the full line. */
        char *result = strndup(buf->base, nread);
        
        /* Clear pending request state */
        worker->pending_request = NULL;
        worker->php_state = PHP_READY;
        
        req->callback(result, req->data);
        
        free(result);
        free(req->command);
        free(req);
        
        uv_read_stop(stream);
    }

    if (buf->base) free(buf->base);
}

static void on_write(uv_write_t *req, int status) {
    (void)status;
    free(req);
}

static int spawn_worker(int idx, uv_loop_t *loop) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -errno;
    }

    char poller_id[TINY_BUFSIZE];
    snprintf(poller_id, TINY_BUFSIZE, "--poller=%d", set.poller_id);
    
    char *argv[] = {
        set.path_php,
        "-q",
        set.path_php_server,
        "--environ=spine",
        poller_id,
        NULL
    };

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    
    /* Redirect socket end to child stdin/stdout */
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&fa, fds[0]);
    posix_spawn_file_actions_addclose(&fa, fds[1]);

    spine_pid_t pid;
    char **child_env = spine_build_child_env();
    int r = posix_spawn(&pid, argv[0], &fa, NULL, argv, child_env ? child_env : environ);
    
    posix_spawn_file_actions_destroy(&fa);
    if (child_env) free(child_env);
    close(fds[1]);

    if (r != 0) {
        close(fds[0]);
        return r;
    }

    php_t *worker = &g_php_pool.workers[idx];
    worker->php_pid = pid;
    worker->php_read_fd = fds[0];
    worker->php_write_fd = fds[0];
    worker->php_state = PHP_READY;
    
    uv_pipe_init(loop, &worker->php_pipe, 0);
    worker->php_pipe.data = worker;
    uv_pipe_open(&worker->php_pipe, fds[0]);

    return 0;
}

int spine_async_php_init(uv_loop_t *loop) {
    if (g_php_pool.initialized) return 0;

    g_php_pool.loop = loop;
    g_php_pool.num_workers = set.php_servers;
    g_php_pool.workers = calloc(g_php_pool.num_workers, sizeof(php_t));

    for (int i = 0; i < g_php_pool.num_workers; i++) {
        int r = spawn_worker(i, loop);
        if (r != 0) {
            SPINE_LOG(("ERROR: Failed to spawn async PHP worker %d", i));
            return r;
        }
    }

    g_php_pool.initialized = true;
    return 0;
}

int spine_async_php_cmd(const char *command, async_php_cb cb, void *data) {
    if (!g_php_pool.initialized) return -EINVAL;

    /* Round-robin pick for simplicity in this prototype */
    static int last_idx = 0;
    int idx = last_idx % g_php_pool.num_workers;
    last_idx++;

    php_t *worker = &g_php_pool.workers[idx];
    
    /* In a real implementation, we should queue if all workers are busy.
     * For this prototype, we assume we can fire. */
    
    async_php_request_t *req = malloc(sizeof(async_php_request_t));
    req->command = strdup(command);
    req->callback = cb;
    req->data = data;
    
    worker->pending_request = req;
    worker->php_state = PHP_BUSY;

    /* Send command + CRLF */
    char full_cmd[BUFSIZE];
    snprintf(full_cmd, BUFSIZE, "%s\r\n", command);
    
    uv_buf_t buf = uv_buf_init(strdup(full_cmd), strlen(full_cmd));
    uv_write_t *w_req = malloc(sizeof(uv_write_t));
    uv_write(w_req, (uv_stream_t *)&worker->php_pipe, &buf, 1, on_write);
    
    /* Start reading for result */
    uv_read_start((uv_stream_t *)&worker->php_pipe, on_alloc, on_read);

    return 0;
}

static void on_worker_close(uv_handle_t *handle) {
    (void)handle;
}

void spine_async_php_cleanup(void) {
    if (!g_php_pool.initialized) return;

    for (int i = 0; i < g_php_pool.num_workers; i++) {
        php_t *worker = &g_php_pool.workers[i];
        if (worker->php_pid > 0) {
            spine_process_terminate(worker->php_pid);
            uv_close((uv_handle_t *)&worker->php_pipe, on_worker_close);
        }
    }
    
    free(g_php_pool.workers);
    g_php_pool.initialized = false;
}
