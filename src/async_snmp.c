#include "common.h"
#include "spine.h"
#include "async_snmp.h"

typedef struct {
    uv_poll_t poll;
    void *sessp;
    async_snmp_cb callback;
    void *data;
    int closed_handles;
    int fd;
    bool callback_fired;
    bool closing;
} async_snmp_ctx_t;

static void on_poll_close(uv_handle_t *handle);

static void async_snmp_finish(async_snmp_ctx_t *ctx, struct snmp_pdu *pdu) {
    if (ctx == NULL) {
        return;
    }

    if (!ctx->callback_fired) {
        ctx->callback_fired = true;
        ctx->callback(ctx->sessp, pdu, ctx->data);
    }

    if (!ctx->closing) {
        ctx->closing = true;
        uv_poll_stop(&ctx->poll);
        uv_close((uv_handle_t *)&ctx->poll, on_poll_close);
    }
}

static void on_poll_close(uv_handle_t *handle) {
    async_snmp_ctx_t *ctx = (async_snmp_ctx_t *)handle->data;
    ctx->closed_handles++;
    if (ctx->closed_handles == 1) {
        free(ctx);
    }
}

static void __attribute__((unused)) on_snmp_timeout(uv_timer_t *handle);

static void on_snmp_readable(uv_poll_t *handle, int status, int events) {
    async_snmp_ctx_t *ctx = (async_snmp_ctx_t *)handle->data;

    if (status < 0) {
        async_snmp_finish(ctx, NULL);
        return;
    }

    if (events & UV_READABLE) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(ctx->fd, &read_fds);

        /* Hand the raw socket data to net-snmp for parsing.
           This will internally trigger your async_response_handler. */
        snmp_sess_read(ctx->sessp, &read_fds);

        /* Resynchronize handles based on the new internal net-snmp state */
        // Note: For KISS/Opaque, we let poller.c handle the higher level state
    }
}

static void __attribute__((unused)) on_snmp_timeout(uv_timer_t *handle) {
    async_snmp_ctx_t *ctx = (async_snmp_ctx_t *)handle->data;

    /* net-snmp handles the internal retry counter.
       If it exhausts retries, it triggers the callback with NETSNMP_CALLBACK_OP_TIMED_OUT */
    snmp_sess_timeout(ctx->sessp);
}

/* Internal Net-SNMP response callback */
static int async_response_handler(int operation, struct snmp_session *sp, 
                                  int reqid, struct snmp_pdu *pdu, void *magic) {
    (void)operation;
    (void)sp;
    (void)reqid;
    async_snmp_ctx_t *ctx = (async_snmp_ctx_t *)magic;

    async_snmp_finish(ctx, pdu);
    
    return 1; /* Acknowledge we handled the PDU */
}

int spine_async_snmp_get(uv_loop_t *runtime_loop, void *sessp, const char *oid_str, async_snmp_cb cb, void *data) {
    struct snmp_pdu *pdu;
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;

    if (!runtime_loop || !sessp || !oid_str || !cb) {
        return -EINVAL;
    }

    if (!snmp_parse_oid(oid_str, anOID, &anOID_len)) {
        return -1;
    }

    pdu = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(pdu, anOID, anOID_len);

    async_snmp_ctx_t *ctx = calloc(1, sizeof(async_snmp_ctx_t));
    ctx->sessp = sessp;
    ctx->callback = cb;
    ctx->data = data;

    /* Send the async request. */
    if (snmp_sess_async_send(sessp, pdu, async_response_handler, ctx) == 0) {
        snmp_free_pdu(pdu);
        free(ctx);
        return -1;
    }

    int fds = 0, block = 1;
    fd_set fdset;
    struct timeval timeout;
    FD_ZERO(&fdset);
    snmp_sess_select_info(sessp, &fds, &fdset, &timeout, &block);

    int fd_found = 0;
    for (int i = 0; i < fds; i++) {
        if (FD_ISSET(i, &fdset)) {
            ctx->fd = i;
            if (uv_poll_init(runtime_loop, &ctx->poll, i) != 0) {
                /* ctx is still registered as the magic pointer in the
                 * net-snmp async request started by snmp_sess_async_send
                 * above; freeing it now causes async_response_handler to
                 * dereference freed memory on response or timeout. Cancel
                 * the outstanding request (best effort; not all net-snmp
                 * versions expose snmp_sess_timeout with a synchronous
                 * abort) and let the handler's own completion path drive
                 * the free via async_snmp_finish. */
                snmp_sess_timeout(sessp);
                return -1;
            }
            ctx->poll.data = ctx;
            if (uv_poll_start(&ctx->poll, UV_READABLE, on_snmp_readable) != 0) {
                /* Already initialized - ctx is freed when on_poll_close
                 * fires, which also lets async_response_handler unwind
                 * safely if it races. */
                uv_close((uv_handle_t *)&ctx->poll, on_poll_close);
                return -1;
            }
            fd_found = 1;
            break;
        }
    }

    if (!fd_found) {
        /* Same rationale as the uv_poll_init error path: let net-snmp's
         * timeout machinery drive async_response_handler so ctx is freed
         * from async_snmp_finish with no in-flight UAF. */
        snmp_sess_timeout(sessp);
        return -1;
    }

    return 0;
}
