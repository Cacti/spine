#ifndef SPINE_POLL_STATE_H
#define SPINE_POLL_STATE_H

#include "common.h"
#include "spine.h"

typedef enum {
    POLL_STATE_INIT,
    POLL_STATE_DNS,
    POLL_STATE_PING,
    POLL_STATE_REINDEX,
    POLL_STATE_SNMP_SEND,
    POLL_STATE_SNMP_WAIT,
    POLL_STATE_SCRIPTS,
    POLL_STATE_FLUSH,
    POLL_STATE_DONE,
    POLL_STATE_ERROR
} poll_state_t;

typedef struct poll_context_struct poll_context_t;

/**
 * Interface for an asynchronous polling stage.
 * Returns 0 if the stage started successfully and will call spine_transition_state later.
 * Returns non-zero to trigger an immediate transition to POLL_STATE_ERROR.
 */
typedef int (*spine_async_stage_f)(poll_context_t *ctx);

void spine_async_poll_start(poller_thread_t *det);
void spine_transition_state(poll_context_t *ctx);

#endif
