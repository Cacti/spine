#include "task_governor.h"
#include "uthash.h"
#include <stdlib.h>

static uint32_t g_max_global_inflight = 5000;
static uint32_t g_global_inflight = 0;

typedef struct {
    uint32_t host_id;
    uint32_t inflight;
    uint32_t max_concurrency;
    uint32_t consecutive_timeouts;
    UT_hash_handle hh;
} host_throttle_t;

static host_throttle_t *host_stats = NULL;

void spine_governor_init(uint32_t max_global) {
    g_max_global_inflight = max_global;
    g_global_inflight = 0;
    /* host_stats is initialized to NULL (empty hash) automatically */
}

void spine_governor_destroy(void) {
    host_throttle_t *current, *tmp;
    HASH_ITER(hh, host_stats, current, tmp) {
        HASH_DEL(host_stats, current);
        free(current);
    }
    host_stats = NULL;
    g_global_inflight = 0;
}

static host_throttle_t* get_or_create_host(uint32_t host_id) {
    host_throttle_t *ht;
    HASH_FIND_INT(host_stats, &host_id, ht);
    if (!ht) {
        ht = calloc(1, sizeof(host_throttle_t));
        ht->host_id = host_id;
        ht->max_concurrency = 10; /* Conservative default */
        HASH_ADD_INT(host_stats, host_id, ht);
    }
    return ht;
}

bool spine_governor_global_allow(void) {
    return g_global_inflight < g_max_global_inflight;
}

bool spine_governor_host_allow(uint32_t host_id) {
    host_throttle_t *ht = get_or_create_host(host_id);
    return ht->inflight < ht->max_concurrency;
}

bool spine_governor_subnet_allow(uint32_t subnet_id) {
    (void)subnet_id;
    return true; /* Subnet limits not enforced in this phase */
}

void spine_governor_consume(spine_task_t *task) {
    g_global_inflight++;
    host_throttle_t *ht = get_or_create_host(task->host_id);
    ht->inflight++;
}

void spine_governor_release(spine_task_t *task, bool success) {
    if (g_global_inflight > 0) {
        g_global_inflight--;
    }
    
    host_throttle_t *ht = get_or_create_host(task->host_id);
    if (ht->inflight > 0) {
        ht->inflight--;
    }
    
    /* Adaptive Throttling logic (TCP Reno style AIMD) */
    if (success) {
        ht->consecutive_timeouts = 0;
        if (ht->max_concurrency < 50) {
            ht->max_concurrency++; /* Additive Increase */
        }
    } else {
        ht->consecutive_timeouts++;
        if (ht->consecutive_timeouts >= 2) {
            ht->max_concurrency /= 2; /* Multiplicative Decrease */
            if (ht->max_concurrency < 1) {
                ht->max_concurrency = 1;
            }
            ht->consecutive_timeouts = 0; /* CRITICAL FIX: Reset to prevent immediate recursive halving */
        }
    }
}

uint32_t spine_governor_get_global_inflight(void) {
    return g_global_inflight;
}
