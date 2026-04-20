#include "task_governor.h"
#include "uthash.h"
#include <stdlib.h>
#include <uv.h>

static uint32_t g_max_global_inflight = 5000;
static uint32_t g_global_inflight = 0;
static uv_mutex_t governor_lock;
static bool governor_initialized = false;

typedef struct {
    uint32_t host_id;
    uint32_t inflight;
    uint32_t max_concurrency;
    uint32_t consecutive_timeouts;
    uint64_t last_halved_time_ms; /* Track AIMD window */
    UT_hash_handle hh;
} host_throttle_t;

static host_throttle_t *host_stats = NULL;

void spine_governor_init(uint32_t max_global) {
    if (!governor_initialized) {
        uv_mutex_init(&governor_lock);
        governor_initialized = true;
    }
    uv_mutex_lock(&governor_lock);
    g_max_global_inflight = max_global;
    g_global_inflight = 0;
    uv_mutex_unlock(&governor_lock);
}

void spine_governor_destroy(void) {
    if (!governor_initialized) return;
    
    uv_mutex_lock(&governor_lock);
    host_throttle_t *current, *tmp;
    HASH_ITER(hh, host_stats, current, tmp) {
        HASH_DEL(host_stats, current);
        free(current);
    }
    host_stats = NULL;
    g_global_inflight = 0;
    uv_mutex_unlock(&governor_lock);
    
    uv_mutex_destroy(&governor_lock);
    governor_initialized = false;
}

static host_throttle_t* get_or_create_host(uint32_t host_id) {
    host_throttle_t *ht;
    HASH_FIND_INT(host_stats, &host_id, ht);
    if (!ht) {
        ht = calloc(1, sizeof(host_throttle_t));
        ht->host_id = host_id;
        ht->max_concurrency = 10; /* Conservative default */
        ht->last_halved_time_ms = 0;
        HASH_ADD_INT(host_stats, host_id, ht);
    }
    return ht;
}

bool spine_governor_global_allow(void) {
    if (!governor_initialized) return false;
    uv_mutex_lock(&governor_lock);
    bool allow = g_global_inflight < g_max_global_inflight;
    uv_mutex_unlock(&governor_lock);
    return allow;
}

bool spine_governor_host_allow(uint32_t host_id) {
    if (!governor_initialized) return false;
    uv_mutex_lock(&governor_lock);
    host_throttle_t *ht = get_or_create_host(host_id);
    bool allow = ht->inflight < ht->max_concurrency;
    uv_mutex_unlock(&governor_lock);
    return allow;
}

bool spine_governor_subnet_allow(uint32_t subnet_id) {
    (void)subnet_id;
    return true; /* Subnet limits not enforced in this phase */
}

void spine_governor_consume(spine_task_t *task) {
    if (!governor_initialized) return;
    uv_mutex_lock(&governor_lock);
    g_global_inflight++;
    host_throttle_t *ht = get_or_create_host(task->host_id);
    ht->inflight++;
    uv_mutex_unlock(&governor_lock);
}

void spine_governor_release(spine_task_t *task, bool success) {
    if (!governor_initialized) return;
    uv_mutex_lock(&governor_lock);
    
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
        uint64_t now = uv_hrtime() / 1000000;
        
        if (ht->consecutive_timeouts >= 2) {
            /* Only halve if 1000ms has passed since the last halving (1 RTT window) */
            if (now - ht->last_halved_time_ms > 1000) {
                ht->max_concurrency /= 2;
                if (ht->max_concurrency < 1) {
                    ht->max_concurrency = 1;
                }
                ht->last_halved_time_ms = now;
            }
            ht->consecutive_timeouts = 0; /* Reset to prevent immediate recursive halving */
        }
    }
    uv_mutex_unlock(&governor_lock);
}

uint32_t spine_governor_get_global_inflight(void) {
    if (!governor_initialized) return 0;
    uv_mutex_lock(&governor_lock);
    uint32_t count = g_global_inflight;
    uv_mutex_unlock(&governor_lock);
    return count;
}

uint32_t spine_governor_get_throttled_hosts(void) {
    if (!governor_initialized) return 0;
    uint32_t count = 0;
    uv_mutex_lock(&governor_lock);
    host_throttle_t *current, *tmp;
    HASH_ITER(hh, host_stats, current, tmp) {
        if (current->inflight >= current->max_concurrency) {
            count++;
        }
    }
    uv_mutex_unlock(&governor_lock);
    return count;
}
