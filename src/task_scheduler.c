#include "task_scheduler.h"
#include "task_governor.h"
#include "task_executor.h"
#include "uthash.h"
#include <stdlib.h>
#include <uv.h>

#define MAX_GLOBAL_INFLIGHT 5000

/* Slab Allocator */
static spine_task_t task_pool[MAX_GLOBAL_INFLIGHT];
static spine_task_t *free_list = NULL;

/* Per-Host Queue */
typedef struct {
    uint32_t host_id;
    spine_task_t *head;
    spine_task_t *tail;
    UT_hash_handle hh;
} host_queue_t;

static host_queue_t *active_hosts = NULL;
static host_queue_t *current_host_ptr = NULL;
static spine_task_t *inflight_head = NULL;
static uv_mutex_t scheduler_lock;
static bool scheduler_initialized = false;
static uint32_t total_retries = 0;

void spine_scheduler_init(void) {
    if (scheduler_initialized) return;
    uv_mutex_init(&scheduler_lock);
    
    uv_mutex_lock(&scheduler_lock);
    active_hosts = NULL;
    current_host_ptr = NULL;
    inflight_head = NULL;
    total_retries = 0;
    
    /* Initialize Free List */
    for (int i = 0; i < MAX_GLOBAL_INFLIGHT - 1; i++) {
        task_pool[i].next = &task_pool[i + 1];
    }
    task_pool[MAX_GLOBAL_INFLIGHT - 1].next = NULL;
    free_list = &task_pool[0];
    uv_mutex_unlock(&scheduler_lock);
    
    scheduler_initialized = true;
}

spine_task_t* spine_task_alloc(void) {
    if (!scheduler_initialized) return NULL;
    uv_mutex_lock(&scheduler_lock);
    spine_task_t *task = free_list;
    if (task) {
        free_list = task->next;
        memset(task, 0, sizeof(spine_task_t));
    }
    uv_mutex_unlock(&scheduler_lock);
    return task;
}

void spine_task_free(spine_task_t *task) {
    if (!scheduler_initialized || !task) return;
    uv_mutex_lock(&scheduler_lock);
    task->next = free_list;
    free_list = task;
    uv_mutex_unlock(&scheduler_lock);
}

void spine_scheduler_purge(int error_code) {
    if (!scheduler_initialized) return;
    
    uv_mutex_lock(&scheduler_lock);
    
    /* 1. Purge Queued Tasks */
    host_queue_t *current, *tmp;
    HASH_ITER(hh, active_hosts, current, tmp) {
        spine_task_t *task = current->head;
        while (task) {
            spine_task_t *next = task->next;
            task->state = STATE_FAILED;
            if (task->on_complete) {
                task->on_complete(task, error_code, NULL);
            }
            task = next;
        }
        HASH_DEL(active_hosts, current);
        free(current);
    }
    active_hosts = NULL;
    current_host_ptr = NULL;
    
    /* 2. Purge Inflight Tasks */
    /* We cannot free them instantly, we must call complete_task so uv_close triggers */
    spine_task_t *itask = inflight_head;
    /* We must copy the pointers because complete_task alters the list */
    spine_task_t **inflight_array = calloc(MAX_GLOBAL_INFLIGHT, sizeof(spine_task_t*));
    int inflight_count = 0;
    while (itask && inflight_count < MAX_GLOBAL_INFLIGHT) {
        inflight_array[inflight_count++] = itask;
        itask = itask->next_inflight;
    }
    uv_mutex_unlock(&scheduler_lock);
    
    for (int i = 0; i < inflight_count; i++) {
        spine_executor_complete_task(inflight_array[i], error_code, NULL);
    }
    free(inflight_array);
}

void spine_scheduler_destroy(void) {
    if (!scheduler_initialized) return;
    /* -125 is UV_ECANCELED, safe generic error for teardown */
    spine_scheduler_purge(-125); 
    uv_mutex_destroy(&scheduler_lock);
    scheduler_initialized = false;
}

void spine_scheduler_enqueue(spine_task_t *task) {
    if (!scheduler_initialized) return;
    uv_mutex_lock(&scheduler_lock);
    
    host_queue_t *hq;
    HASH_FIND_INT(active_hosts, &task->host_id, hq);
    if (!hq) {
        hq = calloc(1, sizeof(host_queue_t));
        hq->host_id = task->host_id;
        HASH_ADD_INT(active_hosts, host_id, hq);
    }
    
    task->next = NULL;
    task->state = STATE_QUEUED;
    if (hq->tail) {
        hq->tail->next = task;
    } else {
        hq->head = task;
    }
    hq->tail = task;
    
    uv_mutex_unlock(&scheduler_lock);
}

static void spine_scheduler_inflight_add(spine_task_t *task) {
    /* Assumes scheduler_lock is held */
    task->next_inflight = inflight_head;
    task->prev_inflight = NULL;
    if (inflight_head) inflight_head->prev_inflight = task;
    inflight_head = task;
}

void spine_scheduler_inflight_remove(spine_task_t *task) {
    if (!scheduler_initialized) return;
    uv_mutex_lock(&scheduler_lock);
    if (task->prev_inflight) task->prev_inflight->next_inflight = task->next_inflight;
    else if (inflight_head == task) inflight_head = task->next_inflight;
    
    if (task->next_inflight) task->next_inflight->prev_inflight = task->prev_inflight;
    
    task->prev_inflight = task->next_inflight = NULL;
    uv_mutex_unlock(&scheduler_lock);
}

void spine_scheduler_tick(uv_loop_t *loop) {
    if (!scheduler_initialized) return;
    
    uv_mutex_lock(&scheduler_lock);
    if (!active_hosts) {
        uv_mutex_unlock(&scheduler_lock);
        return;
    }
    
    host_queue_t *start_host = current_host_ptr ? current_host_ptr : active_hosts;
    host_queue_t *hq = start_host;
    
    while (spine_governor_global_allow()) {
        bool dispatched = false;

        /* CRITICAL FIX: Delete empty hosts to prevent O(N) CPU livelock */
        if (!hq->head) {
            host_queue_t *empty_hq = hq;
            hq = hq->hh.next ? hq->hh.next : active_hosts;
            
            if (empty_hq == start_host) {
                start_host = hq;
            }
            
            HASH_DEL(active_hosts, empty_hq);
            free(empty_hq);
            
            if (!active_hosts) {
                current_host_ptr = NULL;
                break;
            }
            continue; /* Loop again with the newly advanced hq */
        }

        /* If this host has tasks AND is allowed to dispatch */
        if (spine_governor_host_allow(hq->host_id)) {
            spine_task_t *task = hq->head;
            hq->head = task->next;
            if (!hq->head) hq->tail = NULL;
            
            spine_governor_consume(task);
            spine_scheduler_inflight_add(task);
            
            /* Dispatch I/O while holding the lock. This is safe and O(1) */
            spine_executor_dispatch(loop, task);
            
            dispatched = true;
        }
        
        /* Move to next host (Round Robin) */
        hq = hq->hh.next ? hq->hh.next : active_hosts;
        
        /* If we completed a full lap of all hosts and dispatched nothing, break to avoid CPU spin */
        if (hq == start_host) {
            if (!dispatched) {
                break;
            }
        }
    }
    current_host_ptr = active_hosts ? hq : NULL;
    uv_mutex_unlock(&scheduler_lock);
}

uint32_t spine_scheduler_get_active_hosts(void) {
    if (!scheduler_initialized) return 0;
    uv_mutex_lock(&scheduler_lock);
    uint32_t count = HASH_COUNT(active_hosts);
    uv_mutex_unlock(&scheduler_lock);
    return count;
}

uint32_t spine_scheduler_get_queued_count(void) {
    if (!scheduler_initialized) return 0;
    uint32_t count = 0;
    uv_mutex_lock(&scheduler_lock);
    host_queue_t *current, *tmp;
    HASH_ITER(hh, active_hosts, current, tmp) {
        spine_task_t *task = current->head;
        while (task) {
            count++;
            task = task->next;
        }
    }
    uv_mutex_unlock(&scheduler_lock);
    return count;
}

uint32_t spine_scheduler_get_retries_count(void) {
    if (!scheduler_initialized) return 0;
    uv_mutex_lock(&scheduler_lock);
    uint32_t count = total_retries;
    uv_mutex_unlock(&scheduler_lock);
    return count;
}

void spine_scheduler_inc_retries(void) {
    if (!scheduler_initialized) return;
    uv_mutex_lock(&scheduler_lock);
    total_retries++;
    uv_mutex_unlock(&scheduler_lock);
}
