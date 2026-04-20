#include "task_scheduler.h"
#include "task_governor.h"
#include "task_executor.h"
#include "uthash.h"
#include <stdlib.h>

/* Per-Host Queue */
typedef struct {
    uint32_t host_id;
    spine_task_t *head;
    spine_task_t *tail;
    UT_hash_handle hh;
} host_queue_t;

static host_queue_t *active_hosts = NULL;
static host_queue_t *current_host_ptr = NULL;

void spine_scheduler_init(void) {
    active_hosts = NULL;
    current_host_ptr = NULL;
}

void spine_scheduler_purge(int error_code) {
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
}

void spine_scheduler_destroy(void) {
    /* -125 is UV_ECANCELED, safe generic error for teardown */
    spine_scheduler_purge(-125); 
}

void spine_scheduler_enqueue(spine_task_t *task) {
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
}

void spine_scheduler_tick(uv_loop_t *loop) {
    if (!active_hosts) return;
    
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
    current_host_ptr = hq;
}

uint32_t spine_scheduler_get_active_hosts(void) {
    return HASH_COUNT(active_hosts);
}

uint32_t spine_scheduler_get_queued_count(void) {
    uint32_t count = 0;
    host_queue_t *current, *tmp;
    HASH_ITER(hh, active_hosts, current, tmp) {
        spine_task_t *task = current->head;
        while (task) {
            count++;
            task = task->next;
        }
    }
    return count;
}
