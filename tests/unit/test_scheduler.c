#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include "task_types.h"
#include "task_governor.h"
#include "task_scheduler.h"
#include "task_executor.h"

static int completed_tasks = 0;
static int failed_tasks = 0;

static void test_on_complete(spine_task_t *task, int status, void *result) {
    (void)task;
    (void)result;
    if (status == 0) {
        completed_tasks++;
    } else {
        failed_tasks++;
    }
}

void test_sparse_id(void) {
    printf("Running Sparse ID Test...\n");
    spine_scheduler_init();
    spine_governor_init(5000);
    completed_tasks = 0;

    spine_task_t t1 = {0};
    t1.task_id = 1;
    t1.host_id = 1;
    t1.on_complete = test_on_complete;

    spine_task_t t2 = {0};
    t2.task_id = 2;
    t2.host_id = 999999999; /* Out of bounds for old flat array */
    t2.on_complete = test_on_complete;

    spine_scheduler_enqueue(&t1);
    spine_scheduler_enqueue(&t2);

    uv_loop_t *loop = uv_default_loop();
    spine_scheduler_tick(loop);

    assert(t1.state == STATE_INFLIGHT);
    assert(t2.state == STATE_INFLIGHT);

    spine_executor_complete_task(&t1, 0, NULL);
    spine_executor_complete_task(&t2, 0, NULL);

    uv_run(loop, UV_RUN_DEFAULT);
    
    spine_scheduler_destroy();
    spine_governor_destroy();
    
    assert(completed_tasks == 2);
    printf("Sparse ID Test Passed.\n");
}

void test_blackhole(void) {
    printf("Running Blackhole Test...\n");
    spine_scheduler_init();
    spine_governor_init(5000);
    completed_tasks = 0;
    failed_tasks = 0;

    spine_task_t bad_tasks[100];
    spine_task_t good_tasks[10];

    for (int i=0; i<100; i++) {
        memset(&bad_tasks[i], 0, sizeof(spine_task_t));
        bad_tasks[i].task_id = 100+i;
        bad_tasks[i].host_id = 10; /* Bad host */
        bad_tasks[i].max_retries = 0;
        bad_tasks[i].on_complete = test_on_complete;
        spine_scheduler_enqueue(&bad_tasks[i]);
    }

    for (int i=0; i<10; i++) {
        memset(&good_tasks[i], 0, sizeof(spine_task_t));
        good_tasks[i].task_id = 200+i;
        good_tasks[i].host_id = 20; /* Good host */
        good_tasks[i].max_retries = 0;
        good_tasks[i].on_complete = test_on_complete;
        spine_scheduler_enqueue(&good_tasks[i]);
    }

    uv_loop_t *loop = uv_default_loop();
    spine_scheduler_tick(loop);

    /* Bad host gets throttled to 10 (default), good host dispatches all 10 */
    int bad_inflight = 0;
    int good_inflight = 0;

    for (int i=0; i<100; i++) if(bad_tasks[i].state == STATE_INFLIGHT) bad_inflight++;
    for (int i=0; i<10; i++) if(good_tasks[i].state == STATE_INFLIGHT) good_inflight++;

    assert(bad_inflight == 10);
    assert(good_inflight == 10);

    /* Fail the bad ones */
    for (int i=0; i<100; i++) {
        if(bad_tasks[i].state == STATE_INFLIGHT) {
            spine_executor_complete_task(&bad_tasks[i], -1, NULL);
        }
    }
    /* Complete the good ones */
    for (int i=0; i<10; i++) {
        if(good_tasks[i].state == STATE_INFLIGHT) {
            spine_executor_complete_task(&good_tasks[i], 0, NULL);
        }
    }

    uv_run(loop, UV_RUN_DEFAULT);
    
    spine_scheduler_destroy();
    spine_governor_destroy();
    
    printf("Failed Tasks: %d, Completed Tasks: %d\n", failed_tasks, completed_tasks);
    assert(failed_tasks == 100);
    assert(completed_tasks == 10);
    printf("Blackhole Test Passed.\n");
}

void test_empty_host_removal_and_purge(void) {
    printf("Running Empty Host Removal and Purge Test...\n");
    spine_scheduler_init();
    spine_governor_init(5000);
    completed_tasks = 0;
    failed_tasks = 0;

    spine_task_t t1 = {0};
    t1.task_id = 1;
    t1.host_id = 1;
    t1.on_complete = test_on_complete;

    spine_task_t t2 = {0};
    t2.task_id = 2;
    t2.host_id = 1;
    t2.on_complete = test_on_complete;

    spine_scheduler_enqueue(&t1);
    spine_scheduler_enqueue(&t2);
    
    assert(spine_scheduler_get_active_hosts() == 1);
    assert(spine_scheduler_get_queued_count() == 2);

    uv_loop_t *loop = uv_default_loop();
    spine_scheduler_tick(loop);
    
    /* 2 tasks dispatched, host queue became empty and was removed in the same tick */
    assert(t1.state == STATE_INFLIGHT);
    assert(t2.state == STATE_INFLIGHT);
    assert(spine_scheduler_get_queued_count() == 0);
    assert(spine_scheduler_get_active_hosts() == 0);
    
    /* Complete inflight */
    spine_executor_complete_task(&t1, 0, NULL);
    spine_executor_complete_task(&t2, 0, NULL);
    uv_run(loop, UV_RUN_DEFAULT);
    assert(completed_tasks == 2);

    /* Test Purge */
    completed_tasks = 0;
    failed_tasks = 0;
    spine_task_t t3 = {0};
    t3.task_id = 3;
    t3.host_id = 2;
    t3.on_complete = test_on_complete;
    
    spine_scheduler_enqueue(&t3);
    assert(spine_scheduler_get_active_hosts() == 1);
    assert(spine_scheduler_get_queued_count() == 1);
    
    /* Simulate immediate shutdown */
    spine_scheduler_destroy();
    
    /* Should have purged t3 and fired callback with failure */
    assert(failed_tasks == 1);
    assert(spine_scheduler_get_active_hosts() == 0);
    
    spine_governor_destroy();
    printf("Empty Host Removal and Purge Test Passed.\n");
}

int main() {
    test_sparse_id();
    test_blackhole();
    test_empty_host_removal_and_purge();
    return 0;
}
