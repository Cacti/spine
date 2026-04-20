#ifndef SPINE_POLL_STATE_INTERNAL_H
#define SPINE_POLL_STATE_INTERNAL_H

#include "poll_state.h"
#include "spine.h"
#include "async_dns.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

struct poll_context_struct {
    poll_state_t state;
    spine_spine_host_t *host;
    int device_counter;
    int spine_host_thread;
	    int spine_host_threads;
	    int host_data_ids;
    char spine_host_time[SMALL_BUFSIZE];
    double spine_host_time_double;
	    int host_errors;
	    uv_loop_t *event_loop;
	    spine_async_dns_runtime_t *dns_runtime;
    
    /* Net-SNMP and libuv bridge state */
    uv_poll_t snmp_poll;
    uv_timer_t snmp_timer;
    void *sessp;          /* Opaque net-snmp thread-safe session */
    int active_fd;        /* Cached file descriptor for diffing */
    int handles_closed;   /* Tracker for uv_close synchronization */
    int fd;               /* Current active FD */

    /* Internal iteration state */
    int current_item_idx;
    target_t *poller_items;
    int num_items;
    int mux_tasks_pending;
    struct poll_context_struct *next_in_queue;
};

#endif
