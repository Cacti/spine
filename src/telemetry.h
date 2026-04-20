#ifndef SPINE_TELEMETRY_H
#define SPINE_TELEMETRY_H

#include <uv.h>

/**
 * Initialize the asynchronous telemetry server.
 * Listens on a Unix Domain Socket or TCP port for metrics requests.
 */
int spine_telemetry_init(uv_loop_t *runtime_loop, const char *path);

/**
 * Update internal metrics.
 */
void spine_telemetry_record_latency(int stage, double ms);
void spine_telemetry_add_completed(void);
void spine_telemetry_cleanup(void);

#endif
