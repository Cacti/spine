#ifndef SPINE_ASYNC_PHP_H
#define SPINE_ASYNC_PHP_H

#include <uv.h>
#include "spine.h"

typedef void (*async_php_cb)(const char *result, void *data);

/**
 * Initialize the persistent PHP Script Server pool with Unix Domain Sockets.
 */
int spine_async_php_init(uv_loop_t *loop);

/**
 * Execute a command on the PHP Script Server pool asynchronously.
 * Automatically picks a ready worker or queues the request.
 */
int spine_async_php_cmd(const char *command, async_php_cb cb, void *data);

/**
 * Shutdown the PHP pool and close all sockets.
 */
void spine_async_php_cleanup(void);

#endif
