#ifndef SPINE_ASYNC_MYSQL_H
#define SPINE_ASYNC_MYSQL_H

#include <uv.h>
#include <mysql.h>

typedef void (*async_mysql_cb)(MYSQL *mysql, int status, void *data);

int spine_async_mysql_query(uv_loop_t *runtime_loop, MYSQL *mysql, const char *query, async_mysql_cb cb, void *data);

/* Set the async-mysql shutdown fence. After this call, new queries
 * submitted through spine_async_mysql_query return -ESHUTDOWN; in-
 * flight queries continue through their existing uv_poll chain so
 * the uv_run drain can flush them before the MYSQL handle is closed. */
void spine_async_mysql_shutdown_begin(void);

#endif
