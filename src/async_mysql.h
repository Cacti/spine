#ifndef SPINE_ASYNC_MYSQL_H
#define SPINE_ASYNC_MYSQL_H

#include <uv.h>
#include <mysql.h>

typedef void (*async_mysql_cb)(MYSQL *mysql, int status, void *data);

int spine_async_mysql_query(uv_loop_t *runtime_loop, MYSQL *mysql, const char *query, async_mysql_cb cb, void *data);

#endif
