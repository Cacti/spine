#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#include "../../src/poll_state_internal.h"
#include "../../src/async_exec.h"
#include "../../src/async_snmp.h"
#include "../../src/async_mysql.h"
#include "../../src/async_dns.h"
#include "test_platform_helpers.h"

// Define loop
#ifndef HAVE_LIBUV
#define HAVE_LIBUV 1
#endif
uv_loop_t *loop = NULL;
static spine_async_dns_runtime_t *dns_runtime = NULL;
static uv_loop_t test_loop;

static void dns_cb(struct addrinfo *res, int status, void *data) {
    (void)res;
    (void)status;
    int *called = (int *)data;
    *called = 1;
}

static void test_async_dns_success(void) {
    int called = 0;
    // Localhost should always resolve
    int r = spine_async_dns_lookup_runtime(dns_runtime, "localhost", dns_cb, &called);
    ASSERT_INT_EQ(r, 0);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_INT_EQ(called, 1);
}

static void exec_cb(const char *result, int exit_status, int term_signal, void *data) {
    (void)result;
    (void)exit_status;
    (void)term_signal;
    int *called = (int *)data;
    *called = 1;
}

static void test_async_exec_success(void) {
    int called = 0;
    int r = spine_async_exec(loop, "echo test", 1000, exec_cb, &called);
    ASSERT_INT_EQ(r, 0);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_INT_EQ(called, 1);
}

static void test_async_exec_timeout(void) {
    int called = 0;
    int r = spine_async_exec(loop, "sleep 2", 10, exec_cb, &called);
    ASSERT_INT_EQ(r, 0);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_INT_EQ(called, 1);
}

static void test_async_exec_spawn_fail(void) {
    int called = 0;
    // Test a command that will return a non-zero exit status
    int r = spine_async_exec(loop, "false", 1000, exec_cb, &called);
    ASSERT_INT_EQ(r, 0);
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_INT_EQ(called, 1);
}

static void test_async_snmp_parse_fail(void) {
    // Test argument validation path
    int r = spine_async_snmp_get(loop, NULL, "invalid.oid", NULL, NULL);
    ASSERT_TRUE(r != 0);
}

#ifndef HAVE_MYSQL_ASYNC
static void mysql_cb(MYSQL *mysql, int status, void *data) {
    (void)mysql;
    (void)status;
    int *called = (int *)data;
    *called = 1;
}

static void test_async_mysql_query(void) {
    int called = 0;
    int r = spine_async_mysql_query(loop, NULL, "SELECT 1", mysql_cb, &called);
    ASSERT_INT_EQ(r, -EINVAL);
}
#endif

// Stubs for poller functions
void extract_and_format_pdu(struct snmp_pdu *pdu, poll_context_t *ctx) {
    (void)pdu; (void)ctx;
}

void spine_transition_state(poll_context_t *ctx) {
    (void)ctx;
}

int main(void) {
    ASSERT_INT_EQ(uv_loop_init(&test_loop), 0);
    loop = &test_loop;
    ASSERT_INT_EQ(spine_async_dns_runtime_create(loop, &dns_runtime), 0);
    test_async_dns_success();
    test_async_exec_success();
    test_async_exec_timeout();
    test_async_exec_spawn_fail();
    test_async_snmp_parse_fail();
#ifndef HAVE_MYSQL_ASYNC
    test_async_mysql_query();
#endif
    spine_async_dns_runtime_destroy(dns_runtime);
    dns_runtime = NULL;
    uv_run(loop, UV_RUN_DEFAULT);
    ASSERT_INT_EQ(uv_loop_close(loop), 0);
    loop = NULL;
    return finish_tests("async coverage tests");
}
