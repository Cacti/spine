/* Deterministic coverage for init_sockaddr() resolver retry/error handling. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "spine.h"
#include "ping.h"

static int resolver_result;
static int transient_failures;
static int resolver_calls;
static int free_calls;
static int sleep_calls;
static struct sockaddr_in resolved_address;
static struct addrinfo resolved_info;

int __wrap_getaddrinfo(const char *node, const char *service,
	const struct addrinfo *hints, struct addrinfo **result) {
	(void) node;
	(void) service;
	(void) hints;
	resolver_calls++;
	if (resolver_calls <= transient_failures) return EAI_AGAIN;
	if (resolver_result != 0) return resolver_result;
	*result = &resolved_info;
	return 0;
}

void __wrap_freeaddrinfo(struct addrinfo *result) {
	assert_ptr_equal(result, &resolved_info);
	free_calls++;
}

int __wrap_usleep(useconds_t usec) {
	assert_int_equal(usec, 50000);
	sleep_calls++;
	return 0;
}

static int reset(void **state) {
	(void) state;
	memset(&set, 0, sizeof(set));
	memset(&resolved_address, 0, sizeof(resolved_address));
	memset(&resolved_info, 0, sizeof(resolved_info));
	resolved_address.sin_family = AF_INET;
	resolved_address.sin_addr.s_addr = htonl(0xc0000201U);
	resolved_info.ai_family = AF_INET;
	resolved_info.ai_addr = (struct sockaddr *)&resolved_address;
	resolved_info.ai_addrlen = sizeof(resolved_address);
	resolver_result = 0;
	transient_failures = 0;
	resolver_calls = 0;
	free_calls = 0;
	sleep_calls = 0;
	set.log_destination = LOGDEST_STDOUT;
	return 0;
}

static void test_transient_resolution_retries_then_succeeds(void **state) {
	struct sockaddr_in result;
	(void) state;
	transient_failures = 3;
	assert_int_equal(init_sockaddr(&result, "example.test", 8080), TRUE);
	assert_int_equal(resolver_calls, 4);
	assert_int_equal(sleep_calls, 3);
	assert_int_equal(free_calls, 1);
	assert_int_equal(result.sin_family, AF_INET);
	assert_int_equal(result.sin_addr.s_addr, resolved_address.sin_addr.s_addr);
	assert_int_equal(result.sin_port, htons(8080));
}

static void assert_resolver_failure(int result_code, int failures,
	int expected_calls, int expected_sleeps) {
	struct sockaddr_in result;
	resolver_result = result_code;
	transient_failures = failures;
	assert_int_equal(init_sockaddr(&result, "example.test", 80), FALSE);
	assert_int_equal(resolver_calls, expected_calls);
	assert_int_equal(sleep_calls, expected_sleeps);
	assert_int_equal(free_calls, 0);
}

static void test_transient_resolution_stops_after_retry_budget(void **state) {
	(void) state;
	transient_failures = 4;
	assert_resolver_failure(0, 4, 4, 3);
}

static void test_permanent_resolution_failure_returns_false(void **state) {
	(void) state;
	assert_resolver_failure(EAI_FAIL, 0, 1, 0);
}

static void test_out_of_memory_resolution_returns_false(void **state) {
	(void) state;
	assert_resolver_failure(EAI_MEMORY, 0, 1, 0);
}

static void test_unknown_resolution_error_returns_false(void **state) {
	(void) state;
	assert_resolver_failure(EAI_NONAME, 0, 1, 0);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_transient_resolution_retries_then_succeeds, reset),
		cmocka_unit_test_setup(test_transient_resolution_stops_after_retry_budget, reset),
		cmocka_unit_test_setup(test_permanent_resolution_failure_returns_false, reset),
		cmocka_unit_test_setup(test_out_of_memory_resolution_returns_false, reset),
		cmocka_unit_test_setup(test_unknown_resolution_error_returns_false, reset),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
