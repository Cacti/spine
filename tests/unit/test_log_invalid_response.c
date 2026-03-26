/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Unit tests for log_invalid_response                                    |
 +-------------------------------------------------------------------------+
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "common.h"
#include "spine.h"

/* capture last log message for verification */
static char last_log[4096];
static int log_called;

int spine_log(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vsnprintf(last_log, sizeof(last_log), format, args);
	va_end(args);
	log_called = 1;
	return 0;
}

void die(const char *format, ...) {
	(void)format;
	exit(1);
}

int *debug_devices = NULL;
config_t set;

/* inline log_invalid_response */
void log_invalid_response(int host_id, int host_thread, int local_data_id, const char *format, ...) {
	char    message[LOGSIZE];
	va_list args;

	va_start(args, format);
	vsnprintf(message, sizeof(message), format, args);
	va_end(args);

	spine_log("WARNING: Invalid Response, Device[%i] HT[%i] DS[%i] %s",
		host_id, host_thread, local_data_id, message);
}

static int setup(void **state) {
	(void)state;
	last_log[0] = '\0';
	log_called = 0;
	return 0;
}

static void test_basic_log(void **state) {
	(void)state;
	log_invalid_response(1, 2, 3, "SNMP: %s, output: %s", "test_oid", "bad_value");
	assert_true(log_called);
	assert_non_null(strstr(last_log, "Device[1]"));
	assert_non_null(strstr(last_log, "HT[2]"));
	assert_non_null(strstr(last_log, "DS[3]"));
	assert_non_null(strstr(last_log, "test_oid"));
}

static void test_empty_format(void **state) {
	(void)state;
	log_invalid_response(0, 0, 0, "");
	assert_true(log_called);
	assert_non_null(strstr(last_log, "Device[0]"));
}

static void test_long_message(void **state) {
	char long_str[8192];
	(void)state;
	memset(long_str, 'A', sizeof(long_str) - 1);
	long_str[sizeof(long_str) - 1] = '\0';
	log_invalid_response(1, 1, 1, "output: %s", long_str);
	assert_true(log_called);
}

static void test_numeric_args(void **state) {
	(void)state;
	log_invalid_response(999, 5, 12345, "SCRIPT: %s, code: %d", "/usr/bin/test", 42);
	assert_true(log_called);
	assert_non_null(strstr(last_log, "Device[999]"));
	assert_non_null(strstr(last_log, "DS[12345]"));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup(test_basic_log, setup),
		cmocka_unit_test_setup(test_empty_format, setup),
		cmocka_unit_test_setup(test_long_message, setup),
		cmocka_unit_test_setup(test_numeric_args, setup),
	};
	return cmocka_run_group_tests_name("log_invalid_response", tests, NULL, NULL);
}
