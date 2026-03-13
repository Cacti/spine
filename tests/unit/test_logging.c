#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>

/* Mock Spine environment */
#define UNIT_TESTING
#include "../../common.h"
#include "../../spine.h"

/* Define globals that Spine expects */
config_t set;

/* Mock spine_log to capture output */
char last_log[BUFSIZE];
int spine_log(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vsnprintf(last_log, sizeof(last_log), format, args);
    va_end(args);
    return 0;
}

int is_debug_device(int device_id) {
    return mock_type(int);
}

/* Test cases */
static void test_spine_log_variadic(void **state) {
    memset(last_log, 0, sizeof(last_log));
    SPINE_LOG("Test message with %s and %d", "string", 42);
    assert_string_equal(last_log, "Test message with string and 42");
}

static void test_spine_log_debug_gating(void **state) {
    set.log_level = POLLER_VERBOSITY_LOW;
    memset(last_log, 0, sizeof(last_log));
    SPINE_LOG_DEBUG("Should not log");
    assert_string_equal(last_log, "");

    set.log_level = POLLER_VERBOSITY_DEBUG;
    SPINE_LOG_DEBUG("Should log %d", 123);
    assert_string_equal(last_log, "Should log 123");
}

static void test_spine_log_dev_debug(void **state) {
    /* Case 1: Device debug is ON */
    will_return(is_debug_device, TRUE);
    memset(last_log, 0, sizeof(last_log));
    SPINE_LOG_DEV(1, DEBUG, "Device debug message %s", "active");
    assert_string_equal(last_log, "Device debug message active");

    /* Case 2: Device debug is OFF, but global level is LOW */
    set.log_level = POLLER_VERBOSITY_LOW;
    will_return(is_debug_device, FALSE);
    memset(last_log, 0, sizeof(last_log));
    SPINE_LOG_DEV(1, DEBUG, "Should be gated");
    assert_string_equal(last_log, "");

    /* Case 3: Device debug is OFF, but global level is DEBUG */
    set.log_level = POLLER_VERBOSITY_DEBUG;
    will_return(is_debug_device, FALSE);
    memset(last_log, 0, sizeof(last_log));
    SPINE_LOG_DEV(1, DEBUG, "Log via global level");
    assert_string_equal(last_log, "Log via global level");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_spine_log_variadic),
        cmocka_unit_test(test_spine_log_debug_gating),
        cmocka_unit_test(test_spine_log_dev_debug),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
