#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define UNIT_TESTING
#include "../../src/internal/common.h"
#include "../../src/app/spine.h"

/* Define globals that Spine expects */
config_t set;
double start_time;
char config_paths[CONFIG_PATHS][BUFSIZE];
int *debug_devices = NULL;

/* Mock functions needed by util.c */
int db_connect(int type, MYSQL *mysql) { return TRUE; }
void db_disconnect(MYSQL *mysql) {}
MYSQL_RES *db_query(MYSQL *mysql, int type, const char *query) { return NULL; }
void db_free_result(MYSQL_RES *result) {}
int db_insert(MYSQL *mysql, int type, const char *query) { return 0; }
void db_escape(MYSQL *mysql, char *output, int max_size, const char *input) {}
int append_hostrange(char *obuf, size_t capacity, const char *colname) { return 0; }
int parse_logdest(const char *res, int default_dest) { return 0; }
const char *printable_logdest(int dest) { return ""; }
void php_close(int php_process) {}
int ping_icmp_open_shared(void) { return 0; }
int ping_icmp_shared_available(void) { return 0; }

/* Include the actual source file */
#include "../../src/app/buffer.c"
#include "../../src/platform/clock.c"
#include "../../src/platform/socket.c"
#include "../../src/platform/thread.c"
#include "../../src/config/text.c"
#include "../../src/log/debug.c"
#include "../../src/script/escape.c"
#include "../../src/platform/descriptor.c"
#include "../../src/log/sanitize.c"
#include "../../src/config/settings.c"
#include "../../src/config/options.c"
#include "../../src/config/file.c"
#include "../../src/database/transfer.c"
#include "../../src/log/log.c"
#include "../../src/poller/result.c"
#include "../../src/config/validate.c"
#include "../../src/platform/privileges.c"
#include "../../src/poller/regex.c"


static void test_strpos_found(void **state) {
    const char *haystack = "The quick brown fox";
    assert_int_equal(strpos(haystack, "quick"), 4);
    assert_int_equal(strpos(haystack, "The"), 0);
    assert_int_equal(strpos(haystack, "fox"), 16);
}

static void test_strpos_not_found(void **state) {
    const char *haystack = "The quick brown fox";
    assert_int_equal(strpos(haystack, "lazy"), -1);
    assert_int_equal(strpos(haystack, "THE"), -1); /* Case sensitive */
}

static void test_strpos_empty(void **state) {
    assert_int_equal(strpos("", "something"), -1);
    assert_int_equal(strpos("something", ""), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_strpos_found),
        cmocka_unit_test(test_strpos_not_found),
        cmocka_unit_test(test_strpos_empty),
    };
    
    return cmocka_run_group_tests(tests, NULL, NULL);
}
