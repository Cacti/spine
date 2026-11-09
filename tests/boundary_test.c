/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2024 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 +-------------------------------------------------------------------------+
 | spine: boundary tests for buffer handling helpers                       |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

/*
 * Links the spine objects except spine.c, so the globals spine.c owns are
 * defined here. Run through "make check"; build with
 * CFLAGS="-fsanitize=address,undefined" to catch out of bounds access that
 * plain assertions cannot observe.
 */

#include "common.h"
#include "spine.h"

#if defined(__APPLE__)
/* <malloc/malloc.h> pulls in a Mach host_t that clashes with spine's */
extern size_t malloc_size(const void *ptr);
#  define ALLOCATED_SIZE(p) malloc_size(p)
#elif defined(__GLIBC__)
#  include <malloc.h>
#  define ALLOCATED_SIZE(p) malloc_usable_size(p)
#endif

int entries = 0;
int num_hosts = 0;
sem_t available_threads;
sem_t available_scripts;
double start_time;
double total_time;

config_t set;
php_t   *php_processes = 0;
char    config_paths[CONFIG_PATHS][BUFSIZE];
int     *debug_devices;

pool_t  *db_pool_local;
pool_t  *db_pool_remote;

poller_thread_t** details = NULL;

static int failures = 0;

#define CHECK(cond, name) do { \
	if (cond) { \
		printf("ok - %s\n", name); \
	} else { \
		printf("not ok - %s (%s:%d)\n", name, __FILE__, __LINE__); \
		failures++; \
	} \
} while (0)

static void test_add_slashes(void) {
	char   input[BUFSIZE];
	char   *output;
	size_t i;
	int    all_doubled = TRUE;

	/* the largest input a BUFSIZE caller can pass, every byte doubled */
	memset(input, '\\', sizeof(input) - 1);
	input[sizeof(input) - 1] = '\0';

	output = add_slashes(input);

#ifdef ALLOCATED_SIZE
	CHECK(ALLOCATED_SIZE(output) >= 2 * strlen(input) + 1, "add_slashes allocation holds a fully doubled input");
#endif
	CHECK(strlen(output) == 2 * strlen(input), "add_slashes doubles every backslash");

	for (i = 0; i < 2 * strlen(input); i++) {
		if (output[i] != '\\') {
			all_doubled = FALSE;
			break;
		}
	}
	CHECK(all_doubled, "add_slashes output contains only backslashes");
	free(output);

	output = add_slashes("a\\b");
	CHECK(strcmp(output, "a\\\\b") == 0, "add_slashes preserves other characters");
	free(output);

	output = add_slashes("");
	CHECK(output[0] == '\0', "add_slashes returns an empty owned string");
	free(output);
}

int main(void) {
	test_add_slashes();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
