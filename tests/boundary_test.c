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
#include <fcntl.h>
#include <sys/resource.h>

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

static void test_snmp_format_value(void) {
	netsnmp_variable_list vars;
	oid    name[] = { 1, 3, 6, 1, 2, 1, 1, 1, 0 };
	char   *output;
	u_char *value;
	size_t value_len = RESULTS_BUFFER * 2;

	/* an exactly sized heap buffer full of garbage, like an uninitialized stack buffer */
	output = malloc(RESULTS_BUFFER);
	value  = malloc(value_len);
	memset(value, 'x', value_len);

	memset(&vars, 0, sizeof(vars));
	snmp_set_var_objid(&vars, name, sizeof(name) / sizeof(oid));
	snmp_set_var_typed_value(&vars, ASN_OCTET_STR, value, value_len);

	memset(output, 'G', RESULTS_BUFFER);
	CHECK(!snmp_format_value(output, RESULTS_BUFFER, &vars), "snmp_format_value reports a value that does not fit");
	CHECK(memchr(output, '\0', RESULTS_BUFFER) != NULL, "snmp_format_value terminates an oversized value");
	CHECK(IS_UNDEFINED(output), "snmp_format_value records an oversized value as U");

	snmp_set_var_typed_value(&vars, ASN_OCTET_STR, (const u_char *) "short", 5);

	memset(output, 'G', RESULTS_BUFFER);
	CHECK(snmp_format_value(output, RESULTS_BUFFER, &vars), "snmp_format_value accepts a value that fits");
	CHECK(memchr(output, '\0', RESULTS_BUFFER) != NULL && strstr(output, "short") != NULL, "snmp_format_value terminates a value that fits");

	snmp_reset_var_buffers(&vars);
	free(value);
	free(output);
}

/* Collect the single quoted SQL string literals of a row, undoing backslash escapes. */
static int quoted_fields(const char *row, char fields[][RESULTS_BUFFER], int max_fields) {
	int    count = 0;
	size_t used;

	while (*row != '\0') {
		if (*row++ != '\'') continue;
		if (count == max_fields) return -1;

		used = 0;
		while (*row != '\0' && *row != '\'') {
			if (*row == '\\' && row[1] != '\0') row++;
			if (used + 1 >= RESULTS_BUFFER) return -1;
			fields[count][used++] = *row++;
		}
		if (*row != '\'') return -1;
		row++;

		fields[count++][used] = '\0';
	}

	return count;
}

static void test_poller_output_row(void) {
	MYSQL  *mysql = mysql_init(NULL);
	char   rrd_name[sizeof(((target_t *) 0)->rrd_name)];
	char   result[RESULTS_BUFFER];
	char   row[RESULTS_BUFFER * 2 + DBL_BUFSIZE + SMALL_BUFSIZE];
	char   escaped[8];
	char   (*fields)[RESULTS_BUFFER] = calloc(3, RESULTS_BUFFER);
	size_t i;
	size_t trailing;

	CHECK(mysql != NULL && fields != NULL, "poller output test setup");
	if (mysql == NULL || fields == NULL) return;

	/* values at their maximum length made only of characters that need escaping */
	for (i = 0; i < sizeof(rrd_name) - 1; i++) rrd_name[i] = (i % 2) ? '\'' : '\\';
	rrd_name[sizeof(rrd_name) - 1] = '\0';
	for (i = 0; i < sizeof(result) - 1; i++) result[i] = (i % 3 == 0) ? '\'' : ((i % 3 == 1) ? '\\' : '"');
	result[sizeof(result) - 1] = '\0';

	CHECK(format_poller_output_row(mysql, row, sizeof(row), 42, rrd_name, "1700000000", result), "poller output row fits at maximum value lengths");
	CHECK(quoted_fields(row, fields, 3) == 2, "poller output row keeps exactly two string literals");
	CHECK(strcmp(fields[0], rrd_name) == 0, "poller output row round trips rrd_name");
	CHECK(strcmp(fields[1], result) == 0, "poller output row round trips result");

	CHECK(format_poller_output_row(mysql, row, sizeof(row), 7, "ds:name", "1700000000", "in:1 out:2") &&
		strcmp(row, " (7, 'ds:name', FROM_UNIXTIME(1700000000), 'in:1 out:2')") == 0, "poller output row leaves plain values unchanged");

	CHECK(!format_poller_output_row(mysql, row, 16, 7, "ds", "1700000000", "1"), "poller output row reports a row that does not fit");

	/* a destination too small for the input keeps only whole escape sequences */
	memset(escaped, 'G', sizeof(escaped));
	db_escape(mysql, escaped, sizeof(escaped), "\\\\\\\\\\\\\\\\\\\\");
	CHECK(memchr(escaped, '\0', sizeof(escaped)) != NULL, "db_escape terminates a truncated value");
	for (trailing = 0, i = strlen(escaped); i > 0 && escaped[i - 1] == '\\'; i--) trailing++;
	CHECK(strlen(escaped) > 0 && trailing % 2 == 0, "db_escape does not split an escape sequence");

	free(fields);
	mysql_close(mysql);
}

/* Descriptors held open so the next one allocated is FD_SETSIZE or above. */
static int held_fds[FD_SETSIZE];
static int held_count = 0;
static struct rlimit saved_limit;

static bool hold_low_descriptors(void) {
	struct rlimit limit;
	rlim_t wanted = FD_SETSIZE + 64;
	int fd;

	if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return FALSE;
	saved_limit = limit;
	if (limit.rlim_max != RLIM_INFINITY && limit.rlim_max < wanted) return FALSE;
	if (limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur < wanted) {
		limit.rlim_cur = wanted;
		if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return FALSE;
	}

	while ((fd = open("/dev/null", O_RDONLY)) >= 0) {
		held_fds[held_count++] = fd;
		if (fd >= FD_SETSIZE - 1 || held_count == FD_SETSIZE) break;
	}

	return fd == FD_SETSIZE - 1;
}

static void release_low_descriptors(void) {
	while (held_count > 0) close(held_fds[--held_count]);
	setrlimit(RLIMIT_NOFILE, &saved_limit);
}

static unsigned short closed_udp_port(void) {
	struct sockaddr_in address = {0};
	socklen_t length = sizeof(address);
	unsigned short port = 0;
	int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (fd >= 0 && bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0 &&
		getsockname(fd, (struct sockaddr *)&address, &length) == 0) {
		port = ntohs(address.sin_port);
	}
	if (fd >= 0) close(fd);

	return port;
}

/* Callers switch on the select() result, so the replacement has to keep it. */
static void test_wait_fd_readable(void) {
	struct timeval none = {0, 0};
	struct timeval negative = {0, -1};
	struct timeval oversized = {0, 1000000};
	char byte;
	int pdes[2];
	int closed;

	CHECK(pipe(pdes) == 0, "wait_fd_readable test pipe");
	CHECK(wait_fd_readable(pdes[0], &none) == 0, "wait_fd_readable times out on an empty pipe");

	errno = 0;
	CHECK(wait_fd_readable(pdes[0], &negative) == -1 && errno == EINVAL, "wait_fd_readable rejects a negative timeout as select() does");

	errno = 0;
	CHECK(wait_fd_readable(pdes[0], &oversized) == -1 && errno == EINVAL, "wait_fd_readable rejects tv_usec of a second or more as select() does");

	errno = 0;
	CHECK(wait_fd_readable(-1, &none) == -1 && errno == EBADF, "wait_fd_readable reports a negative descriptor as EBADF");

	close(pdes[1]);
	CHECK(wait_fd_readable(pdes[0], &none) == 1 && read(pdes[0], &byte, 1) == 0, "wait_fd_readable reports end of file as readable");

	closed = pdes[0];
	close(closed);
	errno = 0;
	CHECK(wait_fd_readable(closed, &none) == -1 && errno == EBADF, "wait_fd_readable reports a closed descriptor as EBADF");
}

static void test_descriptors_above_fd_setsize(void) {
	host_t host;
	ping_t ping;
	php_t server;
	int pdes[2];
	int no_debug_devices[1] = {0};
	int saved_script_timeout;
	int saved_php_servers;
	unsigned short port = closed_udp_port();
	char *result;

	if (!hold_low_descriptors()) {
		release_low_descriptors();
		printf("ok - # SKIP RLIMIT_NOFILE cannot reach FD_SETSIZE %d\n", FD_SETSIZE);
		return;
	}

	debug_devices = no_debug_devices;
	saved_script_timeout = set.script_timeout;
	saved_php_servers = set.php_servers;
	set.script_timeout = 5;

	/* macOS has no unnamed semaphores, so exec_poll() cannot take a script permit there */
	if (sem_init(&available_scripts, 0, 1) == 0) {
		memset(&host, 0, sizeof(host));
		host.id = 1;
		result = exec_poll(&host, "/bin/echo 42", 1, "DS");
		CHECK(result != NULL && strncmp(result, "42", 2) == 0, "exec_poll reads a script pipe at or above FD_SETSIZE");
		free(result);
		sem_destroy(&available_scripts);
	} else {
		printf("ok - # SKIP sem_init is unavailable for the exec_poll script permit\n");
	}

	memset(&host, 0, sizeof(host));
	memset(&ping, 0, sizeof(ping));
	host.id = 1;
	snprintf(host.hostname, sizeof(host.hostname), "127.0.0.1");
	host.ping_port = port;
	host.ping_timeout = 1000;
	host.ping_retries = 0;
	CHECK(port != 0 && ping_udp(&host, &ping) == HOST_UP, "ping_udp waits on a socket at or above FD_SETSIZE");

	CHECK(pipe(pdes) == 0 && pdes[0] >= FD_SETSIZE, "script server test pipe is at or above FD_SETSIZE");
	CHECK(write(pdes[1], "42\n", 3) == 3, "script server test reply is written");
	memset(&server, 0, sizeof(server));
	server.php_read_fd = pdes[0];
	server.php_write_fd = -1;
	php_processes = &server;
	set.php_servers = 1;
	result = php_readpipe(0, "INIT");
	CHECK(result != NULL && strncmp(result, "42", 2) == 0, "php_readpipe reads a Script Server pipe at or above FD_SETSIZE");
	free(result);
	php_processes = NULL;
	set.php_servers = saved_php_servers;
	set.script_timeout = saved_script_timeout;
	close(pdes[0]);
	close(pdes[1]);
	debug_devices = NULL;

	release_low_descriptors();
}

int main(void) {
	/* keep completed checks visible if a later one crashes, and fail a
	 * stalled script server restart instead of hanging make check */
	setvbuf(stdout, NULL, _IOLBF, 0);
	alarm(60);
	init_mutexes();
	test_add_slashes();
	test_snmp_format_value();
	test_poller_output_row();
	test_wait_fd_readable();
	test_descriptors_above_fd_setsize();

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
