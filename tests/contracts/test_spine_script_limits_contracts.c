/*
 * SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "internal/common.h"
#include "app/spine.h"

static void check_script(host_t *host, const char *command, const char *expected) {
	char *copy = strdup(command);
	char *result;
	assert(copy != NULL);
	result = exec_poll(host, copy, 1, "DS");
	if (result == NULL || strcmp(result, expected) != 0)
		fprintf(stderr, "script limit result: expected='%s' actual='%s'\n", expected, result == NULL ? "NULL" : result);
	assert(result != NULL && strcmp(result, expected) == 0);
	free(copy);
	free(result);
	assert(spine_permits_available(&available_scripts) == 1);
}

typedef struct {
	host_t host;
	int cancellation_type;
	char command[BUFSIZE];
} cancelled_script_t;

static void *run_cancelled_script(void *argument) {
	cancelled_script_t *script = argument;
	char *result;
	pthread_setcanceltype(script->cancellation_type, NULL);
	result = exec_poll(&script->host, script->command, 1, "DS");
	free(result);
	return NULL;
}

static void test_script_cancellation(int cancellation_type) {
	cancelled_script_t script = {{0}, cancellation_type, "/bin/sleep 10"};
	pthread_t thread;
	void *returned;
	char marker[] = "spine-script-cancel-XXXXXX";
	int fd;
	FILE *file;
	int pid;
	double deadline;
	/* Cancellation while waiting must not return a permit owned by another
	 * thread. This previously inflated the permit count and leaked result. */
	assert(spine_permits_try_acquire(&available_scripts) == 0);
	assert(pthread_create(&thread, NULL, run_cancelled_script, &script) == 0);
	spine_sleep_usec(20000);
	assert(pthread_cancel(thread) == 0);
	assert(pthread_join(thread, &returned) == 0 && returned == PTHREAD_CANCELED);
	assert(spine_permits_available(&available_scripts) == 0);
	assert(spine_permits_release(&available_scripts) == 0);
	fd = mkstemp(marker);
	assert(fd >= 0 && close(fd) == 0);
	/* Use the registered group leader's PID, avoiding an orphan grandchild
	 * zombie when the container's PID 1 does not reap adopted descendants. */
	spine_snprintf(script.command, sizeof(script.command), "/usr/bin/printf ''; echo $$ > %s; exec /bin/sleep 10", marker);
	assert(pthread_create(&thread, NULL, run_cancelled_script, &script) == 0);
	deadline = spine_monotonic_time() + 5;
	pid = 0;
	while (pid <= 1 && spine_monotonic_time() < deadline) {
		file = fopen(marker, "r");
		assert(file != NULL);
		if (fscanf(file, "%i", &pid) != 1) pid = 0;
		assert(fclose(file) == 0);
		spine_sleep_usec(1000);
	}
	assert(pid > 1);
	assert(pthread_cancel(thread) == 0);
	assert(pthread_join(thread, &returned) == 0 && returned == PTHREAD_CANCELED);
	assert(spine_permits_available(&available_scripts) == 1);
	deadline = spine_monotonic_time() + 5;
	while (nft_abandoned_pending() && spine_monotonic_time() < deadline) spine_sleep_usec(1000);
	assert(nft_abandoned_pending() == 0);
	errno = 0;
	assert(kill(pid, 0) == -1 && errno == ESRCH);
	assert(unlink(marker) == 0);
}

void run_script_limit_contracts(void) {
	spine_php_config_t previous = set.php;
	host_t host = {0};
	char command[BUFSIZE];
	char file_path[] = "spine-script-file-XXXXXX";
	const char *probe = getenv("SPINE_SCRIPT_RESOURCE_PROBE");
	int fd;
	struct stat status;
	assert(spine_permits_init(&available_scripts, 1) == 0);
	set.php.script_timeout = 5;
	memset(&set.php.limits, 0, sizeof(set.php.limits));
	set.php.limits.output_bytes = 3;
	check_script(&host, "/usr/bin/printf 123", "123");
	check_script(&host, "/usr/bin/printf 1234", "U");
	check_script(&host, "/bin/sh -c 'printf 1; sleep 0.05; printf 23'", "123");
	check_script(&host, "/bin/sh -c 'printf 123; sleep 0.05; printf 4'", "U");
	check_script(&host, "/bin/sh -c 'printf 1; exit 42'", "U");
	set.php.limits.deadline_seconds = 1;
	check_script(&host, "/bin/sh -c 'printf 1; sleep 3'", "U");
	check_script(&host, "/usr/bin/printf ''", "U");
	memset(&set.php.limits, 0, sizeof(set.php.limits));
	test_script_cancellation(PTHREAD_CANCEL_DEFERRED);
	test_script_cancellation(PTHREAD_CANCEL_ASYNCHRONOUS);
#ifdef __linux__
	if (probe != NULL) {
		assert(strchr(probe, '\'') == NULL);
		set.php.limits = (spine_script_limits_t){0, 3, 1, 16384, 1, 16};
		spine_snprintf(command, sizeof(command), "/bin/sh -c 'exec \"$1\" policy' spine-probe '%s'", probe);
		check_script(&host, command, "1");
		spine_snprintf(command, sizeof(command), "/bin/sh -c 'exec \"$1\" cpu' spine-probe '%s'", probe);
		check_script(&host, command, "U");
		spine_snprintf(command, sizeof(command), "/bin/sh -c 'exec \"$1\" memory' spine-probe '%s'", probe);
		check_script(&host, command, "U");
		spine_snprintf(command, sizeof(command), "/bin/sh -c 'exec \"$1\" files' spine-probe '%s'", probe);
		check_script(&host, command, "U");
		fd = mkstemp(file_path);
		assert(fd >= 0 && close(fd) == 0);
		spine_snprintf(command, sizeof(command), "/bin/sh -c 'exec \"$1\" size \"$2\"' spine-probe '%s' '%s'", probe, file_path);
		check_script(&host, command, "U");
		assert(stat(file_path, &status) == 0 && status.st_size <= 1024);
		assert(unlink(file_path) == 0);
		puts("production child CPU, memory, file-size and descriptor limit contracts passed");
	}
#else
	(void) probe;
	(void) command;
	(void) file_path;
	(void) fd;
	(void) status;
	set.php.limits.cpu_seconds = 1;
	check_script(&host, "/usr/bin/printf 1", "U");
#endif
	assert(spine_permits_destroy(&available_scripts) == 0);
	set.php = previous;
	puts("production script output, deadline and cancellation ownership contracts passed");
}
