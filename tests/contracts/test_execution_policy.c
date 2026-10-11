/* SPDX-FileCopyrightText: 2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later */
#include "internal/common.h"
#include "app/spine.h"
#include <limits.h>

static void expect_script(host_t *host, char *command, const char *expected) {
	char *result = exec_poll(host, command, 712, "DS");
	if (result == NULL || strcmp(result, expected) != 0)
		fprintf(stderr, "execution-policy fixture %s: expected %s, got %s\n", command, expected, result == NULL ? "NULL" : result);
	assert(result != NULL && strcmp(result, expected) == 0);
	free(result);
	assert(spine_permits_available(&available_scripts) == 1);
}

typedef struct {
	host_t *host;
	char *command;
} canceled_script_t;

static void *run_canceled_script(void *argument) {
	canceled_script_t *script = argument;
	char *result = exec_poll(script->host, script->command, 713, "DS");
	free(result);
	return NULL;
}

static void cancellation_contract(host_t *host) {
	char filename[] = "spine-policy-child-XXXXXX";
	char command[BUFSIZE];
	pthread_t worker;
	void *outcome;
	canceled_script_t script = {host, command};
	FILE *file;
	int fd = mkstemp(filename);
	int pid = 0;
	int attempts;
	assert(fd >= 0 && close(fd) == 0);
	/* $$ belongs to nft_popen's shell, which Spine can reap directly. A nested
	 * shell may remain a zombie until the environment's init adopts/reaps it. */
	snprintf(command, sizeof(command), "/usr/bin/printf '%%s' $$ > %s; /usr/bin/printf 42; sleep 30", filename);
	assert(pthread_create(&worker, NULL, run_canceled_script, &script) == 0);
	for (attempts = 0; attempts < 100 && pid == 0; attempts++) {
		file = fopen(filename, "r");
		assert(file != NULL);
		(void) fscanf(file, "%d", &pid);
		assert(fclose(file) == 0);
		if (pid == 0) usleep(10000);
	}
	assert(pid > 1);
	assert(pthread_cancel(worker) == 0 && pthread_join(worker, &outcome) == 0);
	assert(outcome == PTHREAD_CANCELED);
	assert(spine_permits_available(&available_scripts) == 1);
	for (attempts = 0; attempts < 100 && nft_abandoned_pending() != 0; attempts++) usleep(10000);
	assert(nft_abandoned_pending() == 0);
	assert(kill(pid, 0) == -1 && errno == ESRCH);
	assert(unlink(filename) == 0);
	/* Cancellation while waiting must not manufacture an unowned permit. */
	assert(spine_permits_try_acquire(&available_scripts) == 0);
	assert(pthread_create(&worker, NULL, run_canceled_script, &script) == 0);
	usleep(50000);
	assert(pthread_cancel(worker) == 0 && pthread_join(worker, &outcome) == 0);
	assert(outcome == PTHREAD_CANCELED && spine_permits_available(&available_scripts) == 0);
	assert(spine_permits_release(&available_scripts) == 0);
}

void test_execution_policy(void) {
	config_t saved = set;
	host_t host = {.id = 981};
	char executable[PATH_MAX];
	char config_name[] = "spine-policy-XXXXXX";
	FILE *config;
	int fd;
	pid_t child;
	int status;
	const char *invalid[] = {"-1", "+1", "garbage", "1x", "4294967296", "999999999999999999999999"};
	size_t i;
	assert(realpath("./spine", executable) != NULL);
	assert(strlen(executable) < sizeof(set.php.script_executable));
	strcpy(set.php.script_executable, executable);
	set.php.script_timeout = 2;
	set.php.script_max_output = set.php.script_cpu_seconds = set.php.script_memory_mb = 0;
	assert(spine_permits_init(&available_scripts, 1) == 0);
	expect_script(&host, "/usr/bin/printf 42", "42");
	expect_script(&host, "/bin/sh -c 'printf 42; exit 7'", "42");
	set.php.script_max_output = 2;
	expect_script(&host, "/usr/bin/printf 42", "42");
	expect_script(&host, "/usr/bin/printf 421", "U");
	expect_script(&host, "/usr/bin/printf ''", "U");
	expect_script(&host, "/bin/sh -c 'printf 42; exit 7'", "U");
	expect_script(&host, "/bin/sh -c 'printf 42; exec 1>&-; sleep 30'", "U");
	expect_script(&host, "./tests/support/resource_fixture chunked", "42");
	expect_script(&host, "./tests/support/resource_fixture linger", "U");
	cancellation_contract(&host);
	set.php.script_cpu_seconds = 1;
	expect_script(&host, "./tests/support/resource_fixture cpu", "U");
	expect_script(&host, "./tests/support/resource_fixture limits", "1");
	set.php.script_executable[0] = '\0';
	expect_script(&host, "/usr/bin/printf 42", "U");
	strcpy(set.php.script_executable, executable);
#ifdef __linux__
	set.php.script_memory_mb = 64;
	expect_script(&host, "./tests/support/resource_fixture memory", "U");
	expect_script(&host, "/usr/bin/printf 42", "42");
#endif
	assert(spine_permits_destroy(&available_scripts) == 0);
	for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		strcpy(config_name, "spine-policy-XXXXXX");
		fd = mkstemp(config_name);
		assert(fd >= 0);
		config = fdopen(fd, "w");
		assert(config != NULL && fprintf(config, "ScriptCpuSeconds %s\n", invalid[i]) > 0);
		assert(fclose(config) == 0);
		child = fork();
		assert(child >= 0);
		if (child == 0) {
			read_spine_config(config_name);
			_exit(99);
		}
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
		assert(unlink(config_name) == 0);
	}
	strcpy(config_name, "spine-policy-XXXXXX");
	fd = mkstemp(config_name);
	assert(fd >= 0);
	config = fdopen(fd, "w");
	assert(config != NULL);
	assert(fprintf(config, "ScriptMaxOutputBytes %d\nScriptCpuSeconds 2\nScriptMemoryMB 0\n", RESULTS_BUFFER - 1) > 0);
	assert(fclose(config) == 0 && read_spine_config(config_name) == 0);
	assert(set.php.script_max_output == RESULTS_BUFFER - 1 && set.php.script_cpu_seconds == 2 && set.php.script_memory_mb == 0);
	assert(unlink(config_name) == 0);
	/* A configured cap cannot exceed storage or disappear through an empty directive. */
	for (i = 0; i < 3; i++) {
		strcpy(config_name, "spine-policy-XXXXXX");
		fd = mkstemp(config_name);
		assert(fd >= 0);
		config = fdopen(fd, "w");
		assert(config != NULL);
		if (i == 0) assert(fprintf(config, "ScriptMaxOutputBytes %d\n", RESULTS_BUFFER) > 0);
		else if (i == 1) assert(fputs("ScriptCpuSeconds\n", config) >= 0);
#ifdef __linux__
		else assert(fputs("ScriptMemoryMB 4294967296\n", config) >= 0);
#else
		else assert(fputs("ScriptMemoryMB 64\n", config) >= 0);
#endif
		assert(fclose(config) == 0);
		child = fork();
		assert(child >= 0);
		if (child == 0) {
			read_spine_config(config_name);
			_exit(99);
		}
		assert(waitpid(child, &status, 0) == child);
		assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_FAILURE);
		assert(unlink(config_name) == 0);
	}
	status = system("./spine --internal-script-child >/dev/null");
	assert(status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 125);
	for (i = 0; i < 100 && nft_abandoned_pending() != 0; i++) usleep(10000);
	assert(nft_abandoned_pending() == 0);
	set = saved;
}
