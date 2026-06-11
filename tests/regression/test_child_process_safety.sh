#!/bin/sh
set -eu

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

grep -q '#include <fcntl.h>' common.h ||
	fail "common.h must include fcntl.h for FD_CLOEXEC helpers"

grep -q 'FD_CLOEXEC' php.c ||
	fail "php.c must set close-on-exec on script-server pipe fds"

grep -q 'FD_CLOEXEC' nft_popen.c ||
	fail "nft_popen.c must set close-on-exec on popen pipe fds"

grep -q 'php_set_pipe_cloexec(cacti2php_pdes)' php.c ||
	fail "php.c must protect cacti-to-php pipe fds with close-on-exec"

grep -q 'php_set_pipe_cloexec(php2cacti_pdes)' php.c ||
	fail "php.c must protect php-to-cacti pipe fds with close-on-exec"

grep -q 'set_pipe_cloexec(pdes)' nft_popen.c ||
	fail "nft_popen.c must protect popen pipe fds with close-on-exec"

grep -q 'waitpid(pid, pstat, WNOHANG)' nft_popen.c ||
	fail "nft_popen.c must reap child processes with WNOHANG"

grep -q 'kill(cur->pid, SIGKILL)' nft_popen.c ||
	fail "nft_popen.c must escalate timed-out child reaping to SIGKILL"

grep -q 'switch (pid = fork())' nft_popen.c ||
	fail "nft_popen.c must use fork() for child process creation"

grep -q 'pid = fork()' php.c ||
	fail "php.c must use fork() for script-server child process creation"

if grep -q 'waitpid(cur->pid, &pstat, 0)' nft_popen.c; then
	fail "nft_popen.c must not use blocking waitpid() in nft_pclose"
fi

if grep -q 'waitpid(phpp->php_pid, &wstatus, 0)' php.c; then
	fail "php.c must not use blocking waitpid() in php_close"
fi

if grep -q 'vfork()' nft_popen.c php.c; then
	fail "deprecated vfork() must not be used in child process creation"
fi

echo "PASS: child process safety invariants"
