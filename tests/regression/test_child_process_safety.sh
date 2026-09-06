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

if grep -q 'waitpid(cur->pid, &pstat, 0)' nft_popen.c; then
	fail "nft_popen.c must not use blocking waitpid() in nft_pclose"
fi

if grep -q 'waitpid(phpp->php_pid, &wstatus, 0)' php.c; then
	fail "php.c must not use blocking waitpid() in php_close"
fi

echo "PASS: child process safety invariants"

# php_init() has one cleanup path that closes every descriptor it still holds,
# so spine_open_pipe_cloexec() must not return FALSE while leaving live
# descriptor numbers in the caller's array; that path would close them twice,
# and in a threaded daemon the second close lands on whatever another thread
# opened in between. The cloexec branch cannot be driven from a unit test:
# fcntl(F_SETFD) does not fail on a valid descriptor, and ld --wrap cannot
# intercept the call because it is inside the same translation unit.
awk '/^int spine_open_pipe_cloexec/,/^}/' nft_popen.c |
	grep -q 'pdes\[0\] = -1;' ||
	fail "spine_open_pipe_cloexec() must clear pdes when it fails after opening the pipe"

# php_init() must have exactly one teardown. Five hand-copied ones drifted and
# every one of them leaked the command buffer.
php_init_body=$(awk '/^int php_init\(int php_process\) \{/{f=1} f{print} f&&/^\}/{exit}' php.c)

printf '%s\n' "$php_init_body" | grep -cE '^\s+return FALSE;' | grep -qx '1' ||
	fail "php_init() must reach its teardown by goto, not by a return that skips it"

printf '%s\n' "$php_init_body" | grep -q '^cleanup:' ||
	fail "php_init() must have a single cleanup label"

exit 0
