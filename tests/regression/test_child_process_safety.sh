#!/bin/sh
# Structural guard for the child process hardening.
#
# The behaviour is covered by tests/unit/test_linked.c, which opens a pipe and
# checks the flag survives an exec, and by test_poll_host_release. This script
# is the cheaper backstop for the failure that actually happened: PR #542
# removed the whole mechanism in a stale-branch merge, and nothing noticed.
#
# It stayed red on develop from that merge onward because nothing ran it. It is
# in TESTS now, so `make check` fails instead of a person having to remember.
set -eu

# automake runs the suite from the build directory, which is not the source
# directory under `make distcheck`. Everything below reads source files.
srcdir="${srcdir:-.}"
cd "$srcdir"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# The close-on-exec helper lives in nft_popen.c and both callers share it.
grep -q 'FD_CLOEXEC' nft_popen.c ||
	fail "nft_popen.c must set close-on-exec on pipe fds"

grep -q 'spine_open_pipe_cloexec(pdes)' nft_popen.c ||
	fail "nft_popen() must open its pipe with close-on-exec"

grep -q 'spine_open_pipe_cloexec(cacti2php_pdes)' php.c ||
	fail "php.c must protect the cacti-to-php pipe with close-on-exec"

grep -q 'spine_open_pipe_cloexec(php2cacti_pdes)' php.c ||
	fail "php.c must protect the php-to-cacti pipe with close-on-exec"

# The reap must be bounded and must escalate.
grep -q 'waitpid(pid, pstat, WNOHANG)' nft_popen.c ||
	fail "nft_popen.c must reap child processes with WNOHANG"

grep -q 'kill(cur->pid, SIGKILL)' nft_popen.c ||
	fail "nft_popen.c must escalate a timed-out reap to SIGKILL"

if grep -q 'waitpid(cur->pid, &pstat, 0)' nft_popen.c; then
	fail "nft_pclose() must not block in waitpid()"
fi

if grep -q 'waitpid(phpp->php_pid, &wstatus, 0)' php.c; then
	fail "php_close() must not block in waitpid()"
fi

# ping_icmp() owns a packet and a raw socket and has six exits. One of them
# closed the socket and returned without freeing the packet (#593). Both are
# released in one place now, so there must be exactly one of each.
[ "$(grep -c 'SPINE_FREE(packet)' ping.c)" = "1" ] ||
	fail "ping_icmp() must release its packet in one place"

[ "$(grep -c 'close(icmp_socket)' ping.c)" = "1" ] ||
	fail "ping_icmp() must close its socket in one place"

# close() needs no privileges; re-entering root to call it widened the elevated
# window and serialised every poller thread on LOCK_SETEUID.
if grep -A6 'close(icmp_socket)' ping.c | grep -q 'seteuid(0)'; then
	fail "ping_icmp() must not elevate to close its socket"
fi

# Every exit from poll_host() must end the MySQL thread; see #594.
grep -q 'mysql_thread_end' poller.c ||
	fail "poll_host() must end the MySQL thread"

echo "PASS: child process safety invariants"
