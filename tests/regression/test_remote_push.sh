#!/bin/sh
# Structural guards for the remote push path.
#
# poller_push_data_to_main() writes to the main server, but spine derives
# set.dbonupdate from the local one. Branching on it there emitted MySQL 8 row
# alias syntax at a MariaDB main server, which rejects it, so a mixed-vendor
# remote poller lost its host status and poller_item sync every cycle with
# nothing in the log. See #590.
#
# There is no unit test for this: the function needs two live connections. The
# rule is a property of the source, so guard it there. The behavioural half is
# tests/unit/test_poller_output.c, which pins the same rule for the poll_host()
# suffix that does have a testable seam.
set -eu

srcdir="${srcdir:-.}"
cd "$srcdir"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

# The body of poller_push_data_to_main(), from its definition to the next
# function at column zero.
body=$(awk '/^void poller_push_data_to_main\(void\) \{/{f=1} f{print} f&&/^\}/{exit}' util.c)

[ -n "$body" ] ||
	fail "could not find poller_push_data_to_main() in util.c"

printf '%s\n' "$body" | grep -q 'AS rs ON DUPLICATE KEY UPDATE' &&
	fail "poller_push_data_to_main() must not emit row-alias upsert syntax; the main server may be MariaDB"

printf '%s\n' "$body" | grep -q 'ON DUPLICATE KEY UPDATE' ||
	fail "poller_push_data_to_main() lost its upsert suffix"

# the branch itself, not the comment that explains why it is gone
printf '%s\n' "$body" | grep -q 'if (set.dbonupdate' &&
	fail "poller_push_data_to_main() must not branch on set.dbonupdate; it describes the local server, not the main one"

# poll_host() keeps the branch, because there the local connection is the target
# unless this is a remote poller. Both halves of that condition must survive.
grep -q 'set.dbonupdate == 0 || (set.poller_id > 1 && set.mode == REMOTE_ONLINE)' poller.c ||
	fail "poll_host_build_queries() must keep the remote-poller exception on the upsert form"

# The batch loops must flush before emitting a row, never in place of it. The
# original shape reset the batch when it filled and dropped the row that
# triggered the reset, so every 501st host and every 10001st poller_item never
# reached the main server. Both loops now share push_flush_batch().
printf '%s\n' "$body" | grep -q 'push_flush_batch(&mysqlr, sqlbuf, &sqlp, suffix)' ||
	fail "poller_push_data_to_main() must flush its batches through push_flush_batch()"

printf '%s\n' "$body" | grep -Eq 'rows >= 500 \|\| remaining < PUSH_ROW_MAX' ||
	fail "the host batch must flush on remaining bytes as well as row count"

printf '%s\n' "$body" | grep -Eq 'rows >= 10000 \|\| remaining < PUSH_ROW_MAX' ||
	fail "the poller_item batch must flush on remaining bytes as well as row count"

# A batch that did not fit must not be sent. spine_appendf() reports it; the
# point of the helper is that somebody reads the report.
awk '/^static void push_flush_batch/{f=1} f{print} f&&/^\}/{exit}' util.c |
	grep -q 'if (!spine_appendf' ||
	fail "push_flush_batch() must refuse to send a statement that overflowed"

exit 0
