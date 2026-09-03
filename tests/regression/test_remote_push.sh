#!/bin/sh
# Structural guard for the cross-vendor upsert rule.
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

exit 0
