#!/bin/sh
# Structural guards for the remote push path's cross-vendor and batching rules.
set -eu

srcdir="${srcdir:-.}"
cd "$srcdir"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

body=$(awk '/^void poller_push_data_to_main\(void\) \{/{f=1} f{print} f&&/^\}/{exit}' util.c)

[ -n "$body" ] || fail "could not find poller_push_data_to_main() in util.c"

printf '%s\n' "$body" | grep -q 'AS rs ON DUPLICATE KEY UPDATE' &&
	fail "remote pushes must not use row-alias syntax selected from the local server"

printf '%s\n' "$body" | grep -q 'if (set.dbonupdate' &&
	fail "remote pushes must not branch on the local server version"

awk '/^static void push_flush_batch/{f=1} f{print} f&&/^\}/{exit}' util.c |
	grep -q 'if (!spine_appendf' ||
	fail "overflowed remote push batches must not be sent"

exit 0
