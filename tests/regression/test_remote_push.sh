#!/bin/sh
# Structural guards for the remote push path's cross-vendor and batching rules.
set -eu

srcdir="${srcdir:-.}"
cd "$srcdir"

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

queries_body=$(awk '/^static void transfer_queries\(/{f=1} f{print} f&&/^\}/{exit}' src/database/transfer.c)
table_body=$(awk '/^static bool transfer_table\(/{f=1} f{print} f&&/^\}/{exit}' src/database/transfer.c)
prepare_body=$(awk '/^void poller_prepare_queries\(/{f=1} f{print} f&&/^\}/{exit}' src/poller/query.c)

[ -n "$queries_body" ] || fail "could not find transfer_queries() in src/database/transfer.c"
[ -n "$table_body" ] || fail "could not find transfer_table() in src/database/transfer.c"
[ -n "$prepare_body" ] || fail "could not find poller_prepare_queries() in src/poller/query.c"

printf '%s\n' "$queries_body" | grep -q 'AS rs' &&
	fail "remote pushes must not use row-alias syntax selected from the local server"

printf '%s\n' "$queries_body" | grep -q 'onupdate' &&
	fail "remote pushes must not branch on the local server version"

printf '%s\n' "$table_body" | grep -q 'length + suffix_length + 3 > HUGE_BUFSIZE - used' ||
	fail "remote push batches must flush before a row that would overflow them"

printf '%s\n' "$prepare_body" | grep -q 'onupdate' &&
	fail "poller_output must not select SQL syntax from the local server version"

printf '%s\n' "$prepare_body" | grep -q 'output=VALUES(output)' ||
	fail "poller_output must use the cross-vendor upsert form"

exit 0
