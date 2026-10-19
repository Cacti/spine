#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-only
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
# Run one test program under Valgrind for the nightly workflow, either as the
# make check LOG_COMPILER or directly. VALGRIND_TOOL selects memcheck or
# helgrind.
#
# Valgrind runs without --error-exitcode: forked children inherit it and
# would exit with that code, which breaks tests that check a child's exit
# status. Each process logs to its own file instead, and any error reported
# in any of them fails the test.
#
# SPINE_VALGRIND_INCOMPATIBLE lists programs whose own assertions cannot hold
# under Valgrind. One of those that fails with no Valgrind error is reported
# as skipped (77), never as passed.
set -eu

test_program=$1
here=$(cd -- "$(dirname -- "$0")" && pwd)
logs=$(mktemp -d)
trap 'rm -rf "$logs"' EXIT

case "$VALGRIND_TOOL" in
memcheck)
	set -- --leak-check=full --errors-for-leak-kinds=definite \
		--track-origins=yes \
		--suppressions="$here/../suppressions/memcheck.supp" "$@"
	;;
helgrind)
	set -- --suppressions="$here/../suppressions/helgrind.supp" "$@"
	;;
*)
	echo "unknown VALGRIND_TOOL: $VALGRIND_TOOL" >&2
	exit 2
	;;
esac

status=0
valgrind --tool="$VALGRIND_TOOL" --log-file="$logs/%p.log" "$@" || status=$?
cat "$logs"/*.log >&2

errors=$(cat "$logs"/*.log |
	sed -n 's/.*ERROR SUMMARY: \([0-9][0-9]*\) errors.*/\1/p' |
	awk '{ total += $1 } END { print total + 0 }')
if [ "$errors" -gt 0 ]; then
	echo "$test_program: Valgrind reported $errors error(s)" >&2
	exit 1
fi

if [ "$status" -ne 0 ]; then
	for name in ${SPINE_VALGRIND_INCOMPATIBLE:-}; do
		if [ "${test_program##*/}" = "$name" ]; then
			echo "$test_program: exit $status without a Valgrind error;" \
				"its assertions do not hold under Valgrind" >&2
			exit 77
		fi
	done
fi
exit "$status"
