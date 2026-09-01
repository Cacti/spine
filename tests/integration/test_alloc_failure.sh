#!/usr/bin/env bash
# Integration test for the startup allocation guards (issue#564).
#
# php_processes and debug_devices are dereferenced on the line after their
# calloc(), so an allocation failure there used to be a NULL deref rather than
# a diagnosable exit.  A unit test cannot reach them: they live in main().
# This injects the failure into the real binary with an LD_PRELOAD calloc that
# returns NULL on the Nth call, and asserts spine dies with its own message.
#
# The db_pool_local and db_pool_remote guards are not covered here.  They run
# after the database connection, so reaching them needs the SNMPv3 harness's
# MySQL container rather than a bare binary.
#
# Skips with exit 77 (automake and prove read that as "skipped") when the
# binary, a compiler, or LD_PRELOAD interposition is unavailable, so the
# suite stays green on platforms where this technique does not apply.
#
# Usage: ./tests/integration/test_alloc_failure.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

SPINE=""
if [[ -x "$REPO_ROOT/spine" ]]; then
	SPINE="$REPO_ROOT/spine"
elif command -v spine >/dev/null 2>&1; then
	SPINE="$(command -v spine)"
fi

if [[ -z "$SPINE" ]]; then
	echo "no spine binary found; skipping"
	exit 77
fi

if ! command -v cc >/dev/null 2>&1; then
	echo "no compiler available for the interposer; skipping"
	exit 77
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/failcalloc.c" <<'INTERPOSER'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>

/* Return NULL from the Nth calloc() of the process, pass the rest through. */
static long seen;
static long fail_at = -1;

void *calloc(size_t nmemb, size_t size) {
	static void *(*real_calloc)(size_t, size_t);

	if (real_calloc == NULL) {
		const char *at;

		real_calloc = dlsym(RTLD_NEXT, "calloc");
		at = getenv("SPINE_FAIL_CALLOC_AT");

		if (at != NULL) {
			fail_at = atol(at);
		}
	}

	if (++seen == fail_at) {
		return NULL;
	}

	return real_calloc(nmemb, size);
}
INTERPOSER

if ! cc -shared -fPIC -o "$WORK/failcalloc.so" "$WORK/failcalloc.c" -ldl 2>/dev/null; then
	echo "could not build the LD_PRELOAD interposer; skipping"
	exit 77
fi

# Sanity check: without injection --help must still work, otherwise the
# interposer itself is broken and every assertion below would be meaningless.
if ! LD_PRELOAD="$WORK/failcalloc.so" "$SPINE" --help >/dev/null 2>&1; then
	echo "LD_PRELOAD interposition not supported here; skipping"
	exit 77
fi

echo "Allocation failure guards:"

# --help exits before the database connection, so only the two allocations at
# the top of main() are reachable.  They are the first and second calloc() the
# process makes.
check_guard() {
	local nth="$1" want="$2" out

	out="$(SPINE_FAIL_CALLOC_AT="$nth" LD_PRELOAD="$WORK/failcalloc.so" "$SPINE" --help 2>&1 || true)"

	if grep -q "Fatal calloc error: spine.c $want" <<<"$out"; then
		pass "calloc #$nth failing reports $want"
	else
		fail "calloc #$nth failing did not report $want (got: ${out:0:120})"
	fi

	if grep -qiE 'segmentation fault|signal 11' <<<"$out"; then
		fail "calloc #$nth failing crashed instead of exiting cleanly"
	else
		pass "calloc #$nth failing did not crash"
	fi
}

check_guard 1 php_processes
check_guard 2 debug_devices

echo
echo "passed: $PASS, failed: $FAIL"
[[ "$FAIL" -eq 0 ]]
