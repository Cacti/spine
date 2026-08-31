#!/usr/bin/env bash
# Integration tests for spine command-line argument handling.
#
# Regression guard for the -O/--option NULL-deref fix: "spine -O foo" (no
# colon) must report the error and must NOT segfault.  Also checks that a
# well-formed "-O name:value" is accepted and that --version / -h work.
#
# Runs against a locally built spine binary (./spine after ./configure && make)
# or one on PATH.  If no binary is found the script skips with exit 77, which
# automake and prove treat as "skipped".
#
# Usage: ./tests/integration/test_cli_args.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

# Locate the spine binary: built in the repo root, or on PATH.
SPINE=""
if [[ -x "$REPO_ROOT/spine" ]]; then
	SPINE="$REPO_ROOT/spine"
elif command -v spine >/dev/null 2>&1; then
	SPINE="$(command -v spine)"
fi

if [[ -z "$SPINE" ]]; then
	echo "  SKIP: no spine binary found."
	echo "        Build one first: ./configure && make   (needs net-snmp + mysql)."
	exit 77
fi

echo "  Using spine binary: $SPINE"

# Run spine and capture exit code + stderr without aborting under set -e.
# $1 = label, remaining args = spine args.  Sets RC and ERR globals.
run_spine() {
	local _label="$1"; shift
	ERR="$("$SPINE" "$@" 2>&1 >/dev/null)" && RC=0 || RC=$?
}

# ---------------------------------------------------------------------------
# Test 1: -O without a colon -- must report the error, must not crash
#
# die() exits with set.exit_code, which is 0 during init, so the meaningful
# regression signal is the error message plus the absence of a crash signal,
# not a non-zero status.  Before the fix this path dereferenced a NULL value.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: -O foo (missing colon) ==="

run_spine "no-colon" -O foo

if echo "$ERR" | grep -q "requires setting:value"; then
	pass "spine reported the -O syntax error"
else
	fail "spine did not report the -O syntax error (stderr: $ERR)"
fi

# RC 139 = 128+SIGSEGV, 134 = 128+SIGABRT.  Either means a crash.
if [[ "$RC" -eq 139 || "$RC" -eq 134 ]]; then
	fail "spine crashed on '-O foo' (rc=$RC) -- NULL-deref regression"
else
	pass "spine did not crash on '-O foo' (rc=$RC)"
fi

# ---------------------------------------------------------------------------
# Test 2: -O name:value -- must be accepted (no syntax error)
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: -O name:value (well-formed) ==="

run_spine "well-formed" -O log_verbosity:1 --version

if echo "$ERR" | grep -q "requires setting:value"; then
	fail "spine rejected a well-formed -O name:value"
else
	pass "spine accepted -O name:value"
fi

# ---------------------------------------------------------------------------
# Test 3: --version prints the banner and exits cleanly
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: --version ==="

version_out="$("$SPINE" --version 2>&1)" && vrc=0 || vrc=$?

if echo "$version_out" | grep -q "SPINE.*Copyright"; then
	pass "--version printed the banner"
else
	fail "--version did not print the banner (got: $version_out)"
fi

if [[ "$vrc" -eq 0 ]]; then
	pass "--version exited 0"
else
	fail "--version exited non-zero (rc=$vrc)"
fi

# ---------------------------------------------------------------------------
# Test 4: --help prints usage and exits cleanly
#
# Note: the short "-h" is shadowed by "-H/--hostlist" because option matching
# is case-insensitive (STRIMATCH), so only the long "--help" reaches the help
# branch.  We test the form that actually works.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: --help ==="

help_out="$("$SPINE" --help 2>&1)" && hrc=0 || hrc=$?

if echo "$help_out" | grep -q "Usage: spine"; then
	pass "--help printed the usage listing"
else
	fail "-h did not print usage (got: $help_out)"
fi

if [[ "$hrc" -eq 0 ]]; then
	pass "--help exited 0"
else
	fail "-h exited non-zero (rc=$hrc)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
