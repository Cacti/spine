#!/usr/bin/env bash
# Integration tests for db_column_exists() runtime detection in spine.
#
# Exercises three schema lifecycle states for poller_item.output_regex:
#   1. Absent  (baseline Cacti 1.3.0 schema) -- no detection log, no SQL errors
#   2. Present (ALTER TABLE ADD COLUMN)       -- detection log fires, correct output
#   3. Removed (ALTER TABLE DROP COLUMN)      -- graceful fallback, correct output
#
# For each state the test also verifies that poller_output is written and
# host.total_polls is incremented, confirming end-to-end poll correctness.
#
# Requires: docker compose (uses the snmpv3 test fixture).
# Usage: ./tests/integration/test_db_column_detect.sh
set -euo pipefail


# These need a prepared docker fixture and an in-tree build, neither of which
# holds under `make distcheck`, where the tree is a read-only copy. Default to
# skipping so `make check` stays meaningful everywhere; the integration
# workflow sets SPINE_INTEGRATION=1 where the fixture is actually up.
#
# The earlier guard only checked whether docker existed. On a GitHub runner it
# does, so these ran and failed rather than skipping.
if [ "${SPINE_INTEGRATION:-0}" != "1" ]; then
	echo "  SKIP: set SPINE_INTEGRATION=1 with the docker fixture running"
	exit 77
fi

# Skip rather than fail where the fixture cannot run: 77 is the exit status
# automake reads as SKIP, so `make check` stays green on a machine without
# docker while still reporting the test as not run.
if ! command -v docker >/dev/null 2>&1; then
	echo "  SKIP: docker not installed"
	exit 77
fi

if ! docker compose version >/dev/null 2>&1; then
	echo "  SKIP: docker compose not available"
	exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

cleanup() {
	echo ""
	echo "=== Cleanup ==="
	"${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

wait_for_db() {
	local max_wait=120
	local elapsed=0
	echo "  Waiting for database with seed data (up to ${max_wait}s)..."
	while [[ $elapsed -lt $max_wait ]]; do
		local count
		count=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
			-N -e "SELECT COUNT(*) FROM host;" 2>/dev/null || echo "0")
		if [[ "$count" -gt 0 ]]; then
			echo "  Database ready after ${elapsed}s"
			return 0
		fi
		sleep 3
		elapsed=$((elapsed + 3))
	done
	echo "  Database not ready after ${max_wait}s"
	return 1
}

# Reset between runs: clear poller_output and zero total_polls so each
# scenario starts from a known baseline and the assertions are unambiguous.
reset_between_runs() {
	"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
		TRUNCATE poller_output;
		UPDATE host SET total_polls = 0 WHERE id = 1;
	" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
echo ""
echo "=== Setup: build and start infrastructure ==="
"${COMPOSE[@]}" build spine 2>&1 | tail -1
"${COMPOSE[@]}" up -d db snmpd 2>&1
wait_for_db || { fail "database did not start"; exit 1; }
pass "infrastructure ready"

# ---------------------------------------------------------------------------
# Scenario 1: Baseline schema -- output_regex column absent
#
# Spine must complete without SQL errors. The detection log must NOT appear
# (the column is absent so db_column_exists() returns FALSE and the branch
# is skipped entirely). poller_output and total_polls must be updated.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 1: column absent (baseline schema) ==="

col_check=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SHOW COLUMNS FROM poller_item LIKE 'output_regex';" 2>/dev/null || echo "")

if [[ -z "$col_check" ]]; then
	pass "output_regex column absent before run"
else
	fail "output_regex column unexpectedly present at baseline"
fi

reset_between_runs

output1=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
	--conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

# No SQL errors or crashes
if echo "$output1" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column\|FATAL.*Database"; then
	fail "scenario 1: spine crashed or SQL error (column absent)"
else
	pass "scenario 1: spine ran without error (column absent)"
fi

# Detection log must NOT appear -- column is absent so the branch is not taken
if echo "$output1" | grep -q "output_regex column detected"; then
	fail "scenario 1: detection log fired but column is absent"
else
	pass "scenario 1: detection log correctly absent"
fi

# poller_output written
s1_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$s1_output" ]]; then
	pass "scenario 1: poller_output written (value=$s1_output)"
else
	fail "scenario 1: poller_output empty"
fi

# total_polls incremented
s1_polls=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT total_polls FROM host WHERE id=1;" 2>/dev/null || echo "0")
if [[ "$s1_polls" -gt 0 ]]; then
	pass "scenario 1: host.total_polls incremented (total_polls=$s1_polls)"
else
	fail "scenario 1: host.total_polls not incremented"
fi

# ---------------------------------------------------------------------------
# Scenario 2: Column added -- db_column_exists() must detect it
#
# After ALTER TABLE the detection log must appear in spine's output and
# polling must remain fully functional.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 2: column added (ALTER TABLE ADD COLUMN) ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
	ALTER TABLE poller_item
		ADD COLUMN output_regex varchar(255) NOT NULL DEFAULT '' AFTER arg3;
" 2>/dev/null

col_check=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SHOW COLUMNS FROM poller_item LIKE 'output_regex';" 2>/dev/null || echo "")

if [[ -n "$col_check" ]]; then
	pass "output_regex column present after ALTER TABLE ADD"
else
	fail "output_regex column missing after ALTER TABLE ADD"
fi

reset_between_runs

output2=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
	--conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

# Detection log must appear (log_verbosity=5 / POLLER_VERBOSITY_DEBUG in seed)
if echo "$output2" | grep -q "output_regex column detected"; then
	pass "scenario 2: db_column_exists() detection logged"
else
	fail "scenario 2: detection log absent -- db_column_exists() may not be firing"
fi

# No crashes or SQL errors
if echo "$output2" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column\|FATAL.*Database"; then
	fail "scenario 2: spine crashed or SQL error (column present)"
else
	pass "scenario 2: spine ran without error (column present)"
fi

# poller_output written
s2_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$s2_output" ]]; then
	pass "scenario 2: poller_output written (value=$s2_output)"
else
	fail "scenario 2: poller_output empty"
fi

# total_polls incremented
s2_polls=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT total_polls FROM host WHERE id=1;" 2>/dev/null || echo "0")
if [[ "$s2_polls" -gt 0 ]]; then
	pass "scenario 2: host.total_polls incremented (total_polls=$s2_polls)"
else
	fail "scenario 2: host.total_polls not incremented"
fi

# ---------------------------------------------------------------------------
# Scenario 3: Column removed -- spine must fall back gracefully
#
# After ALTER TABLE DROP COLUMN spine must not crash, must not emit an
# "Unknown column" error, and must continue writing output and updating polls.
# ---------------------------------------------------------------------------
echo ""
echo "=== Scenario 3: column removed (ALTER TABLE DROP COLUMN) ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
	ALTER TABLE poller_item DROP COLUMN output_regex;
" 2>/dev/null

col_check=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SHOW COLUMNS FROM poller_item LIKE 'output_regex';" 2>/dev/null || echo "")

if [[ -z "$col_check" ]]; then
	pass "output_regex column absent after ALTER TABLE DROP"
else
	fail "output_regex column still present after ALTER TABLE DROP"
fi

reset_between_runs

output3=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
	--conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

# Must not crash or produce a SQL error referencing the dropped column
if echo "$output3" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column\|FATAL.*Database"; then
	fail "scenario 3: spine crashed or SQL error after column removal"
else
	pass "scenario 3: spine handled column removal gracefully"
fi

# Detection log must NOT appear -- column is absent again
if echo "$output3" | grep -q "output_regex column detected"; then
	fail "scenario 3: detection log fired but column was dropped"
else
	pass "scenario 3: detection log correctly absent after drop"
fi

# poller_output written
s3_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$s3_output" ]]; then
	pass "scenario 3: poller_output written (value=$s3_output)"
else
	fail "scenario 3: poller_output empty after column removal"
fi

# total_polls incremented
s3_polls=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
	-N -e "SELECT total_polls FROM host WHERE id=1;" 2>/dev/null || echo "0")
if [[ "$s3_polls" -gt 0 ]]; then
	pass "scenario 3: host.total_polls incremented (total_polls=$s3_polls)"
else
	fail "scenario 3: host.total_polls not incremented after column removal"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
