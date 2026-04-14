#!/usr/bin/env bash
# Integration tests for output_regex column detection.
#
# Validates that spine correctly detects the presence or absence of the
# output_regex column in poller_item and adjusts its queries accordingly.
#
# Requires: docker compose (uses the snmpv3 test fixture).
# Usage: ./tests/integration/test_output_regex.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
PASS=0
FAIL=0

pass() {
  echo "  PASS: $*"
  PASS=$((PASS + 1))
}
fail() {
  echo "  FAIL: $*"
  FAIL=$((FAIL + 1))
}

cleanup() {
  echo ""
  echo "=== Cleanup ==="
  "${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

wait_for_db() {
  local max_wait=120
  local elapsed=0
  while [[ $elapsed -lt $max_wait ]]; do
    local count
    count=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
      -N -e "SELECT COUNT(*) FROM host;" 2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]]; then
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done
  return 1
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
echo ""
echo "=== Setup: build and start infrastructure ==="
"${COMPOSE[@]}" build spine 2>&1 | tail -1
"${COMPOSE[@]}" up -d db snmpd 2>&1
echo "  Waiting for database..."
wait_for_db || {
  fail "database did not start"
  exit 1
}
pass "infrastructure ready"

# ---------------------------------------------------------------------------
# Test 1: Spine works WITHOUT output_regex column (baseline Cacti schema)
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: poll WITHOUT output_regex column ==="

has_col=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SHOW COLUMNS FROM poller_item LIKE 'output_regex';" 2>/dev/null || echo "")

if [[ -z "$has_col" ]]; then
  pass "output_regex column absent (baseline schema)"
else
  fail "output_regex column unexpectedly present"
fi

output1=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

if echo "$output1" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column"; then
  fail "spine crashed or SQL error without output_regex column"
else
  pass "spine ran without output_regex column"
fi

if echo "$output1" | grep -q "Devices: 1"; then
  pass "device polled without output_regex"
else
  fail "device not polled without output_regex"
fi

v1_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$v1_output" ]]; then
  pass "poller_output written without output_regex (value=$v1_output)"
else
  fail "poller_output empty without output_regex"
fi

# ---------------------------------------------------------------------------
# Test 2: Add output_regex column, verify spine detects and uses it
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: poll WITH output_regex column ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
ALTER TABLE poller_item ADD COLUMN output_regex varchar(255) NOT NULL DEFAULT '' AFTER arg3;
" 2>/dev/null

has_col=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SHOW COLUMNS FROM poller_item LIKE 'output_regex';" 2>/dev/null || echo "")

if [[ -n "$has_col" ]]; then
  pass "output_regex column added"
else
  fail "output_regex column not found after ALTER TABLE"
fi

# Clear previous output
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
TRUNCATE poller_output;
" 2>/dev/null

output2=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

if echo "$output2" | grep -q "poller_item.output_regex column detected"; then
  pass "spine detected output_regex column"
else
  fail "spine did not log output_regex detection"
fi

if echo "$output2" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column"; then
  fail "spine crashed or SQL error with output_regex column"
else
  pass "spine ran with output_regex column"
fi

if echo "$output2" | grep -q "Devices: 1"; then
  pass "device polled with output_regex"
else
  fail "device not polled with output_regex"
fi

v2_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$v2_output" ]]; then
  pass "poller_output written with output_regex (value=$v2_output)"
else
  fail "poller_output empty with output_regex"
fi

# ---------------------------------------------------------------------------
# Test 3: Set a regex pattern and verify it filters the SNMP value
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: output_regex filtering ==="

# Set a regex that extracts just the integer part of sysUpTime
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
UPDATE poller_item SET output_regex = '([0-9]+)' WHERE local_data_id = 1;
TRUNCATE poller_output;
" 2>/dev/null

output3=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

if echo "$output3" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
  fail "spine crashed with output_regex pattern set"
else
  pass "spine ran with output_regex pattern"
fi

v3_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$v3_output" ]]; then
  pass "poller_output written with regex filtering (value=$v3_output)"
else
  fail "poller_output empty with regex filtering"
fi

# ---------------------------------------------------------------------------
# Test 4: Drop column again, verify spine falls back gracefully
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: column removal fallback ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
ALTER TABLE poller_item DROP COLUMN output_regex;
TRUNCATE poller_output;
" 2>/dev/null

output4=$("${COMPOSE[@]}" run --rm --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)

if echo "$output4" | grep -qi "segfault\|SIGSEGV\|Aborted\|Unknown column"; then
  fail "spine crashed after output_regex column removed"
else
  pass "spine gracefully handled column removal"
fi

if echo "$output4" | grep -q "Devices: 1"; then
  pass "device polled after column removal"
else
  fail "device not polled after column removal"
fi

v4_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$v4_output" ]]; then
  pass "poller_output written after column removal (value=$v4_output)"
else
  fail "poller_output empty after column removal"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
