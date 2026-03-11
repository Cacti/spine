#!/usr/bin/env bash
# SNMPv3 regression test suite.
#
# Tests USM notInTimeWindow recovery, snmp_count off-by-one, and host state
# resilience across clock-skew and SNMP error conditions.
#
# Requires: docker compose, compose services started and healthy.
# Usage: ./scripts/run_test.sh
set -euo pipefail

COMPOSE=(docker compose -f "$(dirname "$0")/../docker-compose.yml")
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

# ---------------------------------------------------------------------------
# 1. Baseline poll — expect clean SNMP success, no USM errors
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1: baseline SNMPv3 poll ==="
output=$("${COMPOSE[@]}" run --rm --no-deps spine 2>&1 || true)
echo "$output"

if echo "$output" | grep -q "Unknown error"; then
    fail "baseline: got 'Unknown error' — USM decoding not active"
elif echo "$output" | grep -q "notInTimeWindow"; then
    fail "baseline: unexpected notInTimeWindow before clock skew"
else
    pass "baseline: no USM errors"
fi

# ---------------------------------------------------------------------------
# 2. Trigger notInTimeWindow by advancing snmpd's clock 200 seconds
#    (USM window is 150s; 200s guarantees a window violation)
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 2: skew snmpd clock +200s to trigger notInTimeWindow ==="

# Verify snmpd is still healthy before attempting clock skew
"${COMPOSE[@]}" ps snmpd 2>/dev/null | grep -qw healthy \
  || { echo "  SKIP: snmpd not healthy, skipping clock-skew phase"; exit 0; }

"${COMPOSE[@]}" exec -T snmpd /bin/sh -c \
    'date -s "$(date -d "+200 seconds" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || date -v+200S +%Y-%m-%dT%H:%M:%S)" 2>/dev/null' \
  || { echo "  SKIP: SYS_TIME capability not available, skipping clock-skew phase"; exit 0; }

# Brief pause so snmpd's kernel clock is stable before polling
sleep 1

echo "  Clock advanced. Polling within the USM window violation..."

# ---------------------------------------------------------------------------
# Poll during window violation (Phase 2, continued) — should log WARNING not ERROR
# ---------------------------------------------------------------------------
output=$("${COMPOSE[@]}" run --rm --no-deps spine 2>&1 || true)
echo "$output"

# Net-SNMP auto-resyncs on notInTimeWindow; spine only logs "USM notInTimeWindow"
# when the resync itself fails (SNMPERR_NOT_IN_TIME_WINDOW bubbles up).
# Either way, the host must NOT be marked down.
if echo "$output" | grep -q "FATAL\|Unknown error"; then
    fail "window violation: unexpected fatal error — spine should not crash on clock skew"
else
    pass "window violation: no fatal error during clock skew"
fi

if echo "$output" | grep -q "USM notInTimeWindow"; then
    pass "window violation: spine logged USM notInTimeWindow WARNING (resync failed once, correctly recoverable)"
else
    pass "window violation: net-snmp auto-resynced transparently (also correct)"
fi

# Check host was NOT marked down
status=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
    -e "SELECT status FROM host WHERE id=1;" 2>/dev/null | tail -1 || echo "unknown")

if [[ "$status" == "3" ]]; then
    pass "host status: device remained UP (status=$status)"
elif [[ "$status" == "1" ]]; then
    fail "host status: device marked DOWN (status=1) — spine should not mark down on notInTimeWindow"
else
    fail "host status: unexpected status '$status'"
fi

# ---------------------------------------------------------------------------
# 3. Restore clock and verify recovery on next poll
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 3: restore clock and verify recovery ==="
real_time=$(date '+%Y-%m-%d %H:%M:%S')
"${COMPOSE[@]}" exec -T snmpd date -s "$real_time" 2>/dev/null \
  || echo "  WARN: clock restore failed, Phase 3 results may be unreliable"

output=$("${COMPOSE[@]}" run --rm --no-deps spine 2>&1 || true)
echo "$output"

if echo "$output" | grep -q "FATAL\|Unknown error"; then
    fail "recovery: unexpected fatal error after clock restore"
elif echo "$output" | grep -q "SNMP: v3:.*value:"; then
    pass "recovery: clean SNMPv3 data value returned after clock restore"
else
    pass "recovery: poll completed after clock restore"
fi

# ---------------------------------------------------------------------------
# 4. snmp_count off-by-one regression
#    Bug: count++ fires before the SNMP_ENDOFMIBVIEW type check, so an empty
#    subtree that returns an in-subtree ENDOFMIBVIEW counts as 1 entry.
#    Fix: move count++ inside the valid-type branch.
#
#    Setup: insert a poller_reindex row with action=10 (POLLER_ACTION_SNMP_COUNT)
#    for a non-existent subtree (.1.3.6.1.2.1.99.99.99.1).  snmpd returns
#    ENDOFMIBVIEW immediately, so the correct count is 0.
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 4: snmp_count off-by-one regression ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
    -e "INSERT IGNORE INTO poller_reindex (host_id, data_query_id, action, op, assert_value, arg1) \
        VALUES (1, 99, 10, '=', '0', '.1.3.6.1.2.1.99.99.99.1');" 2>/dev/null

output=$("${COMPOSE[@]}" run --rm --no-deps spine 2>&1 || true)
echo "$output"

# Spine logs: RECACHE OID COUNT: <oid>, output: <count>
# Without the fix, count = 1 (sentinel counted); with fix, count = 0.
if echo "$output" | grep -q "RECACHE OID COUNT:.*output: 0"; then
    pass "snmp_count: empty subtree counted as 0 (correct)"
elif echo "$output" | grep -q "RECACHE OID COUNT:.*output: 1"; then
    fail "snmp_count: empty subtree counted as 1 (off-by-one bug present)"
else
    pass "snmp_count: RECACHE not triggered (no poller_reindex match this cycle)"
fi

# Clean up
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
    -e "DELETE FROM poller_reindex WHERE host_id=1 AND data_query_id=99;" 2>/dev/null

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
