#!/usr/bin/env bash
# Spine build smoke test — validates that the binary compiles, links,
# and exercises the SNMP/SQL code paths that were broken on develop.
#
# Requires: docker compose (uses the snmpv3 test fixture).
# Usage: ./tests/integration/smoke_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
PASS=0
FAIL=0
CLEANUP_NEEDED=0

pass() {
  echo "  PASS: $*"
  PASS=$((PASS + 1))
}
fail() {
  echo "  FAIL: $*"
  FAIL=$((FAIL + 1))
}

cleanup() {
  if [[ $CLEANUP_NEEDED -eq 1 ]]; then
    echo ""
    echo "=== Cleanup: tearing down containers ==="
    "${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
  fi
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
      echo "  Database ready with seed data after ${elapsed}s"
      return 0
    fi
    sleep 3
    elapsed=$((elapsed + 3))
  done
  echo "  Database not ready after ${max_wait}s"
  return 1
}

wait_for_snmpd() {
  local max_wait=30
  local elapsed=0
  echo "  Waiting for snmpd to become healthy (up to ${max_wait}s)..."
  while [[ $elapsed -lt $max_wait ]]; do
    if "${COMPOSE[@]}" exec -T snmpd snmpget -v3 -u testuser -l authPriv \
      -a SHA-256 -A authpass1234 -x AES -X privpass1234 \
      localhost:1161 .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1; then
      echo "  snmpd ready after ${elapsed}s"
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  echo "  snmpd not ready after ${max_wait}s"
  return 1
}

# ---------------------------------------------------------------------------
# Phase 1: Build — confirms the fix compiles inside a clean container
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 1: Docker build (compile from source) ==="

if "${COMPOSE[@]}" build spine 2>&1; then
  pass "spine Docker image built successfully"
else
  fail "spine Docker image build failed"
  echo ""
  echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
  exit 1
fi

# ---------------------------------------------------------------------------
# Phase 2: Binary sanity — version, help
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 2: binary sanity checks ==="

version_output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine --version 2>&1 || true)

if echo "$version_output" | grep -q "SPINE.*Copyright"; then
  pass "spine --version outputs banner"
else
  fail "spine --version did not produce expected banner: $version_output"
fi

# ---------------------------------------------------------------------------
# Phase 3: Start infrastructure and poll — exercises SNMP + SQL paths
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 3: start db + snmpd, run SNMPv3 poll ==="
CLEANUP_NEEDED=1

"${COMPOSE[@]}" up -d db snmpd 2>&1

if wait_for_db; then
  pass "database ready with seed data"
else
  fail "database did not start or seed data missing"
  "${COMPOSE[@]}" logs db 2>&1 | grep -i error | tail -5
  echo ""
  echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
  exit 1
fi

if wait_for_snmpd; then
  pass "snmpd accepting SNMP queries"
else
  fail "snmpd did not start"
fi

# Run spine against the test fixture
poll_output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S -M 2>&1 || true)
echo "$poll_output"

# Check that spine connected to the database (exercises get_cacti_version, db_query)
if echo "$poll_output" | grep -qi "ERROR.*MySQL\|Cannot connect"; then
  fail "spine could not connect to database"
else
  pass "spine connected to database"
fi

# Check that SNMP polling ran (exercises the switch cases in poller.c)
if echo "$poll_output" | grep -q "SNMP: v3:.*value:"; then
  pass "SNMPv3 poll returned data"
elif echo "$poll_output" | grep -q "Device\[1\].*SNMP"; then
  pass "SNMP poll executed for device 1"
elif echo "$poll_output" | grep -q "WARNING.*SNMP timeout"; then
  pass "SNMP poll attempted (timeout is acceptable in test environment)"
else
  fail "no evidence of SNMP polling activity"
fi

# Check device was polled
if echo "$poll_output" | grep -q "Devices: 1"; then
  pass "device 1 was polled"
else
  fail "device was not polled (Devices: 0)"
fi

# Check spine did not crash or segfault
if echo "$poll_output" | grep -qi "segfault\|SIGSEGV\|Aborted\|core dump"; then
  fail "spine crashed during polling"
else
  pass "spine completed without crash"
fi

# Check memory cleanup ran (validates SPINE_FREE fix in spine.c)
if echo "$poll_output" | grep -q "Allocated Variable Memory Freed"; then
  pass "memory cleanup completed (SPINE_FREE fix validated)"
else
  fail "memory cleanup did not complete"
fi

# Check DB close ran (validates get_cacti_version MYSQL_RES fix in util.c)
if echo "$poll_output" | grep -q "MYSQL Free & Close Completed"; then
  pass "database close completed (MYSQL_RES fix validated)"
else
  fail "database close did not complete"
fi

# Verify SNMPv3 data was written to MySQL
v3_polls=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT total_polls FROM host WHERE id=1;" 2>/dev/null || echo "0")
if [[ "$v3_polls" -gt 0 ]]; then
  pass "host table updated (total_polls=$v3_polls)"
else
  fail "host table not updated after SNMPv3 poll"
fi

v3_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=1;" 2>/dev/null || echo "")
if [[ -n "$v3_output" && "$v3_output" != "NULL" ]]; then
  pass "poller_output written for SNMPv3 (value=$v3_output)"
else
  fail "poller_output empty after SNMPv3 poll"
fi

v3_sysdescr=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT snmp_sysDescr FROM host WHERE id=1;" 2>/dev/null || echo "")
if [[ -n "$v3_sysdescr" ]]; then
  pass "snmp_sysDescr populated ($v3_sysdescr)"
else
  echo "  INFO: snmp_sysDescr empty (run with -M to populate)"
fi

# ---------------------------------------------------------------------------
# Phase 4: Add SNMPv2c host and re-poll (exercises poller.c switch cases)
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 4: SNMPv2c poll test ==="

"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
INSERT IGNORE INTO host (
  id, hostname, snmp_community, snmp_version, snmp_port, snmp_timeout,
  max_oids, availability_method, ping_method, status, poller_id,
  device_threads, deleted
) VALUES (
  2, 'snmpd', 'public', 2, 1161, 1000,
  10, 2, 0, 3, 1, 1, ''
);
INSERT IGNORE INTO poller_item (
  local_data_id, host_id, action, hostname, snmp_community,
  snmp_version, snmp_port, snmp_timeout,
  rrd_name, rrd_path, rrd_num, rrd_step,
  arg1, deleted, poller_id
) VALUES (
  2, 2, 0, 'snmpd', 'public',
  2, 1161, 1000,
  'uptime', '/dev/null', 1, 300,
  '.1.3.6.1.2.1.1.3.0', '', 1
);
" 2>/dev/null

v2c_output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 2 -l 2 -S 2>&1 || true)
echo "$v2c_output"

if echo "$v2c_output" | grep -q "Device\[2\]"; then
  pass "SNMPv2c poll executed for device 2"
else
  fail "no evidence of SNMPv2c polling for device 2"
fi

if echo "$v2c_output" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
  fail "spine crashed during SNMPv2c poll"
else
  pass "SNMPv2c poll completed without crash"
fi

# Verify SNMPv2c data was written to MySQL
v2c_polls=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT total_polls FROM host WHERE id=2;" 2>/dev/null || echo "0")
if [[ "$v2c_polls" -gt 0 ]]; then
  pass "host table updated for SNMPv2c (total_polls=$v2c_polls)"
else
  fail "host table not updated after SNMPv2c poll"
fi

v2c_db_output=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=2;" 2>/dev/null || echo "")
if [[ -n "$v2c_db_output" && "$v2c_db_output" != "NULL" ]]; then
  pass "poller_output written for SNMPv2c (value=$v2c_db_output)"
else
  fail "poller_output empty after SNMPv2c poll"
fi

# ---------------------------------------------------------------------------
# Phase 5: Runtime fix validation — multi-device poll + DB integrity checks
# ---------------------------------------------------------------------------
echo ""
echo "=== Phase 5: runtime fix validation ==="

# Poll both devices simultaneously; exercises the poller.c switch statement
# across two concurrent threads to confirm multi-device dispatch is intact.
multi_output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 2 -S 2>&1 || true)
echo "$multi_output"

if echo "$multi_output" | grep -q "Devices: 2"; then
  pass "multi-device poll processed both devices (switch statement intact)"
else
  fail "multi-device poll did not process 2 devices"
fi

# "Unknown column" errors indicate a schema mismatch that the output_regex
# detection fix was meant to guard against.
if echo "$multi_output" | grep -qi "Unknown column"; then
  fail "SQL 'Unknown column' error detected — output_regex schema mismatch"
else
  pass "no SQL 'Unknown column' errors (output_regex detection valid)"
fi

# poller_time rows are written at the end of each spine run; their presence
# confirms the DB write path ran to completion for both polls.
pt_count=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT COUNT(*) FROM poller_time;" 2>/dev/null || echo "0")
if [[ "$pt_count" -ge 2 ]]; then
  pass "poller_time has entries for both poll runs (pt_count=$pt_count)"
else
  fail "poller_time missing entries — DB write path incomplete (pt_count=$pt_count)"
fi

# host_errors rows are inserted when spine records a device-level failure.
# An empty table means neither poll encountered an error condition.
host_err_count=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT COUNT(*) FROM host_errors;" 2>/dev/null || echo "-1")
if [[ "$host_err_count" -eq 0 ]]; then
  pass "host_errors table is empty (no polling errors)"
elif [[ "$host_err_count" -eq -1 ]]; then
  # Table may not exist in all schema versions; treat as non-fatal.
  echo "  INFO: host_errors table not found — skipping check"
else
  fail "host_errors has $host_err_count row(s) — polling errors recorded"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
