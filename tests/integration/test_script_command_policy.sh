#!/usr/bin/env bash
# Integration test for unsafe script command rejection.
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

echo ""
echo "=== Setup: build and start infrastructure ==="
if ! "${COMPOSE[@]}" build spine; then
  fail "spine image build failed"
  exit 1
fi
"${COMPOSE[@]}" up -d db snmpd 2>&1
wait_for_db || {
  fail "database did not start"
  exit 1
}
pass "infrastructure ready"

echo ""
echo "=== Configure script command with blocked metacharacter ==="
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
UPDATE host
SET availability_method = 0,
    ping_method = 0
WHERE id = 1;

INSERT IGNORE INTO poller_item (
  local_data_id, host_id, action, hostname, snmp_community,
  snmp_version, snmp_port, snmp_timeout,
  rrd_name, rrd_path, rrd_num, rrd_step, arg1, deleted, poller_id
) VALUES (
  4, 1, 1, 'snmpd', 'public',
  2, 1161, 1000,
  'script_guard', '/dev/null', 1, 300, 'echo 1; id', '', 1
);
" 2>/dev/null
pass "blocked script test item configured"

echo ""
echo "=== Run poll and validate command rejection ==="
output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 1 -l 1 -S 2>&1 || true)
echo "$output"

if echo "$output" | grep -qi "segfault|SIGSEGV|Aborted|core dump"; then
  fail "spine crashed during blocked script command test"
else
  pass "spine stayed stable while handling blocked script command"
fi

if echo "$output" | grep -q "Device\[1\]"; then
  pass "script test device was processed"
else
  fail "no evidence that script test item host was processed"
fi

if echo "$output" | grep -qi "Refusing unsafe script command"; then
  pass "unsafe script command was explicitly rejected"
else
  fail "missing explicit unsafe script command rejection log"
fi

result_value=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT output FROM poller_output WHERE local_data_id=4 ORDER BY time DESC LIMIT 1;" 2>/dev/null || echo "")
if [[ "$result_value" == "U" || -z "$result_value" ]]; then
  pass "blocked script output did not produce unsafe numeric value"
else
  fail "blocked script output unexpectedly produced '$result_value'"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
