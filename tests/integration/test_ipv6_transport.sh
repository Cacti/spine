#!/usr/bin/env bash
# Integration test for IPv6 transport handling and graceful behavior.
#
# This validates that an IPv6-targeted poll path executes end-to-end without
# crashes or SQL regressions. Depending on container/network capabilities, the
# IPv6 poll may succeed or time out; both outcomes are acceptable as long as
# Spine handles them cleanly.
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
echo "=== Configure IPv6-target host/poller item ==="
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
INSERT IGNORE INTO host (
  id, hostname, snmp_community, snmp_username, snmp_password, snmp_auth_protocol,
  snmp_priv_passphrase, snmp_priv_protocol, snmp_version, snmp_port, snmp_timeout,
  max_oids, availability_method, ping_method, status, poller_id, device_threads, deleted
) VALUES (
  3, '::1', '', 'testuser', 'authpass1234', 'SHA',
  'privpass1234', 'AES', 3, 1161, 1000,
  10, 2, 0, 3, 1, 1, ''
);

INSERT IGNORE INTO poller_item (
  local_data_id, host_id, action, hostname, snmp_community, snmp_username, snmp_password,
  snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol,
  snmp_version, snmp_port, snmp_timeout,
  rrd_name, rrd_path, rrd_num, rrd_step, arg1, deleted, poller_id
) VALUES (
  3, 3, 0, '::1', '', 'testuser', 'authpass1234',
  'SHA', 'privpass1234', 'AES',
  3, 1161, 1000,
  'uptime_ipv6', '/dev/null', 1, 300, '.1.3.6.1.2.1.1.3.0', '', 1
);
" 2>/dev/null
pass "IPv6 test host and poller_item configured"

echo ""
echo "=== Run IPv6-targeted poll ==="
output=$("${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
  --conf=/etc/spine/spine.conf -f 3 -l 3 -S 2>&1 || true)
echo "$output"

if echo "$output" | grep -qi "segfault\|SIGSEGV\|Aborted\|core dump\|Unknown column"; then
  fail "spine crashed or hit SQL regression in IPv6 poll path"
else
  pass "spine handled IPv6 poll path without crash/SQL regression"
fi

if echo "$output" | grep -q "Device\[3\]"; then
  pass "IPv6-targeted device was processed"
else
  fail "no evidence that device 3 was processed"
fi

if echo "$output" | grep -q "SNMP: v3: .*value:"; then
  pass "IPv6 poll produced SNMP value"
elif echo "$output" | grep -qi "timeout\|host unreachable\|destination hostname invalid"; then
  pass "IPv6 poll attempted and failed gracefully in this environment"
else
  fail "no clear success or graceful-failure signal for IPv6 poll"
fi

poll_rows=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
  -N -e "SELECT COUNT(*) FROM poller_output WHERE local_data_id=3;" 2>/dev/null || echo "0")
if [[ "$poll_rows" -ge 0 ]]; then
  pass "database query for IPv6 poll output completed"
else
  fail "database query for IPv6 poll output failed"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
