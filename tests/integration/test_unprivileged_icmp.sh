#!/usr/bin/env bash
# Integration tests for unprivileged ICMP availability (issue #250).
#
# Linux grants SOCK_DGRAM ICMP sockets to the groups in
# net.ipv4.ping_group_range.  Spine only ever asked for SOCK_RAW and decided
# ICMP was unavailable whenever it was neither root nor capability-endowed, so
# the sysctl had no effect.  These tests run spine as an unprivileged user with
# every capability dropped and assert that the sysctl alone decides the answer,
# and that a privileged run still takes the raw path.
#
# Requires: docker compose (uses the snmpv3 test fixture).
# Usage: ./tests/integration/test_unprivileged_icmp.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIXTURE="$REPO_ROOT/tests/snmpv3"
COMPOSE=(docker compose -f "$FIXTURE/docker-compose.yml")
IMAGE="snmpv3-spine"
NETWORK="snmpv3_default"
OPEN_RANGE="0 2147483647"
CLOSED_RANGE="1 0"
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
	local elapsed=0
	while [[ $elapsed -lt 120 ]]; do
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

# $1 sysctl value, remaining args are extra docker flags
run_spine() {
	local range="$1"
	shift
	docker run --rm \
		--network "$NETWORK" \
		--sysctl "net.ipv4.ping_group_range=$range" \
		-v "$FIXTURE/spine/spine.conf:/etc/spine/spine.conf:ro" \
		"$@" \
		"$IMAGE" --conf=/etc/spine/spine.conf 1 1 2>&1 || true
}

echo ""
echo "=== Setup: build and start infrastructure ==="
"${COMPOSE[@]}" build spine 2>&1 | tail -1
"${COMPOSE[@]}" up -d db snmpd 2>&1 | tail -2
echo "  Waiting for database..."
wait_for_db || { fail "database did not start"; exit 1; }

# availability_method 3 is AVAIL_PING, ping_method 1 is PING_ICMP
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
UPDATE host SET availability_method = 3, ping_method = 1 WHERE id = 1;
" 2>/dev/null
pass "infrastructure ready, host set to ICMP availability"

# ---------------------------------------------------------------------------
# Test 1: unprivileged, sysctl covers the caller
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: unprivileged with ping_group_range open ==="

out=$(run_spine "$OPEN_RANGE" --user 65534:65534 --cap-drop=ALL)

if echo "$out" | grep -q "Spine may use unprivileged ICMP sockets"; then
	pass "kernel granted a datagram ICMP socket without privileges"
else
	fail "no unprivileged ICMP socket with the sysctl open"
fi

if echo "$out" | grep -q "Spine has got ICMP"; then
	pass "ICMP marked available"
else
	fail "ICMP still marked unavailable"
fi

if echo "$out" | grep -q "Falling back to UDP Ping Due to SetUID Issues"; then
	fail "still fell back to UDP"
else
	pass "no UDP fallback"
fi

if echo "$out" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
	fail "spine crashed on the datagram path"
else
	pass "no crash on the datagram path"
fi

# ---------------------------------------------------------------------------
# Test 2: unprivileged, sysctl excludes the caller
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: unprivileged with ping_group_range closed ==="

out=$(run_spine "$CLOSED_RANGE" --user 65534:65534 --cap-drop=ALL)

if echo "$out" | grep -q "Spine has not got ICMP"; then
	pass "ICMP correctly reported unavailable"
else
	fail "ICMP reported available without privileges or the sysctl"
fi

if echo "$out" | grep -q "Falling back to UDP Ping Due to SetUID Issues"; then
	pass "fell back to UDP as before"
else
	fail "expected the UDP fallback"
fi

if echo "$out" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
	fail "spine crashed on the fallback path"
else
	pass "no crash on the fallback path"
fi

# ---------------------------------------------------------------------------
# Test 3: privileged run still takes the raw path
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: privileged with ping_group_range closed ==="

out=$(run_spine "$CLOSED_RANGE" --cap-add=NET_RAW)

if echo "$out" | grep -q "Spine has got ICMP"; then
	pass "raw socket path unaffected"
else
	fail "privileged run lost ICMP"
fi

if echo "$out" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
	fail "spine crashed on the raw path"
else
	pass "no crash on the raw path"
fi

echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
