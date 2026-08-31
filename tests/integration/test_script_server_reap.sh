#!/usr/bin/env bash
# Integration test for the PHP script-server reap fix in php_close().
#
# Bug: php_close() sent SIGTERM but never waitpid()'d the child, so each
# script-server shutdown left a <defunct> zombie.  Fix: reap with waitpid()
# and reset php_pid.  This test drives a real poll against a script-server
# data source (poller_item.action = POLLER_ACTION_PHP_SCRIPT_SERVER = 2) and
# asserts no zombie php child survives the run.
#
# Requires: docker compose AND a spine runtime image that bundles PHP plus a
# script_server.php the poller can exec.  The default snmpv3 fixture image is
# debian-slim with no PHP, so this test skips (exit 77) there with the exact
# additions needed.  Wire it up in CI where the full Cacti image is available.
#
# Usage: ./tests/integration/test_script_server_reap.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }

skip() {
	echo "  SKIP: $1"
	exit 77
}

# ---------------------------------------------------------------------------
# Preconditions: docker, the compose fixture, and a PHP-capable spine image.
# ---------------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || skip "docker not installed"
docker compose version >/dev/null 2>&1 || skip "docker compose plugin not available"

echo ""
echo "=== Setup: build spine image and probe for PHP ==="
"${COMPOSE[@]}" build spine >/dev/null 2>&1 \
	|| skip "spine image failed to build (build env not available)"

# The script server execs PHP; without it the action=2 path cannot run.
if ! "${COMPOSE[@]}" run --rm --no-deps --entrypoint sh spine \
		-c 'command -v php >/dev/null 2>&1'; then
	skip "spine runtime image has no PHP. To run this test, extend
        tests/snmpv3/Dockerfile (or use the full Cacti image) to install
        php-cli and provide a script_server.php, then seed a poller_item with
        action=2 (POLLER_ACTION_PHP_SCRIPT_SERVER)."
fi

cleanup() {
	echo ""
	echo "=== Cleanup ==="
	"${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

"${COMPOSE[@]}" up -d db snmpd >/dev/null 2>&1

# Wait for seed data.
elapsed=0
while [[ $elapsed -lt 120 ]]; do
	count=$("${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti \
		-N -e "SELECT COUNT(*) FROM host;" 2>/dev/null || echo "0")
	[[ "$count" -gt 0 ]] && break
	sleep 3; elapsed=$((elapsed + 3))
done
[[ "$count" -gt 0 ]] || { fail "database did not start"; exit 1; }
pass "infrastructure ready"

# ---------------------------------------------------------------------------
# Seed a script-server data source (action=2) for host 1.
# ---------------------------------------------------------------------------
echo ""
echo "=== Seed script-server poller_item (action=2) ==="
"${COMPOSE[@]}" exec -T db mariadb -uspine -pspine cacti -e "
INSERT IGNORE INTO poller_item (
  local_data_id, host_id, action, hostname,
  rrd_name, rrd_path, rrd_num, rrd_step, arg1, deleted, poller_id
) VALUES (
  900, 1, 2, 'localhost',
  'ss', '/dev/null', 1, 300, 'ss_test.php ss_value 1', '', 1
);" 2>/dev/null
pass "script-server poller_item seeded"

# ---------------------------------------------------------------------------
# Poll: spine starts the script server, then php_close() must reap it.
# Run inside one container so we can inspect its process table afterward.
# ---------------------------------------------------------------------------
echo ""
echo "=== Poll and check for zombie php children ==="

poll_out=$("${COMPOSE[@]}" run --rm --entrypoint sh spine -c '
	/usr/local/bin/spine --conf=/etc/spine/spine.conf -f 1 -l 1 -S
	echo "---PROCTABLE---"
	ps -eo pid,ppid,stat,comm 2>/dev/null || true
' 2>&1 || true)
echo "$poll_out"

if echo "$poll_out" | grep -qi "segfault\|SIGSEGV\|Aborted"; then
	fail "spine crashed during script-server poll"
else
	pass "spine completed script-server poll without crash"
fi

# A reaped child leaves no <defunct>/Z-state php entry.
proctable=$(echo "$poll_out" | sed -n '/---PROCTABLE---/,$p')
if echo "$proctable" | grep -Ei '<defunct>|[[:space:]]Z[[:space:]+]*[[:space:]]php'; then
	fail "zombie php child remained after poll (php_close reap regression)"
else
	pass "no zombie php child after poll"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== Results: ${PASS} passed, ${FAIL} failed ==="
[[ $FAIL -eq 0 ]]
