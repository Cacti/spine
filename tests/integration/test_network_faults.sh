#!/usr/bin/env bash
# Verify that complete SNMP packet loss is bounded and polling recovers after
# connectivity returns. This is a lifecycle contract for both the current
# synchronous implementation and the future libuv reactor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMEOUT_SECONDS=${SPINE_TEST_TIMEOUT_SECONDS:-120}
PROJECT=${SPINE_TEST_PROJECT:-spine-network-faults-$$}
ARTIFACT_ROOT=${SPINE_TEST_ARTIFACT_DIR:-"$REPO_ROOT/test-artifacts/network-faults"}
EXTRA_ARGS=()
if [[ -n "${SPINE_TEST_EXTRA_ARGS:-}" ]]; then
	read -r -a EXTRA_ARGS <<< "$SPINE_TEST_EXTRA_ARGS"
fi

if [[ ! "$TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] || (( TIMEOUT_SECONDS < 10 )); then
	echo "SPINE_TEST_TIMEOUT_SECONDS must be an integer of at least 10" >&2
	exit 2
fi

export COMPOSE_PROJECT_NAME=$PROJECT
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
mkdir -p "$ARTIFACT_ROOT"
export SPINE_TEST_ARTIFACT_DIR=$ARTIFACT_ROOT
# shellcheck source=tests/test-harness.sh
source "$REPO_ROOT/tests/test-harness.sh"
harness_init "Spine SNMP network-fault integration"

cleanup() {
	local rc=$?
	"${COMPOSE[@]}" exec -T snmpd tc qdisc del dev eth0 root >/dev/null 2>&1 || true
	"${COMPOSE[@]}" ps --all > "$ARTIFACT_ROOT/compose-ps.txt" 2>&1 || true
	"${COMPOSE[@]}" logs --no-color > "$ARTIFACT_ROOT/compose.log" 2>&1 || true
	if [[ $rc -eq 0 || "${SPINE_TEST_KEEP_ENV_ON_FAILURE:-0}" != 1 ]]; then
		"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
	else
		printf 'Preserving failed Compose project %s\n' "$COMPOSE_PROJECT_NAME" >&2
	fi
}
trap cleanup EXIT

db_query() {
	"${COMPOSE[@]}" exec -T -e MYSQL_PWD=spine db \
		mariadb -uspine cacti -N -B -e "$1"
}

wait_for_fixture() {
	local elapsed=0
	while (( elapsed < 120 )); do
		if [[ "$(db_query 'SELECT COUNT(*) FROM host;' 2>/dev/null || true)" == 1 ]] && \
			"${COMPOSE[@]}" exec -T snmpd snmpget -v3 -u testuser -l authPriv \
			-a SHA-256 -A authpass1234 -x AES -X privpass1234 \
			localhost:1161 .1.3.6.1.2.1.1.3.0 >/dev/null 2>&1; then
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done
	return 1
}

run_spine() {
	local log_file=$1
	local rc
	set +e
	if command -v timeout >/dev/null 2>&1; then
		timeout --signal=TERM --kill-after=10 "$TIMEOUT_SECONDS" \
			"${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
			--conf=/etc/spine/spine.conf -f 1 -l 1 -S "${EXTRA_ARGS[@]}" \
			> "$log_file" 2>&1
	else
		"${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
			--conf=/etc/spine/spine.conf -f 1 -l 1 -S "${EXTRA_ARGS[@]}" \
			> "$log_file" 2>&1
	fi
	rc=$?
	set -e
	return "$rc"
}

reset_poll_state() {
	db_query "TRUNCATE poller_output; TRUNCATE host_errors;
		UPDATE host SET total_polls=0, failed_polls=0, status=3;"
}

echo "=== Build and start the isolated fixture ==="
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" build spine snmpd
"${COMPOSE[@]}" up -d db snmpd
if wait_for_fixture; then
	harness_pass "database and SNMP agent became ready"
else
	harness_fail "fixture did not become ready within 120 seconds"
	harness_finish || true
	exit 1
fi

baseline_log="$ARTIFACT_ROOT/baseline.log"
reset_poll_state
if run_spine "$baseline_log"; then
	harness_pass "baseline poll exits successfully"
else
	harness_fail "baseline poll exits successfully"
fi
harness_assert_eq 1 \
	"$(db_query "SELECT COUNT(*) FROM poller_output WHERE rrd_name = 'uptime';")" \
	"baseline poll writes its SNMP result"

echo "=== Drop every response from the SNMP agent ==="
"${COMPOSE[@]}" exec -T snmpd tc qdisc replace dev eth0 root netem loss 100%
loss_log="$ARTIFACT_ROOT/packet-loss.log"
reset_poll_state
if run_spine "$loss_log"; then
	harness_pass "poll under complete packet loss exits successfully"
else
	harness_fail "poll under complete packet loss exits successfully"
fi
loss_output=$(<"$loss_log")
harness_assert_not_contains "$loss_output" \
	'segmentation fault|SIGSEGV|Aborted|core dump|Polling timed out while waiting' \
	"packet loss does not crash or deadlock the poller"
harness_assert_eq 0 \
	"$(db_query "SELECT COUNT(*) FROM poller_output WHERE rrd_name = 'uptime';")" \
	"complete packet loss cannot produce a stale SNMP result"

echo "=== Restore connectivity and verify recovery ==="
"${COMPOSE[@]}" exec -T snmpd tc qdisc del dev eth0 root
recovery_log="$ARTIFACT_ROOT/recovery.log"
reset_poll_state
if run_spine "$recovery_log"; then
	harness_pass "recovery poll exits successfully"
else
	harness_fail "recovery poll exits successfully"
fi
recovery_output=$(<"$recovery_log")
harness_assert_not_contains "$recovery_output" \
	'segmentation fault|SIGSEGV|Aborted|core dump|FATAL' \
	"recovery poll has no fatal diagnostics"
harness_assert_eq 1 \
	"$(db_query "SELECT COUNT(*) FROM poller_output WHERE rrd_name = 'uptime';")" \
	"SNMP output resumes after packet loss"
harness_assert_eq 3 "$(db_query 'SELECT status FROM host WHERE id = 1;')" \
	"host is healthy after connectivity recovers"

harness_finish
