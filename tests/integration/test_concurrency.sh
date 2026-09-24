#!/usr/bin/env bash
# Exercise Spine against many independent hosts while sweeping worker counts.
# This is deliberately backend-neutral so the same contract can exercise the
# legacy pthread poller and the future sharded libuv reactor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

HOSTS=${SPINE_TEST_HOSTS:-24}
THREADS=${SPINE_TEST_THREAD_COUNTS:-"1 4 12"}
REPEATS=${SPINE_TEST_REPEATS:-1}
TIMEOUT_SECONDS=${SPINE_TEST_TIMEOUT_SECONDS:-120}
DATABASE=${SPINE_TEST_DATABASE:-mariadb}
PROJECT=${SPINE_TEST_PROJECT:-spine-concurrency-${DATABASE}-$$}
ARTIFACT_ROOT=${SPINE_TEST_ARTIFACT_DIR:-"$REPO_ROOT/test-artifacts/concurrency"}
EXTRA_ARGS=()
if [[ -n "${SPINE_TEST_EXTRA_ARGS:-}" ]]; then
	# This is argument splitting, not evaluation: shell metacharacters remain data.
	read -r -a EXTRA_ARGS <<< "$SPINE_TEST_EXTRA_ARGS"
fi

for numeric_value in "$HOSTS" "$REPEATS" "$TIMEOUT_SECONDS"; do
	[[ "$numeric_value" =~ ^[0-9]+$ ]] || {
		echo "host, repeat, and timeout values must be positive integers" >&2
		exit 2
	}
done
(( HOSTS >= 2 && HOSTS <= 500 )) || { echo "SPINE_TEST_HOSTS must be between 2 and 500" >&2; exit 2; }
(( REPEATS >= 1 && REPEATS <= 100 )) || { echo "SPINE_TEST_REPEATS must be between 1 and 100" >&2; exit 2; }
(( TIMEOUT_SECONDS >= 10 )) || { echo "SPINE_TEST_TIMEOUT_SECONDS must be at least 10" >&2; exit 2; }

export COMPOSE_PROJECT_NAME=$PROJECT
COMPOSE=(docker compose -f "$REPO_ROOT/tests/snmpv3/docker-compose.yml")
case "$DATABASE" in
	mariadb) ;;
	mysql) COMPOSE+=(-f "$REPO_ROOT/tests/snmpv3/docker-compose.mysql.yml") ;;
	*) echo "unsupported SPINE_TEST_DATABASE: $DATABASE" >&2; exit 2 ;;
esac

mkdir -p "$ARTIFACT_ROOT"
export SPINE_TEST_ARTIFACT_DIR=$ARTIFACT_ROOT
# shellcheck source=tests/test-harness.sh
source "$REPO_ROOT/tests/test-harness.sh"
harness_init "Spine concurrency integration"

cleanup() {
	local rc=$?
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
		"$DATABASE" -uspine cacti -N -B -e "$1"
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

run_with_timeout() {
	if command -v timeout >/dev/null 2>&1; then
		timeout --signal=TERM --kill-after=10 "$TIMEOUT_SECONDS" "$@"
	else
		"$@"
	fi
}

echo "=== Build and start the isolated fixture ==="
"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
"${COMPOSE[@]}" build spine
"${COMPOSE[@]}" up -d db snmpd
if wait_for_fixture; then
	harness_pass "database and SNMP agent became ready"
else
	harness_fail "fixture did not become ready within 120 seconds"
	harness_finish || true
	exit 1
fi

# Clone the real v3 host and its SNMP item. All rows address the same agent but
# maintain independent host/session state, which exposes lost completions and
# host ownership errors without requiring hundreds of containers.
db_query "
DELIMITER //
CREATE PROCEDURE seed_stress_hosts(IN wanted INT)
BEGIN
  DECLARE current_id INT DEFAULT 2;
  WHILE current_id <= wanted DO
    INSERT INTO host (
      id, hostname, snmp_community, snmp_version, snmp_username, snmp_password,
      snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol,
      snmp_context, snmp_engine_id, snmp_port, snmp_timeout, max_oids,
      availability_method, ping_method, ping_port, ping_timeout, ping_retries,
      status, poller_id, device_threads, deleted
    ) SELECT
      current_id, hostname, snmp_community, snmp_version, snmp_username, snmp_password,
      snmp_auth_protocol, snmp_priv_passphrase, snmp_priv_protocol,
      snmp_context, '', snmp_port, snmp_timeout, max_oids,
      availability_method, ping_method, ping_port, ping_timeout, ping_retries,
      status, poller_id, device_threads, deleted
    FROM host WHERE id = 1;

    INSERT INTO poller_item (
      local_data_id, host_id, action, hostname, snmp_community,
      snmp_version, snmp_username, snmp_password, snmp_auth_protocol,
      snmp_priv_passphrase, snmp_priv_protocol, snmp_context, snmp_engine_id,
      snmp_port, snmp_timeout, rrd_name, rrd_path, rrd_num, rrd_step,
      arg1, deleted, poller_id
    ) SELECT
      1000 + current_id, current_id, action, hostname, snmp_community,
      snmp_version, snmp_username, snmp_password, snmp_auth_protocol,
      snmp_priv_passphrase, snmp_priv_protocol, snmp_context, '',
      snmp_port, snmp_timeout, rrd_name, rrd_path, rrd_num, rrd_step,
      arg1, deleted, poller_id
    FROM poller_item WHERE local_data_id = 1;

    SET current_id = current_id + 1;
  END WHILE;
END//
DELIMITER ;
CALL seed_stress_hosts($HOSTS);
DROP PROCEDURE seed_stress_hosts;"

harness_assert_eq "$HOSTS" "$(db_query 'SELECT COUNT(*) FROM host;')" \
	"stress fixture has the requested host count"

for thread_count in $THREADS; do
	if [[ ! "$thread_count" =~ ^[0-9]+$ ]] || \
		(( thread_count < 1 || thread_count > 256 )); then
		echo "invalid thread count: $thread_count" >&2
		exit 2
	fi

	for (( iteration=1; iteration<=REPEATS; iteration++ )); do
		case_id="threads-${thread_count}-iteration-${iteration}"
		log_file="$ARTIFACT_ROOT/$case_id.log"
		db_query "TRUNCATE poller_output; TRUNCATE host_errors;
			UPDATE host SET total_polls=0, failed_polls=0, status=3;"

		set +e
		run_with_timeout "${COMPOSE[@]}" run --rm --no-deps --entrypoint spine spine \
			--conf=/etc/spine/spine.conf -f 1 -l "$HOSTS" -S -t "$thread_count" \
			"${EXTRA_ARGS[@]}" \
			> "$log_file" 2>&1
		rc=$?
		set -e

		output=$(<"$log_file")
		harness_assert_eq 0 "$rc" "$case_id exits successfully"
		harness_assert_not_contains "$output" \
			'segmentation fault|SIGSEGV|Aborted|core dump|FATAL|Polling timed out while waiting' \
			"$case_id has no fatal, crash, or shutdown-timeout diagnostics"
		harness_assert_contains "$output" "Threads: ${thread_count}, Devices: ${HOSTS}" \
			"$case_id reports every device completed"
		harness_assert_eq "$HOSTS" \
			"$(db_query "SELECT COUNT(*) FROM poller_output WHERE rrd_name = 'uptime';")" \
			"$case_id writes exactly one SNMP result per host"
		harness_assert_eq "$((HOSTS + 1))" \
			"$(db_query 'SELECT COUNT(*) FROM poller_output;')" \
			"$case_id neither loses nor duplicates SNMP and script results"
		harness_assert_eq "$HOSTS" \
			"$(db_query 'SELECT COUNT(*) FROM host WHERE total_polls > 0;')" \
			"$case_id accounts for every host poll"
		harness_assert_eq 0 \
			"$(db_query 'SELECT COUNT(*) FROM host WHERE failed_polls > 0 OR status <> 3;')" \
			"$case_id leaves every host healthy"
		harness_assert_eq 0 "$(db_query 'SELECT COUNT(*) FROM host_errors;')" \
			"$case_id records no host-level errors"
	done
done

harness_finish
