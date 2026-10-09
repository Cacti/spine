#!/usr/bin/env bash
# Run complete Spine polling cycles back to back for a fixed time, record the
# peak RSS of every cycle, and fail when a least-squares fit of RSS against
# elapsed time projects more growth over the run than the threshold allows.
#
# Each cycle is a fresh process, as it is under Cacti's poller, so this finds
# memory that grows with accumulated state: database rows, host status,
# result sizes. In-process leaks within one cycle are Valgrind's job in
# nightly.yml. A slope is used, not first against last, so one noisy cycle
# at either end cannot pass or fail the run by itself.
#
# It needs what regressions.yml provides: a built ./spine, the fixture
# schema loaded into spine_regressions on a MariaDB server reachable as root
# without a password, and the fixture snmpd agent on port 1161.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DB_HOST=${SPINE_TEST_DB_HOST:?SPINE_TEST_DB_HOST must name the fixture database host}
SNMP_HOST=${SPINE_TEST_SNMP_HOST:-127.0.0.1}
SPINE=${SPINE_BINARY:-"$REPO_ROOT/spine"}
DURATION=${SPINE_SOAK_SECONDS:-3600}
HOSTS=${SPINE_SOAK_HOSTS:-50}
THREADS=${SPINE_SOAK_THREADS:-8}
WARMUP=${SPINE_SOAK_WARMUP_CYCLES:-3}
MIN_CYCLES=${SPINE_SOAK_MIN_CYCLES:-20}
MAX_GROWTH_KB=${SPINE_SOAK_MAX_GROWTH_KB:-1024}
CYCLE_TIMEOUT=${SPINE_SOAK_CYCLE_TIMEOUT:-120}
ARTIFACT_ROOT=${SPINE_TEST_ARTIFACT_DIR:-"$REPO_ROOT/test-artifacts/memory-soak"}

for numeric_value in "$DURATION" "$HOSTS" "$THREADS" "$WARMUP" "$MIN_CYCLES" \
	"$MAX_GROWTH_KB" "$CYCLE_TIMEOUT"; do
	[[ "$numeric_value" =~ ^[0-9]+$ ]] || {
		echo "soak durations, counts and thresholds must be non-negative integers" >&2
		exit 2
	}
done
(( DURATION >= 60 )) || { echo "SPINE_SOAK_SECONDS must be at least 60" >&2; exit 2; }
(( HOSTS >= 1 && HOSTS <= 500 )) || { echo "SPINE_SOAK_HOSTS must be between 1 and 500" >&2; exit 2; }
(( THREADS >= 1 && THREADS <= 100 )) || { echo "SPINE_SOAK_THREADS must be between 1 and 100" >&2; exit 2; }
(( MIN_CYCLES >= 3 )) || { echo "SPINE_SOAK_MIN_CYCLES must be at least 3" >&2; exit 2; }
[[ -x "$SPINE" ]] || { echo "Spine binary not found: $SPINE" >&2; exit 2; }
[[ -x /usr/bin/time ]] || { echo "GNU time is required at /usr/bin/time" >&2; exit 2; }

mkdir -p "$ARTIFACT_ROOT"
export SPINE_TEST_ARTIFACT_DIR=$ARTIFACT_ROOT
# shellcheck source=tests/test-harness.sh
source "$REPO_ROOT/tests/test-harness.sh"
harness_init "Spine memory soak"

SERIES="$ARTIFACT_ROOT/rss-series.csv"
SUMMARY="$ARTIFACT_ROOT/summary.txt"
CONFIG="$ARTIFACT_ROOT/spine.conf"

db_query() {
	mariadb --protocol=TCP --host="$DB_HOST" --user=root spine_regressions -N -B -e "$1"
}

# Spine falls back to a default password when DB_Pass is empty, so it gets
# its own fixture account. Public credentials, valid on the throwaway
# server only.
db_query "CREATE USER IF NOT EXISTS 'spine_soak'@'%' IDENTIFIED BY 'soak-only';
GRANT SELECT, INSERT, UPDATE, DELETE ON spine_regressions.* TO 'spine_soak'@'%';"
printf 'DB_Host %s\nDB_Database spine_regressions\nDB_User spine_soak\nDB_Pass soak-only\nDB_Port 3306\n' \
	"$DB_HOST" > "$CONFIG"

# Every host polls the fixture agent for three SNMP values and runs one
# script, so each cycle exercises SNMP sessions, the script path and result
# batching. Host rows are separate, so per-host state is not shared.
db_query "
DELETE FROM host; DELETE FROM poller_item; DELETE FROM poller_output;
DELETE FROM host_errors; DELETE FROM poller_time;
REPLACE INTO poller (id, threads) VALUES (1, $THREADS);
DELETE FROM settings;
INSERT INTO settings (name, value) VALUES ('script_timeout', '5'), ('poller_interval', '300');"
for (( host_id = 1; host_id <= HOSTS; host_id++ )); do
	base=$(( host_id * 10 ))
	printf "INSERT INTO host (id, hostname, poller_id, snmp_community, snmp_version, snmp_port, snmp_timeout, availability_method, status_fail_date, status_rec_date) VALUES (%d, '%s', 1, 'regression', 2, 1161, 500, 2, '2026-01-01 00:00:00', '2026-01-01 00:00:00');\n" \
		"$host_id" "$SNMP_HOST"
	printf "INSERT INTO poller_item (local_data_id, host_id, poller_id, action, hostname, snmp_community, snmp_version, snmp_port, snmp_timeout, rrd_name, arg1) VALUES (%d, %d, 1, 0, '%s', 'regression', 2, 1161, 500, 'uptime', '.1.3.6.1.2.1.1.3.0'), (%d, %d, 1, 0, '%s', 'regression', 2, 1161, 500, 'name', '.1.3.6.1.2.1.1.5.0'), (%d, %d, 1, 0, '%s', 'regression', 2, 1161, 500, 'location', '.1.3.6.1.2.1.1.6.0'), (%d, %d, 1, 1, '', '', 0, 161, 500, 'script', '/bin/echo 42');\n" \
		"$((base + 1))" "$host_id" "$SNMP_HOST" "$((base + 2))" "$host_id" "$SNMP_HOST" \
		"$((base + 3))" "$host_id" "$SNMP_HOST" "$((base + 4))" "$host_id"
done | mariadb --protocol=TCP --host="$DB_HOST" --user=root spine_regressions

expected_rows=$(( HOSTS * 4 ))
harness_assert_eq "$expected_rows" "$(db_query 'SELECT COUNT(*) FROM poller_item;')" \
	"soak fixture has four poller items per host"

printf 'cycle,elapsed_s,max_rss_kb,wall_s,exit,rows\n' > "$SERIES"
start=$SECONDS
cycle=0
failed_cycles=0
while (( SECONDS - start < DURATION )); do
	cycle=$((cycle + 1))
	# Cacti's poller.php consumes these tables after every cycle; without
	# that, row growth would show up as Spine's memory growth.
	db_query "DELETE FROM poller_output; DELETE FROM poller_time;"
	elapsed=$((SECONDS - start))
	: > "$ARTIFACT_ROOT/time.out"
	set +e
	timeout --signal=TERM --kill-after=10 "$CYCLE_TIMEOUT" \
		/usr/bin/time -f '%M %e' -o "$ARTIFACT_ROOT/time.out" \
		"$SPINE" --conf="$CONFIG" -p 1 -t "$THREADS" -S -V 1 \
		> "$ARTIFACT_ROOT/last-cycle.log" 2>&1
	rc=$?
	set -e
	# GNU time puts any exit or signal note before the formatted line.
	rss=0
	wall=0
	read -r rss wall < <(tail -n 1 "$ARTIFACT_ROOT/time.out") || true
	rows=$(db_query "SELECT COUNT(*) FROM poller_output;")
	printf '%d,%d,%s,%s,%d,%s\n' "$cycle" "$elapsed" "$rss" "$wall" "$rc" "$rows" >> "$SERIES"
	# A failed cycle allocates less, which would hide growth; stop at the
	# first one rather than fit a series that mixes the two.
	if (( rc != 0 )) || [[ "$rows" != "$expected_rows" ]]; then
		failed_cycles=$((failed_cycles + 1))
		cp "$ARTIFACT_ROOT/last-cycle.log" "$ARTIFACT_ROOT/failed-cycle-$cycle.log"
		break
	fi
done

harness_assert_eq 0 "$failed_cycles" \
	"every cycle exits 0 and writes all $expected_rows results"

# Least squares of peak RSS on elapsed seconds, warm-up cycles excluded.
# Projected growth is the slope times the span of the fitted cycles.
read -r fitted slope_kb_per_hour projected first_kb last_kb min_kb max_kb mean_kb < <(
	awk -F, -v warmup="$WARMUP" '
		NR == 1 || $1 <= warmup { next }
		{
			n++; x = $2; y = $3
			sx += x; sy += y; sxx += x * x; sxy += x * y
			if (n == 1) { first = y; x0 = x; min = y; max = y }
			last = y; x1 = x
			if (y < min) min = y
			if (y > max) max = y
		}
		END {
			if (n < 2) { print n, 0, 0, 0, 0, 0, 0, 0; exit }
			d = n * sxx - sx * sx
			slope = d == 0 ? 0 : (n * sxy - sx * sy) / d
			printf "%d %.1f %.0f %d %d %d %d %.0f\n", n, slope * 3600,
				slope * (x1 - x0), first, last, min, max, sy / n
		}' "$SERIES")

{
	printf 'cycles run: %d (warm-up excluded: %d, fitted: %d)\n' "$cycle" "$WARMUP" "$fitted"
	printf 'hosts: %d, threads: %d, duration: %ds\n' "$HOSTS" "$THREADS" "$DURATION"
	printf 'peak RSS KB: first %d, last %d, min %d, max %d, mean %d\n' \
		"$first_kb" "$last_kb" "$min_kb" "$max_kb" "$mean_kb"
	printf 'slope: %s KB/hour; projected growth over the run: %s KB (limit %d KB)\n' \
		"$slope_kb_per_hour" "$projected" "$MAX_GROWTH_KB"
} | tee "$SUMMARY"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	{
		printf '### Spine memory soak\n\n```text\n'
		cat "$SUMMARY"
		printf '```\n\n'
	} >> "$GITHUB_STEP_SUMMARY"
fi

if (( fitted >= MIN_CYCLES )); then
	harness_pass "at least $MIN_CYCLES cycles were fitted (got $fitted)"
else
	harness_fail "at least $MIN_CYCLES cycles were fitted (got $fitted)"
fi
if (( projected <= MAX_GROWTH_KB )); then
	harness_pass "projected RSS growth ${projected} KB is within ${MAX_GROWTH_KB} KB"
else
	harness_fail "projected RSS growth ${projected} KB exceeds ${MAX_GROWTH_KB} KB"
fi

harness_finish
