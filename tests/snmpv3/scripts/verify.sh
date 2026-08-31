#!/bin/sh
# Asserts that the poll actually produced data, rather than that spine exited 0.
#
# Runs after the spine service completes, against the same database spine wrote
# to. Every check here is something a regression in poll_host() would break.
set -eu

Q="mariadb -h db -u spine -pspine cacti -N -B -e"

fail() { echo "FAIL: $1"; exit 1; }
ok()   { echo "ok: $1"; }

# 1. the poll wrote a result for the configured data source
rows=$($Q "SELECT COUNT(*) FROM poller_output WHERE local_data_id = 1;")
[ "$rows" -ge 1 ] || fail "poller_output has no row for local_data_id 1 (got $rows)"
ok "poller_output has $rows row(s) for local_data_id 1"

# 2. the value is a number, not an error string or 'U'
val=$($Q "SELECT output FROM poller_output WHERE local_data_id = 1 LIMIT 1;")
case "$val" in
	''|*[!0-9]*) fail "poller_output.output is not numeric: '$val'" ;;
esac
ok "sysUpTime came back numeric: $val"

# 3. sysUpTime is a timeticks counter, so it must be moving
[ "$val" -gt 0 ] || fail "sysUpTime is $val, expected a running counter"
ok "sysUpTime is non-zero"

# 4. the device was not marked down or put into an error state
status=$($Q "SELECT status FROM host WHERE id = 1;")
[ "$status" = "3" ] || fail "host status is $status, expected 3 (up)"
ok "host 1 recorded as up"

# 5. availability accounting ran
fails=$($Q "SELECT status_fail_date FROM host WHERE id = 1;")
errs=$($Q "SELECT COUNT(*) FROM host_errors WHERE host_id = 1;")
[ "$errs" = "0" ] || fail "host_errors has $errs row(s) for host 1"
ok "no host errors recorded"

# 6. the script-action data source ran and stored exactly what it printed
srows=$($Q "SELECT COUNT(*) FROM poller_output WHERE local_data_id = 2;")
[ "$srows" -ge 1 ] || fail "poller_output has no row for the script data source (got $srows)"
sval=$($Q "SELECT output FROM poller_output WHERE local_data_id = 2 LIMIT 1;")
[ "$sval" = "42" ] || fail "script data source stored '$sval', expected '42'"
ok "script action returned $sval"

# 7. the auto-reindex assertion matched, so no reindex was queued. A broken
#    compare shows up here as a spurious reindex on every poll.
cmds=$($Q "SELECT COUNT(*) FROM poller_command WHERE poller_id = 1;")
[ "$cmds" = "0" ] || fail "poller_command has $cmds row(s); the reindex assertion should have matched"
ok "auto-reindex assertion matched, nothing queued"

echo "integration checks passed"
