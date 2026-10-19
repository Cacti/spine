#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-only
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
# A setuid root spine must give up root before it reads any option or file.
#
# Spine used to keep euid 0 through option parsing, the config file and the
# database connection, so "-O path_cactilog:<path>" or a Cacti_Log line in a
# "-C" file made it create a root-owned file wherever the caller asked, and
# the saved uid stayed 0 for the whole run.
#
# This installs a copy of the built binary setuid root, starts it as nobody
# with a config FIFO so it blocks while reading the config, reads its ids from
# /proc, then lets it run and checks that nothing appeared in a directory only
# root can write. -O path_cactilog takes effect once the settings are read, so
# that half needs SPINE_TEST_DB_HOST: a database named SPINE_TEST_DB_NAME
# (default spine_regressions) loaded with tests/fixtures, which the default
# cactiuser/cactiuser account can read. Without it spine stops at the
# connection, which still covers the ids and the config file's Cacti_Log.
#
# Needs root, Linux and setpriv; it skips anywhere else, which includes an
# ordinary `make check`.
set -eu

top_builddir="${top_builddir:-.}"

skip() {
	echo "SKIP: $*"
	exit 77
}

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

failed=0
check_failed() {
	echo "FAIL: $*" >&2
	failed=1
}

[ "$(uname -s)" = "Linux" ] || skip "Linux only"
[ "$(id -u)" -eq 0 ] || skip "needs root to install a setuid copy"
command -v setpriv >/dev/null 2>&1 || skip "setpriv not installed"
[ -x "$top_builddir/spine" ] || fail "spine has not been built"

work=$(mktemp -d)
pid=""
cleanup() {
	if [ -n "$pid" ]; then
		kill "$pid" 2>/dev/null || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

chmod 755 "$work"
cp "$top_builddir/spine" "$work/spine"
chown root:root "$work/spine"
chmod 4755 "$work/spine"
mkdir "$work/rootonly"
chmod 700 "$work/rootonly"
mkfifo "$work/spine.conf"
chmod 666 "$work/spine.conf"

setpriv --reuid=65534 --regid=65534 --clear-groups \
	"$work/spine" -R -C "$work/spine.conf" -O "path_cactilog:$work/rootonly/option.log" \
	>"$work/out" 2>&1 &
pid=$!

# Opening the FIFO blocks until a writer appears, so a sleeping process is
# past startup and inside read_spine_config().
state=""
tries=0
while [ "$tries" -lt 50 ]; do
	state=$(awk '/^State:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)
	[ "$state" = "S" ] && break
	tries=$((tries + 1))
	sleep 0.1
done
[ "$state" = "S" ] || fail "spine did not block on its config FIFO"
sleep 0.2

uids=$(awk '/^Uid:/ {print $2, $3, $4, $5}' "/proc/$pid/status")
gids=$(awk '/^Gid:/ {print $2, $3, $4, $5}' "/proc/$pid/status")
echo "while reading the config: Uid $uids, Gid $gids"
[ "$uids" = "65534 65534 65534 65534" ] || check_failed "real, effective, saved or fs uid is not the caller's: $uids"
[ "$gids" = "65534 65534 65534 65534" ] || check_failed "real, effective, saved or fs gid is not the caller's: $gids"

if [ -n "${SPINE_TEST_DB_HOST:-}" ]; then
	printf 'DB_Host %s\nDB_Database %s\nCacti_Log %s\n' "$SPINE_TEST_DB_HOST" \
		"${SPINE_TEST_DB_NAME:-spine_regressions}" "$work/rootonly/config.log" >"$work/spine.conf"
else
	printf 'DB_Host 127.0.0.1\nDB_Port 1\nCacti_Log %s\n' "$work/rootonly/config.log" >"$work/spine.conf"
fi
wait "$pid" || true
pid=""
cat "$work/out"
if [ -n "$(ls -A "$work/rootonly")" ]; then
	ls -l "$work/rootonly" >&2
	check_failed "a setuid spine created a file in a root-only directory"
fi

[ "$failed" -eq 0 ] || exit 1
echo "PASS: setuid spine drops root before reading options and config"
