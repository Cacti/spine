#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# A setuid root spine re-executes itself for a script that has CPU or memory
# limits. The child must drop root before it runs the command, hold no
# capabilities or sockets, and see the environment a setuid exec leaves it:
# glibc removes the dynamic linker variables and TMPDIR from it.
#
# This installs a copy of the built binary setuid root and runs it as nobody.
# Needs root, Linux and setpriv; it skips anywhere else, which includes an
# ordinary `make check`.
set -eu

top_builddir="${top_builddir:-.}"

skip() {
	echo "SKIP: $*"
	exit 77
}

[ "$(uname -s)" = "Linux" ] || skip "Linux only"
[ "$(id -u)" -eq 0 ] || skip "needs root to install a setuid copy"
command -v setpriv >/dev/null 2>&1 || skip "setpriv not installed"
[ -x "$top_builddir/spine" ] || { echo "FAIL: spine has not been built" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
chmod 755 "$work"
cp "$top_builddir/spine" "$work/spine"
chown root:root "$work/spine"
chmod 4755 "$work/spine"

child_script=$(cat <<'SCRIPT'
echo uid=$(id -u)
echo euid=$(awk '/^Uid:/ {print $3}' /proc/$$/status)
echo cap=$(awk '/^CapEff:/ {print $2}' /proc/$$/status)
echo sockets=$(ls -l /proc/$$/fd | grep -c socket)
echo stripped=$(env | grep -c '^LD_LIBRARY_PATH=\|^TMPDIR=')
echo kept=${SPINE_KEPT:-}
SCRIPT
)

out=$(LD_LIBRARY_PATH=/opt/spine-lib TMPDIR=/var/tmp SPINE_KEPT=yes \
	setpriv --reuid=65534 --regid=65534 --clear-groups \
	"$work/spine" --internal-script-child 5 0 "$child_script")

failed=0
expect() {
	if ! printf '%s\n' "$out" | grep -qx "$1"; then
		echo "FAIL: expected '$1' in:" >&2
		printf '%s\n' "$out" >&2
		failed=1
	fi
}

expect "uid=65534"
expect "euid=65534"
expect "cap=0000000000000000"
expect "sockets=0"
expect "stripped=0"
expect "kept=yes"

[ "$failed" -eq 0 ] || exit 1
echo "PASS: the script child runs unprivileged without sockets"
