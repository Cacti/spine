#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
# Test helper entry points with fake make/gdb, never a running poller.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/spine-helper-contract.XXXXXX")
package_version="helper-contract-$(basename "$work")"
package_stage="/tmp/cacti-spine-${package_version}"
package_archive="${package_stage}.tar.gz"
trap 'rm -rf -- "$work" "$package_stage"; rm -f -- "$package_archive"' EXIT HUP INT TERM
cd "$root"
bash scripts/package.sh --help > "$work/help"
grep -q 'Spine Package Script' "$work/help"
if bash scripts/package.sh '../unsafe' > "$work/invalid" 2>&1; then
    echo 'package helper accepted an invalid version' >&2
    exit 1
fi
grep -q 'Invalid version component' "$work/invalid"
if bash scripts/package.sh > "$work/missing" 2>&1; then
    echo 'package helper accepted a missing version' >&2
    exit 1
fi
# Exercise the packaging archive with a local bootstrap stub.
mkdir -p "$work/source/scripts" "$work/source/nested/.svn"
printf obsolete > "$work/source/nested/.svn/entries"
printf obsolete > "$work/source/nested/.travis.yml"
cp scripts/package.sh "$work/source/scripts/package.sh"
printf 'AC_INIT(Spine, %s, example.invalid)\n' "$package_version" > "$work/source/configure.ac"
printf '#!/bin/sh\nexit 0\n' > "$work/source/bootstrap"
chmod +x "$work/source/bootstrap"
(cd "$work/source" && bash scripts/package.sh "$package_version") > "$work/package"
tar -tzf "$package_archive" > "$work/contents"
grep -Fxq "cacti-spine-${package_version}/scripts/package.sh" "$work/contents"
if grep -Eq '/(\.svn|\.travis\.yml)(/|$)' "$work/contents"; then
    echo 'package helper included obsolete checkout metadata' >&2
    exit 1
fi

mkdir "$work/bin"
cat > "$work/bin/make" <<'SH'
#!/bin/sh
exit "${FAKE_MAKE_STATUS:-0}"
SH
cat > "$work/bin/gdb" <<'SH'
#!/bin/sh
printf '%s\n' "$@" > "$SPINE_HELPER_ARGUMENTS"
SH
chmod +x "$work/bin/make" "$work/bin/gdb"
PATH="$work/bin:$PATH" SPINE_CONFIG="$work/a config.conf" \
    SPINE_HELPER_ARGUMENTS="$work/args" bash scripts/debug.sh > "$work/debug"
test "$(tail -n 1 "$work/args")" = "$work/a config.conf"
if PATH="$work/bin:$PATH" FAKE_MAKE_STATUS=1 \
    SPINE_HELPER_ARGUMENTS="$work/unexpected" bash scripts/debug.sh > "$work/failed"; then
    echo 'debug helper ignored a failed build' >&2
    exit 1
fi
test ! -e "$work/unexpected"
printf '%s\n' 'helper script contracts passed'
