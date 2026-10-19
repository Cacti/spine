#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
source_root=$(cd -- "$(dirname -- "$0")/../.." && pwd -P)
configure_work=$(mktemp -d)
trap 'rm -rf -- "$configure_work"' EXIT
mkdir "$configure_work/source"
(cd "$source_root" && tar --exclude='.git' --exclude='config.status' --exclude='config.cache' --exclude='*.o' --exclude='*.gcda' --exclude='*.gcno' --exclude='coverage' -cf - .) |
    (cd "$configure_work/source" && tar -xf -)
source_root=$configure_work/source
configure_case() {
    local name=$1
    shift
    local environment=() arguments=()
    while (($#)); do
        if [[ $1 == --* ]]; then arguments+=("$1"); else environment+=("$1"); fi
        shift
    done
    mkdir "$configure_work/$name"
    (cd "$configure_work/$name" && env "${environment[@]}" "$source_root/configure" "${arguments[@]}" > configure.log 2>&1)
}
configure_case default CC=gcc
grep -Eq '^CFLAGS =.*-std=gnu17' "$configure_work/default/Makefile"
configure_case caller_flags CC=gcc CFLAGS=-std=gnu11
grep -Eq '^CFLAGS =.*-std=gnu11' "$configure_work/caller_flags/Makefile"
if grep -Eq '^CFLAGS =.*-std=gnu17' "$configure_work/caller_flags/Makefile"; then exit 1; fi
grep -q 'older than C17' "$configure_work/caller_flags/configure.log"
configure_case caller_compiler 'CC=gcc -std=gnu11'
grep -Eq '^CC = gcc -std=gnu11$' "$configure_work/caller_compiler/Makefile"
configure_case disable_hardening CC=gcc --disable-hardening
if grep -Eq '^CFLAGS =.*-fstack-protector' "$configure_work/disable_hardening/Makefile"; then exit 1; fi
configure_case preset_fortify CC=gcc CPPFLAGS=-D_FORTIFY_SOURCE=1
grep -Eq '^CPPFLAGS =.*-D_FORTIFY_SOURCE=1' "$configure_work/preset_fortify/Makefile"
if grep -Eq '^CPPFLAGS =.*-D_FORTIFY_SOURCE=[23]' "$configure_work/preset_fortify/Makefile"; then exit 1; fi
if configure_case invalid_client CC=gcc --with-mysql-client=invalid; then
    echo 'Invalid database client unexpectedly accepted' >&2; exit 1
fi
grep -q 'mysql-client' "$configure_work/invalid_client/configure.log"
cat > "$configure_work/reject-c17" <<'EOF'
#!/bin/sh
for argument do
    case "$argument" in -std=gnu17) exit 1;; esac
done
exec gcc "$@"
EOF
chmod +x "$configure_work/reject-c17"
if configure_case unsupported "CC=$configure_work/reject-c17"; then
    echo 'Unsupported GNU C17 compiler unexpectedly accepted' >&2; exit 1
fi
grep -q 'does not accept -std=gnu17' "$configure_work/unsupported/configure.log"
cat > "$configure_work/narrow-time" <<'EOF'
#!/bin/sh
for argument do
    case "$argument" in
        *.c) if grep -q 'time_t_is_64_bit' "$argument"; then exit 1; fi;;
    esac
done
exec gcc "$@"
EOF
chmod +x "$configure_work/narrow-time"
if configure_case narrow_time "CC=$configure_work/narrow-time"; then
    echo 'Narrow time_t unexpectedly accepted' >&2; exit 1
fi
grep -q 'time_t is narrower than 64 bits' "$configure_work/narrow_time/configure.log"
configure_case compatibility_time "CC=$configure_work/narrow-time" --disable-y2038-check
grep -q 'timestamps will overflow' "$configure_work/compatibility_time/configure.log"
printf '%s\n' 'C17 selection, caller overrides, hardening, fortify, connector and time_t validation passed'
