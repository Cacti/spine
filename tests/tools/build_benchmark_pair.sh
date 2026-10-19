#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
[[ $# -eq 3 ]] || { printf 'Usage: %s BASE_REF CANDIDATE_REF OUTPUT_DIRECTORY\n' "$0" >&2; exit 2; }
baseline=$(git rev-parse --verify --end-of-options "$1^{commit}")
candidate=$(git rev-parse --verify --end-of-options "$2^{commit}")
mkdir "$3"
destination=$(cd "$3" && pwd -P)
gcc --version > "$destination/compiler.txt"
dpkg-query -W gcc libc6-dev libmariadb-dev libsnmp-dev libssl-dev snmpd autoconf automake libtool > "$destination/dependencies.txt"
printf 'CC=gcc\nCFLAGS=-O2 -g0\nLDFLAGS=\nconfigure=--with-mysql-client=mariadb\n' > "$destination/build-settings.txt"
for name in baseline candidate; do
    revision=$baseline
    [[ "$name" != candidate ]] || revision=$candidate
    printf '%s\n' "$revision" > "$destination/$name-revision.txt"
    mkdir "$destination/$name"
    git archive "$revision" | tar -x -C "$destination/$name"
    (
        cd "$destination/$name"
        mkdir -p config m4
        autoreconf -fi
        ./configure --with-mysql-client=mariadb CC=gcc CFLAGS='-O2 -g0' LDFLAGS=''
        make -j2 spine
    ) > "$destination/$name-build.log" 2>&1
    sha256sum "$destination/$name/spine" > "$destination/$name-binary.sha256"
done
