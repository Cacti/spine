#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

if [ "$#" -ne 1 ] || [ ! -s "$1" ]; then
    echo 'Nightly requires a nonempty unit-test manifest.' >&2
    exit 1
fi
if [ -n "$(sort "$1" | uniq -d)" ]; then
    echo 'Nightly unit-test manifest contains duplicate suites.' >&2
    exit 1
fi
while IFS= read -r program || [ -n "$program" ]; do
    case "$program" in
        ''|*[!a-zA-Z0-9_/]*|*..*) echo 'Invalid nightly test identity.' >&2; exit 1 ;;
        tests/unit/test_*) ;;
        *) echo 'Unexpected nightly test identity.' >&2; exit 1 ;;
    esac
    if [ ! -x "$program" ] || [ ! -f "$program" ]; then
        echo "Missing nightly test executable: $program" >&2
        exit 1
    fi
done < "$1"
for program in test_spine_regressions test_spine_faults; do
    if [ ! -x "$program" ] || [ ! -f "$program" ]; then
        echo "Missing nightly regression executable: $program" >&2
        exit 1
    fi
done
