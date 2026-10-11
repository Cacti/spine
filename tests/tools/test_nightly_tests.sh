#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
gate=$(cd "$(dirname "$0")" && pwd)/check_nightly_tests.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cd "$fixture"
mkdir -p tests/unit
for program in tests/unit/test_example test_spine_regressions test_spine_faults; do
    printf '#!/bin/sh\nexit 0\n' > "$program"
    chmod +x "$program"
done
printf 'tests/unit/test_example\n' > manifest
"$gate" manifest
must_reject() {
    if "$gate" "$@" >diagnostic 2>&1; then
        echo 'Nightly accepted a missing or invalid suite.' >&2
        exit 1
    fi
    test -s diagnostic
}
must_reject
must_reject nonexistent
: > manifest
must_reject manifest
printf '\n' > manifest
must_reject manifest
printf 'tests/unit/test_missing\n' > manifest
must_reject manifest
printf 'tests/unit/test_example\ntests/unit/test_example\n' > manifest
must_reject manifest
printf '../test_example\n' > manifest
must_reject manifest
printf 'tests/unit/test_example;echo\n' > manifest
must_reject manifest
printf 'other/test_example\n' > manifest
must_reject manifest
printf 'tests/unit/test_example\n' > manifest
chmod -x tests/unit/test_example
must_reject manifest
chmod +x tests/unit/test_example
chmod -x test_spine_regressions
must_reject manifest
chmod +x test_spine_regressions
chmod -x test_spine_faults
must_reject manifest
chmod +x test_spine_faults
printf 'tests/unit/test_example' > manifest
"$gate" manifest
echo 'Nightly test-presence contracts passed.'
