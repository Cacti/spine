#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
root=$(cd "${srcdir:-.}" && pwd)
gate="$root/.github/scripts/verify-nightly-suites.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cd "$fixture"
mkdir -p tests/unit
printf '%s\n' tests/unit/test_resource_policy tests/unit/test_external_policy tests/unit/test_process_abort tests/unit/test_worker_set tests/unit/test_db_lease tests/unit/test_tls_policy test_spine_regressions test_spine_faults > inventory
while IFS= read -r program; do
  printf '#!/bin/sh\nexit 0\n' > "$program"
  chmod 755 "$program"
done < inventory
bash "$gate" inventory
if bash "$gate" missing 2>/dev/null; then echo 'Missing inventory passed' >&2; exit 1; fi
: > empty
if bash "$gate" empty 2>/dev/null; then echo 'Empty inventory passed' >&2; exit 1; fi
head -n 3 inventory > incomplete
if bash "$gate" incomplete 2>/dev/null; then echo 'Missing suite passed' >&2; exit 1; fi
cat inventory inventory > duplicate
if bash "$gate" duplicate 2>/dev/null; then echo 'Duplicate suite passed' >&2; exit 1; fi
for invalid in '' '../outside' 'other_suite'; do
  cp inventory invalid-inventory
  printf '%s\n' "$invalid" >> invalid-inventory
  if bash "$gate" invalid-inventory 2>/dev/null; then echo 'Invalid suite passed' >&2; exit 1; fi
done
printf '%s' "$(cat inventory)" > no-newline
bash "$gate" no-newline
chmod 644 tests/unit/test_external_policy
if bash "$gate" inventory 2>/dev/null; then echo 'Nonexecutable suite passed' >&2; exit 1; fi
echo 'Nightly suite-presence positive and negative contracts passed'
