#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
[[ $# == 1 && -s $1 ]] || { echo 'Missing nightly suite inventory' >&2; exit 1; }
if [[ -n $(sort "$1" | uniq -d) ]]; then
  echo 'Duplicate nightly suite identity' >&2
  exit 1
fi
for required in tests/unit/test_resource_policy tests/unit/test_external_policy tests/unit/test_worker_set tests/unit/test_db_lease tests/unit/test_tls_policy test_spine_regressions test_spine_faults; do
  grep -Fxq "$required" "$1" || { echo "Missing expected suite: $required" >&2; exit 1; }
done
while IFS= read -r program || [[ -n "$program" ]]; do
  case "$program" in
    ''|*[!a-zA-Z0-9_/]*|*..*) echo 'Invalid nightly suite identity' >&2; exit 1 ;;
    tests/unit/test_*|test_spine_regressions|test_spine_faults) ;;
    *) echo 'Unexpected nightly suite identity' >&2; exit 1 ;;
  esac
  [[ -f "$program" && -x "$program" ]] || { echo "Missing executable suite: $program" >&2; exit 1; }
done < "$1"
