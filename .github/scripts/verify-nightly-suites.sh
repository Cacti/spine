#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
[[ $# == 1 && -s $1 ]] || { echo 'Missing nightly suite inventory' >&2; exit 1; }
for required in tests/unit/test_resource_policy tests/unit/test_external_policy test_spine_regressions test_spine_faults; do
  grep -Fxq "$required" "$1" || { echo "Missing expected suite: $required" >&2; exit 1; }
done
while IFS= read -r program; do
  [[ -x "$program" ]] || { echo "Missing executable suite: $program" >&2; exit 1; }
done < "$1"
