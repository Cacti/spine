#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
root=$(cd "${srcdir:-.}" && pwd)
fit="$root/tests/tools/memory_soak_fit.awk"
result=$(printf '%s\n' 'cycle,elapsed_s,max_rss_kb,wall_s,exit,rows' \
  '1,0,9000,1,0,200' '2,1,100,1,0,200' '3,2,110,1,0,200' \
  '4,3,120,1,0,200' '5,4,0,1,1,200' '6,5,0,1,0,199' | \
  awk -F, -v warmup=1 -v expected_rows=200 -f "$fit")
[[ "$result" == '3 36000.0 20 100 120 100 120 110' ]] || {
  printf 'Failed/incomplete cycles distorted the fit: %s\n' "$result" >&2; exit 1;
}
result=$(printf '%s\n' 'cycle,elapsed_s,max_rss_kb,wall_s,exit,rows' \
  '1,0,9000,1,0,200' '2,1,0,1,1,200' '3,2,0,1,0,199' | \
  awk -F, -v warmup=1 -v expected_rows=200 -f "$fit")
[[ "$result" == '0 0 0 0 0 0 0 0' ]]
echo 'Memory soak excludes warm-up, failed and incomplete cycles'
