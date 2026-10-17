#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
set -euo pipefail
if [[ "${1:-}" = '--producers' ]]; then
    : "${2:?Usage: verify_coverage.sh --producers BUILD_DIRECTORY MANIFEST gcno|gcda}"
    : "${3:?Usage: verify_coverage.sh --producers BUILD_DIRECTORY MANIFEST gcno|gcda}"
    : "${4:?Usage: verify_coverage.sh --producers BUILD_DIRECTORY MANIFEST gcno|gcda}"
    case "$4" in gcno|gcda) ;; *) exit 1;; esac
    [[ -s "$3" ]]
    [[ -z "$(sort "$3" | uniq -d)" ]]
    while IFS= read -r producer; do
        case "$producer" in ''|/*|*..*|*[!a-zA-Z0-9_/-]*) exit 1;; *) ;; esac
        [[ -s "$2/$producer.$4" ]]
    done < "$3"
    exit 0
fi
: "${1:?Usage: verify_coverage.sh PROFILE SOURCE_DIRECTORY PRODUCTION_MANIFEST}"
: "${2:?Usage: verify_coverage.sh PROFILE SOURCE_DIRECTORY PRODUCTION_MANIFEST}"
: "${3:?Usage: verify_coverage.sh PROFILE SOURCE_DIRECTORY PRODUCTION_MANIFEST}"
[[ -s "$1" ]]
[[ -s "$3" ]]
awk -F: -v source_dir="$2" '
  function fail(message) { print message > "/dev/stderr"; failed=1; exit 1 }
  FNR==NR {
    if ($0=="" || $0 !~ /\.c$/) fail("Invalid production source manifest")
    identity="SF:" source_dir "/" $0
    if (identity in expected) fail("Duplicate production source in manifest")
    expected[identity]=1
    next
  }
  /^SF:/ {
    if (open_record) fail("Previous coverage record was not terminated")
    identity=$0
    if (!(identity in expected)) fail("Unexpected coverage source: " identity)
    if (identity in produced) fail("Duplicate coverage source: " identity)
    open_record=1
    delete fields
    next
  }
  /^(LF|LH|BRF|BRH|FNF|FNH):/ {
    if (!open_record) fail("Coverage metrics outside a source record")
    if (NF!=2 || $2 !~ /^[0-9]+$/ || ($1 in fields)) fail("Invalid or duplicate coverage metric")
    fields[$1]=$2+0
    next
  }
  /^end_of_record$/ {
    if (!open_record) fail("Coverage terminator without a source record")
    if (!("LF" in fields) || !("LH" in fields) || !("BRF" in fields) || !("BRH" in fields) || !("FNF" in fields) || !("FNH" in fields)) fail("Incomplete coverage metrics")
    if (fields["LF"]<=0 || fields["FNF"]<=0 || fields["LH"]>fields["LF"] || fields["BRH"]>fields["BRF"] || fields["FNH"]>fields["FNF"]) fail("Inconsistent coverage metrics")
    total_lines_hit+=fields["LH"]
    total_branches_hit+=fields["BRH"]
    produced[identity]=1
    open_record=0
    next
  }
  END {
    if (failed) exit 1
    if (open_record) fail("Unterminated final coverage record")
    for (identity in expected) if (!(identity in produced)) fail("Absent production coverage: " identity)
    if (total_lines_hit<=0 || total_branches_hit<=0) fail("No measured line/branch execution")
  }
' "$3" "$1"
