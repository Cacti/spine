#!/usr/bin/env bash
# Copyright (C) 2026 The Cacti Group
# Licensed under the GNU Lesser General Public License, version 2.1 or later.
set -euo pipefail
owned_dir="$(mktemp -d "${TMPDIR:-/tmp}/spine-coverage-verifier.XXXXXX")"
trap 'rm -rf "$owned_dir"' EXIT
verifier="$(dirname "$0")/verify_coverage.sh"
printf '%s\n' one.c two.c > "$owned_dir/sources.txt"
for source in one.c two.c; do
    printf 'SF:/source/%s\nLF:2\nLH:1\nBRF:2\nBRH:1\nFNF:1\nFNH:1\nend_of_record\n' "$source" >> "$owned_dir/complete.info"
done
"$verifier" "$owned_dir/complete.info" /source "$owned_dir/sources.txt"
reject() {
    local profile="$1"
    if "$verifier" "$profile" /source "$owned_dir/sources.txt" > /dev/null 2>&1; then
        printf 'Verifier incorrectly admitted %s\n' "$profile" >&2
        exit 1
    fi
}
reject "$owned_dir/absent.info"
sed '/SF:\/source\/one.c/,/end_of_record/d' "$owned_dir/complete.info" > "$owned_dir/omitted.info"
reject "$owned_dir/omitted.info"
sed -e 's/BRF:2/BRF:0/' -e 's/BRH:1/BRH:0/' "$owned_dir/complete.info" > "$owned_dir/no-branches.info"
reject "$owned_dir/no-branches.info"
sed -e 's/LH:1/LH:0/' -e 's/BRH:1/BRH:0/' "$owned_dir/complete.info" > "$owned_dir/unexecuted.info"
reject "$owned_dir/unexecuted.info"
{ printf 'SF:/source/one.c\n'; sed '/SF:\/source\/one.c/,/end_of_record/d' "$owned_dir/complete.info"; } > "$owned_dir/borrowed-metrics.info"
reject "$owned_dir/borrowed-metrics.info"
sed '$d' "$owned_dir/complete.info" > "$owned_dir/dangling.info"
reject "$owned_dir/dangling.info"
cat "$owned_dir/complete.info" "$owned_dir/complete.info" > "$owned_dir/duplicate.info"
reject "$owned_dir/duplicate.info"
sed '/^LH:/d' "$owned_dir/complete.info" > "$owned_dir/missing-metric.info"
reject "$owned_dir/missing-metric.info"
sed 's/LH:1/LH:3/' "$owned_dir/complete.info" > "$owned_dir/overcount.info"
reject "$owned_dir/overcount.info"
printf '%s\n' one two > "$owned_dir/producers.txt"
printf 'fixture\n' > "$owned_dir/one.gcno"
printf 'fixture\n' > "$owned_dir/two.gcno"
"$verifier" --producers "$owned_dir" "$owned_dir/producers.txt" gcno
if "$verifier" --producers "$owned_dir" "$owned_dir/producers.txt" gcda; then exit 1; fi
printf '%s\n' one missing > "$owned_dir/missing-producer.txt"
if "$verifier" --producers "$owned_dir" "$owned_dir/missing-producer.txt" gcno; then exit 1; fi
printf '%s\n' one one > "$owned_dir/duplicate-producer.txt"
if "$verifier" --producers "$owned_dir" "$owned_dir/duplicate-producer.txt" gcno; then exit 1; fi
printf '%s\n' zero > "$owned_dir/zero-producer.txt"
: > "$owned_dir/zero.gcno"
if "$verifier" --producers "$owned_dir" "$owned_dir/zero-producer.txt" gcno; then exit 1; fi
printf 'Coverage verifier rejects absent, omitted, branchless, unexecuted, malformed, dangling, duplicate and inconsistent reports\n'
