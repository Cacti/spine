#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
# Run only against isolated regression services; database tests mutate fixtures.
set -euo pipefail
: "${SPINE_TEST_DB_HOST:?Set the isolated regression database host}"
: "${SPINE_TEST_SNMP_HOST:?Set the isolated regression SNMP host}"
coverage_base="${SPINE_COVERAGE_DIRECTORY:-coverage}"
mkdir -p "$coverage_base"
coverage_base="$(cd "$coverage_base" && pwd -P)"
source_dir="$(pwd -P)"
coverage_dir="$(mktemp -d "$coverage_base/run.XXXXXX")"
printf '%s\n' incomplete > "$coverage_dir/status.txt"
printf '%s\n' "$coverage_dir" > "$coverage_base/latest-run.txt"
coverage_complete=0
capability_added=0
finish() {
    status=$?
    if [[ "$capability_added" -eq 1 ]]; then
        if [[ "$(id -u)" -eq 0 ]]; then setcap -r ./test_spine_regressions; else sudo setcap -r ./test_spine_regressions; fi
    fi
    if [[ "$coverage_complete" -eq 1 ]] && [[ "$status" -eq 0 ]]; then
        printf '%s\n' success > "$coverage_dir/status.txt"
    else
        printf '%s\n' incomplete > "$coverage_dir/status.txt"
    fi
}
trap finish EXIT
for tool in gcc gcov lcov sha256sum tar python3; do command -v "$tool" >/dev/null; done
# Exclude only the owned evidence directory, never an untested production unit.
coverage_find_path='/not-in-source-tree'
[[ "$coverage_base" != "$source_dir" ]]
case "$coverage_base" in
    "$source_dir"/*) coverage_find_path="./${coverage_base#"$source_dir"/}";;
    *) ;;
esac
find . -path "$coverage_find_path" -prune -o -type f \( -name '*.c' -o -name '*.h' -o -name 'Makefile.am' -o -name 'configure.ac' -o -path './scripts/copyright_year.sh' -o -path './tests/fixtures/*' -o -path './tests/tools/*' -o -path './.github/workflows/*.yml' \) -not -path './.git/*' -not -path './config/config.h' -print0 | sort -z > "$coverage_dir/source-inputs.nul"
xargs -0 sha256sum < "$coverage_dir/source-inputs.nul" > "$coverage_dir/source.sha256"
tar -czf "$coverage_dir/source-inputs.tar.gz" --null -T "$coverage_dir/source-inputs.nul"
# Autoreconf replaces this tracked template. Preserve its original bytes and
# hash the generated template actually used by configure separately below.
cp Makefile.in "$coverage_dir/source-Makefile.in"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git rev-parse HEAD > "$coverage_dir/revision.txt"
    git status --porcelain > "$coverage_dir/worktree-status.txt"
else
    : "${SPINE_SOURCE_REVISION:?Set the exact source revision for a copied build tree}"
    printf '%s\n' "$SPINE_SOURCE_REVISION" > "$coverage_dir/revision.txt"
    printf '%s\n' 'Copied build tree: source.sha256 is authoritative; repository status unavailable.' > "$coverage_dir/worktree-status.txt"
fi
gcc --version > "$coverage_dir/compiler.txt"
gcc -dumpmachine >> "$coverage_dir/compiler.txt"
if command -v dpkg-query >/dev/null; then
    dpkg-query -W gcc libc6-dev libmariadb-dev libsnmp-dev libssl-dev snmpd lcov autoconf automake libtool > "$coverage_dir/dependencies.txt"
else
    printf '%s\n' 'Package version inventory unavailable: dpkg-query is not installed.' > "$coverage_dir/dependencies.txt"
fi
gcov --version > "$coverage_dir/gcov.txt"
lcov --version > "$coverage_dir/lcov.txt"
mkdir -p config m4
autoreconf -fi > "$coverage_dir/build.log" 2>&1
./configure CC=gcc CFLAGS="-std=gnu17 -g -O0 -UNDEBUG --coverage -fprofile-update=atomic -include $source_dir/tests/tools/coverage_process_exit.h" LDFLAGS='--coverage' >> "$coverage_dir/build.log" 2>&1
make --no-print-directory coverage-source-list > "$coverage_dir/production-sources.txt"
make --no-print-directory coverage-test-source-list > "$coverage_dir/test-sources.txt"
make --no-print-directory coverage-fault-source-list > "$coverage_dir/fault-sources.txt"
mapfile -t production_sources < "$coverage_dir/production-sources.txt"
mapfile -t test_sources < "$coverage_dir/test-sources.txt"
mapfile -t fault_sources < "$coverage_dir/fault-sources.txt"
[[ "${#production_sources[@]}" -gt 0 ]]
[[ "${#test_sources[@]}" -gt "${#production_sources[@]}" ]]
[[ "${#fault_sources[@]}" -gt 0 ]]
# All runtime sources must be in both linked test builds. main.c is exercised
# by the standalone --help/--version smoke runs, not by linking another main.
for source in "${production_sources[@]}"; do
    case "$source" in *.c) ;; *) printf 'Unsupported production source: %s\n' "$source" >&2; exit 1;; esac
    [[ -s "$source" ]]
    if [[ "$source" != src/app/main.c ]]; then
        grep -Fxq "$source" "$coverage_dir/test-sources.txt"
        grep -Fxq "$source" "$coverage_dir/fault-sources.txt"
    fi
done
for source in "${test_sources[@]}"; do
    case "$source" in *.c) ;; *) printf 'Unsupported test source: %s\n' "$source" >&2; exit 1;; esac
    [[ -s "$source" ]]
done
for source in "${fault_sources[@]}"; do
    case "$source" in *.c) ;; *) printf 'Unsupported fault source: %s\n' "$source" >&2; exit 1;; esac
    [[ -s "$source" ]]
done
producer_units=()
make --no-print-directory coverage-object-list > "$coverage_dir/object-manifest.txt"
make --no-print-directory coverage-unit-program-list > "$coverage_dir/unit-programs.txt"
make --no-print-directory coverage-unit-object-list > "$coverage_dir/unit-object-manifest.txt"
mapfile -t unit_programs < "$coverage_dir/unit-programs.txt"
if [[ "${#unit_programs[@]}" -eq 0 || -z "${unit_programs[0]}" ]]; then
    printf 'Coverage requires the cmocka unit suites; install its development package.\n' >&2
    exit 1
fi
for program in "${unit_programs[@]}"; do
    case "$program" in tests/unit/test_*) ;; *) printf 'Unsupported unit program: %s\n' "$program" >&2; exit 1;; esac
done
cat "$coverage_dir/object-manifest.txt" "$coverage_dir/unit-object-manifest.txt" | LC_ALL=C sort -u > "$coverage_dir/all-object-manifest.txt"
while IFS= read -r object; do
    case "$object" in *.o) producer_units+=("${object%.o}");; *) exit 1;; esac
done < "$coverage_dir/all-object-manifest.txt"
[[ "${#producer_units[@]}" -gt 0 ]]
printf '%s\n' "${producer_units[@]}" > "$coverage_dir/producers.txt"
[[ "$(sort -u "$coverage_dir/producers.txt" | wc -l)" -eq "${#producer_units[@]}" ]]
make clean >> "$coverage_dir/build.log" 2>&1
find . -path "$coverage_find_path" -prune -o -name '*.gcda' -type f -exec rm -f {} +
make -j2 spine test_spine_regressions test_spine_faults "${unit_programs[@]}" >> "$coverage_dir/build.log" 2>&1
sha256sum config/config.h Makefile.in > "$coverage_dir/generated-config.sha256"
cp config/config.h "$coverage_dir/generated-config.h"
cp Makefile.in "$coverage_dir/generated-Makefile.in"
sha256sum spine test_spine_regressions test_spine_faults > "$coverage_dir/binaries.sha256"
sha256sum "${unit_programs[@]}" >> "$coverage_dir/binaries.sha256"
cp config.log "$coverage_dir/config.log"
notes=()
for producer in "${producer_units[@]}"; do [[ -s "$producer.gcno" ]]; notes+=("$producer.gcno"); done
tests/tools/verify_coverage.sh --producers "$source_dir" "$coverage_dir/producers.txt" gcno
sha256sum "${notes[@]}" > "$coverage_dir/notes.sha256"
./spine --version > "$coverage_dir/entry-version.log" 2>&1
./spine --help > "$coverage_dir/entry-help.log" 2>&1
mkdir -p "$coverage_dir/unit-logs"
for program in "${unit_programs[@]}"; do
    "$program" > "$coverage_dir/unit-logs/${program##*/}.log" 2>&1
done
(cd "$coverage_dir" && sha256sum unit-logs/*.log) > "$coverage_dir/unit-logs.sha256"
./test_spine_regressions > "$coverage_dir/default.log" 2>&1
grep -Fq 'production regression tests passed' "$coverage_dir/default.log"
grep -Fq 'production SNMPv3 key and timeout boundary regressions passed' "$coverage_dir/default.log"
grep -Fq 'production CLI alias regressions passed' "$coverage_dir/default.log"
grep -Fq 'production script stream regressions passed' "$coverage_dir/default.log"
grep -Fq 'production config structure bindings passed' "$coverage_dir/default.log"
grep -Fq 'production numeric error-list boundary regressions passed' "$coverage_dir/default.log"
grep -Fq 'production additional contracts passed' "$coverage_dir/default.log"
grep -Fq 'production startup and statistics output contracts passed' "$coverage_dir/default.log"
./test_spine_regressions --database > "$coverage_dir/database.log" 2>&1
grep -Fq 'production settings write outcome regressions passed' "$coverage_dir/database.log"
grep -Fq 'production configuration option bounds and defaults passed' "$coverage_dir/database.log"
grep -Fq 'production database configuration regressions passed' "$coverage_dir/database.log"
grep -Fq 'production output write failure and retry regressions passed' "$coverage_dir/database.log"
grep -Fq 'production output recollection retains incomplete historical samples passed' "$coverage_dir/database.log"
grep -Fq 'production simultaneous output failure ordering regressions passed' "$coverage_dir/database.log"
grep -Fq 'production remote output destination failure and recollection regressions passed' "$coverage_dir/database.log"
grep -Fq 'production nullable SNMP profile handoff passed' "$coverage_dir/database.log"
grep -Fq 'production live SNMP and PHP reindex contracts passed' "$coverage_dir/database.log"
./test_spine_regressions --snmp-agent > "$coverage_dir/snmp.log" 2>&1
grep -Fq 'production SNMP agent regressions passed' "$coverage_dir/snmp.log"
grep -Fq 'production local silent UDP SNMP multi timeout regressions passed' "$coverage_dir/snmp.log"
SPINE_SNMPV3_EVIDENCE_DIR="$coverage_dir" tests/tools/run_snmpv3.sh > "$coverage_dir/snmpv3.log" 2>&1
grep -Fq 'production live SNMPv3 authentication and privacy regressions passed' "$coverage_dir/snmpv3.log"
./test_spine_faults > "$coverage_dir/fault-default.log" 2>&1
grep -Fq 'production logger date-format failure regressions passed' "$coverage_dir/fault-default.log"
grep -Fq 'production process creation failure regressions passed' "$coverage_dir/fault-default.log"
grep -Fq 'production linker fault regressions passed' "$coverage_dir/fault-default.log"
./test_spine_faults --database > "$coverage_dir/fault-database.log" 2>&1
grep -Fq 'production real lost-connection retry regressions passed' "$coverage_dir/fault-database.log"
grep -Fq 'production ping-only SNMP session ownership regressions passed' "$coverage_dir/fault-database.log"
grep -Fq 'production actual main worker launch failure and retry regressions passed' "$coverage_dir/fault-database.log"
grep -Fq 'production linker fault regressions passed' "$coverage_dir/fault-database.log"
profiles=()
for producer in "${producer_units[@]}"; do [[ -s "$producer.gcda" ]]; profiles+=("$producer.gcda"); done
tests/tools/verify_coverage.sh --producers "$source_dir" "$coverage_dir/producers.txt" gcda
if [[ "$(id -u)" -eq 0 ]]; then
    chmod a+rw "${profiles[@]}"
    setpriv --reuid=65534 --regid=65534 --clear-groups ./test_spine_regressions --icmp-no-capability > "$coverage_dir/icmp-denied.log" 2>&1
    setcap cap_net_raw+ep ./test_spine_regressions
    capability_added=1
    setpriv --reuid=65534 --regid=65534 --clear-groups ./test_spine_regressions --raw-icmp > "$coverage_dir/icmp-capability.log" 2>&1
else
    ./test_spine_regressions --icmp-no-capability > "$coverage_dir/icmp-denied.log" 2>&1
    sudo setcap cap_net_raw+ep ./test_spine_regressions
    capability_added=1
    ./test_spine_regressions --raw-icmp > "$coverage_dir/icmp-capability.log" 2>&1
fi
grep -Fq 'production ICMP socket-failure regression passed' "$coverage_dir/icmp-denied.log"
grep -Fq 'production ICMP loopback regression passed' "$coverage_dir/icmp-capability.log"
lcov_args=()
for source in "${production_sources[@]}"; do lcov_args+=(--include "$source_dir/$source"); done
lcov --capture --directory . --output-file "$coverage_dir/production.info" --rc branch_coverage=1 "${lcov_args[@]}" > "$coverage_dir/capture.log" 2>&1
# LCOV omits BRF/BRH for a source with no branches. Keep the verifier strict:
# obtain gcov's explicit branch arrays and prove the executed main is branchless
# before supplying its measured zero totals. Never infer zeros from absent data.
gcov -b -j -t src/app/main.gcda > "$coverage_dir/entry-gcov.json"
python3 tests/tools/normalize_entry_coverage.py "$coverage_dir/production.info" \
    "$coverage_dir/entry-gcov.json" "$source_dir/src/app/main.c"
python3 tests/tools/test_entry_coverage.py > "$coverage_dir/entry-verifier-self-test.log" 2>&1
tests/tools/test_coverage_verifier.sh > "$coverage_dir/verifier-self-test.log"
tests/tools/verify_coverage.sh "$coverage_dir/production.info" "$source_dir" "$coverage_dir/production-sources.txt"
lcov --summary "$coverage_dir/production.info" --rc branch_coverage=1 > "$coverage_dir/summary.txt" 2>&1
# Bind every producer and scenario to this immutable tested source snapshot.
sha256sum "${profiles[@]}" > "$coverage_dir/profiles.sha256"
mkdir -p "$coverage_dir/profiles" "$coverage_dir/bin"
cp --parents -- "${notes[@]}" "${profiles[@]}" "$coverage_dir/profiles/"
cp -- spine test_spine_regressions test_spine_faults "$coverage_dir/bin/"
cp -- "${unit_programs[@]}" "$coverage_dir/bin/"
(cd "$coverage_dir" && find profiles bin -type f -print0 | sort -z | xargs -0 sha256sum) > "$coverage_dir/saved-producers.sha256"
{
    sha256sum --check "$coverage_dir/source.sha256"
    sha256sum --check "$coverage_dir/generated-config.sha256"
    sha256sum --check "$coverage_dir/binaries.sha256"
    sha256sum --check "$coverage_dir/notes.sha256"
} > "$coverage_dir/source-verification.log"
printf '%s\n' default cmocka-unit-suites numeric-error-boundaries config-bindings script-streams cli-aliases additional-contracts database settings-write-outcome output-write-failure-retry output-recollection-new-timestamp simultaneous-output-failure-ordering remote-output-destination-failure-recollection output-sql-batch-boundary nullable-snmp-profile live-reindex snmp local-silent-udp-snmp-multi-timeout snmpv3-key-timeout snmpv3-live fault-default fault-logger fault-process fault-database-retry fault-ping-only-session worker-launch-admitted worker-launch-rejected worker-launch-eagain-retry icmp-denied icmp-capability > "$coverage_dir/scenarios.txt"
(cd "$coverage_dir" && sha256sum default.log database.log snmp.log snmpv3.log snmpv3-agent.log fault-default.log fault-database.log icmp-denied.log icmp-capability.log scenarios.txt production.info summary.txt source.sha256 generated-config.sha256 binaries.sha256 notes.sha256 profiles.sha256 production-sources.txt test-sources.txt fault-sources.txt producers.txt revision.txt worktree-status.txt compiler.txt dependencies.txt gcov.txt lcov.txt object-manifest.txt unit-programs.txt unit-object-manifest.txt all-object-manifest.txt unit-logs.sha256 unit-logs/*.log entry-help.log entry-version.log entry-gcov.json entry-verifier-self-test.log source-Makefile.in generated-Makefile.in generated-config.h source-inputs.nul source-inputs.tar.gz saved-producers.sha256) > "$coverage_dir/evidence.sha256"
cat "$coverage_dir/summary.txt"
coverage_complete=1
