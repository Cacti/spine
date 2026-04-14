#!/usr/bin/env bash
# Build and smoke-test spine inside representative Linux distros via Docker.
# Usage:
#   scripts/test-distros.sh                 # run the full default matrix
#   scripts/test-distros.sh debian:12 ...   # run a subset
#
# Each distro is built in its own container against the current checkout
# (mounted read-write at /src) into a distro-specific build dir so artefacts
# from one run do not contaminate another. Logs land in build-reports/.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DISTROS=(
    rockylinux:9
    rockylinux:8
    almalinux:9
    fedora:latest
    debian:12
    debian:trixie
    ubuntu:22.04
    ubuntu:24.04
    opensuse/leap:15
    alpine:3.20
)
if [[ $# -gt 0 ]]; then
    DISTROS=("$@")
fi

mkdir -p "$REPO_ROOT/build-reports"
declare -A RESULTS

for distro in "${DISTROS[@]}"; do
    safe="${distro//[:\/]/-}"
    logfile="$REPO_ROOT/build-reports/${safe}.log"
    echo "=== $distro ===" | tee "$logfile"

    case "$distro" in
        rockylinux*|almalinux*)
            PKG='dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel'
            ;;
        fedora*)
            PKG='dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel'
            ;;
        debian*|ubuntu*)
            PKG='apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev'
            ;;
        opensuse*)
            PKG='zypper --non-interactive install cmake gcc make net-snmp-devel libmariadb-devel libopenssl-devel pkg-config systemd-devel'
            ;;
        alpine*)
            PKG='apk add --no-cache bash cmake gcc make musl-dev net-snmp-dev mariadb-connector-c-dev openssl-dev pkgconfig linux-headers'
            ;;
        *)
            echo "unknown distro pattern: $distro" | tee -a "$logfile"
            RESULTS[$distro]=SKIP
            continue
            ;;
    esac

    if docker run --rm \
        -v "$REPO_ROOT:/src" \
        -w /src \
        -e CMAKE_BUILD_PARALLEL_LEVEL="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" \
        "$distro" \
        sh -c "$PKG && cmake -B build-$safe -DCMAKE_BUILD_TYPE=Debug && cmake --build build-$safe -j && ./build-$safe/spine --help | head -3" 2>&1 | tee -a "$logfile"; then
        RESULTS[$distro]=PASS
    else
        RESULTS[$distro]=FAIL
    fi
done

echo
echo "=== SUMMARY ==="
for d in "${!RESULTS[@]}"; do
    printf "%-30s %s\n" "$d" "${RESULTS[$d]}"
done

for r in "${RESULTS[@]}"; do
    if [[ "$r" == "FAIL" ]]; then
        exit 1
    fi
done
exit 0
