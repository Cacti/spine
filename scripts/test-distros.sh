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

# Associative arrays (declare -A) require bash 4+. macOS ships GNU bash 3.2 at
# /bin/bash for licensing reasons; the script must run under a newer bash or
# it will silently corrupt the RESULTS map.
if ((BASH_VERSINFO[0] < 4)); then
  echo "ERROR: scripts/test-distros.sh requires bash 4+ (found ${BASH_VERSION})." >&2
  echo "       On macOS: brew install bash && /opt/homebrew/bin/bash scripts/test-distros.sh" >&2
  exit 1
fi

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
  # Security: validate distro name to prevent command injection
  if [[ ! "$distro" =~ ^[a-zA-Z0-9\._/:-]+$ ]]; then
    echo "ERROR: invalid distro name: $distro" >&2
    exit 1
  fi

  safe="${distro//[:\/]/-}"
  logfile="$REPO_ROOT/build-reports/${safe}.log"
  echo "=== $distro ===" | tee "$logfile"

  CC_ENV=""
  case "$distro" in
    rockylinux* | almalinux*)
      PKG='dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel'
      ;;
    fedora*)
      PKG='dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel'
      ;;
    debian* | ubuntu*)
      PKG='apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev'
      ;;
    opensuse*)
      # Leap 15 ships GCC 7 by default, which rejects -std=c17. gcc13
      # is in the default repos and provides the C17 dialect spine needs.
      PKG='zypper --non-interactive install cmake gcc13 make net-snmp-devel libmariadb-devel libopenssl-devel pkg-config systemd-devel'
      CC_ENV='CC=gcc-13'
      ;;
    alpine*)
      PKG='apk add --no-cache bash cmake gcc make musl-dev net-snmp-dev mariadb-connector-c-dev openssl-dev pkgconfig linux-headers'
      ;;
    *ubi9* | *ubi:9* | *redhat.com/ubi9*)
      # Advisory: UBI 9 ships a restricted package set.
      # mariadb-connector-c-devel typically requires subscription repos.
      # Run with: bash scripts/test-distros.sh registry.access.redhat.com/ubi9/ubi
      PKG='dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm || true; dnf install -y cmake gcc make openssl-devel pkgconfig systemd-devel; dnf install -y net-snmp-devel || echo "net-snmp-devel unavailable"; dnf install -y mariadb-connector-c-devel || echo "mariadb-connector-c-devel unavailable"'
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
    sh -c "$PKG && $CC_ENV cmake -B build-$safe -DCMAKE_BUILD_TYPE=Debug && cmake --build build-$safe -j && ./build-$safe/spine --help | head -3" 2>&1 | tee -a "$logfile"; then
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
