#!/usr/bin/env bash
# Fast local gate: shell lint, spelling, and a clean CMake configure/build.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly BUILD_DIR="${REPO_ROOT}/build-preflight"

cpu_count() {
  if command -v nproc >/dev/null 2>&1; then
    nproc
    return
  fi
  if command -v getconf >/dev/null 2>&1; then
    getconf _NPROCESSORS_ONLN
    return
  fi
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -n hw.ncpu
    return
  fi
  echo 4
}

main() {
  cd "${REPO_ROOT}"

  echo "=== shell lint ==="
  bash scripts/lint-shell.sh

  echo
  echo "=== codespell ==="
  bash scripts/lint-codespell.sh

  echo
  echo "=== cmake configure ==="
  cmake -S . -B "${BUILD_DIR}" -DSPINE_BUILD_MAIN=ON -DCMAKE_BUILD_TYPE=Debug

  echo
  echo "=== cmake build ==="
  cmake --build "${BUILD_DIR}" -j"$(cpu_count)"

  echo
  echo "=== preflight passed ==="
}

main "$@"
