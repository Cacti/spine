#!/usr/bin/env bash
# Local verification helper.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly BUILD_DIR="${REPO_ROOT}/build-verify"

main() {
  cd "${REPO_ROOT}"

  echo "=== preflight ==="
  bash scripts/preflight.sh

  echo
  echo "=== scan-build ==="
  rm -rf "${BUILD_DIR}"
  scan-build -o /tmp/scan-results --status-bugs \
    cmake -G Ninja -S . -B "${BUILD_DIR}" -DSPINE_BUILD_MAIN=ON
  scan-build -o /tmp/scan-results --status-bugs \
    cmake --build "${BUILD_DIR}"

  echo
  echo "=== smoke tests ==="
  "${BUILD_DIR}/spine" --help >/dev/null 2>&1
  echo "spine --help: OK"
  "${BUILD_DIR}/spine" --version >/dev/null 2>&1
  echo "spine --version: OK"

  echo
  echo "=== all checks passed ==="
}

main "$@"
