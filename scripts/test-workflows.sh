#!/usr/bin/env bash
# Test GitHub Actions workflows and policy gates locally.
#
# Requires: act (brew install act / https://github.com/nektos/act)
# Optional: docker (for container-based lanes), python3 (for policy script)
#
# Usage:
#   scripts/test-workflows.sh policy       # run check-workflow-policy.py
#   scripts/test-workflows.sh list         # list all jobs act sees
#   scripts/test-workflows.sh dry          # dry-run (parse, don't execute)
#   scripts/test-workflows.sh <job>        # run one specific job
#   scripts/test-workflows.sh distro <img> # run distro-matrix for one image
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
cd "${REPO_ROOT}"

cmd="${1:-help}"
shift || true

require_cmd() {
  local cmd_name="$1"
  local install_hint="$2"
  command -v "${cmd_name}" >/dev/null 2>&1 || {
    echo "ERROR: install ${install_hint}" >&2
    exit 1
  }
}

validate_token() {
  local value="$1"
  local kind="$2"
  if [[ ! "${value}" =~ ^[a-zA-Z0-9._/:-]+$ ]]; then
    echo "ERROR: invalid ${kind}: ${value}" >&2
    exit 1
  fi
}

case "$cmd" in
  policy)
    if [[ ! -f .github/scripts/check-workflow-policy.py ]]; then
      echo "ERROR: .github/scripts/check-workflow-policy.py not found"
      exit 1
    fi
    python3 .github/scripts/check-workflow-policy.py
    ;;
  list)
    require_cmd act "act (brew install act)"
    act -l
    ;;
  dry)
    require_cmd act "act"
    act -n
    ;;
  distro)
    if [[ $# -lt 1 ]]; then
      echo "Usage: $0 distro <image>"
      echo "Prefer scripts/test-distros.sh for container builds (faster, no act overhead)."
      exit 1
    fi
    # Security: validate image name
    validate_token "$1" "image name"
    bash scripts/test-distros.sh "$1"
    ;;
  help | -h | --help)
    sed -n '2,/^set /p' "$0" | grep -E '^# ' | sed 's/^# \?//'
    ;;
  *)
    # Security: validate job name
    if [[ ! "${cmd}" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      echo "ERROR: invalid job name: $cmd" >&2
      exit 1
    fi
    # Treat as a job name
    require_cmd act "act"
    act -j "$cmd" "$@"
    ;;
esac
