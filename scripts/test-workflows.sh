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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

cmd="${1:-help}"
shift || true

case "$cmd" in
  policy)
    if [[ ! -f .github/scripts/check-workflow-policy.py ]]; then
      echo "ERROR: .github/scripts/check-workflow-policy.py not found"
      exit 1
    fi
    python3 .github/scripts/check-workflow-policy.py
    ;;
  list)
    command -v act >/dev/null 2>&1 || {
      echo "ERROR: install act (brew install act)"
      exit 1
    }
    act -l
    ;;
  dry)
    command -v act >/dev/null 2>&1 || {
      echo "ERROR: install act"
      exit 1
    }
    act -n
    ;;
  distro)
    if [[ $# -lt 1 ]]; then
      echo "Usage: $0 distro <image>"
      echo "Prefer scripts/test-distros.sh for container builds (faster, no act overhead)."
      exit 1
    fi
    # Security: validate image name
    if [[ ! "$1" =~ ^[a-zA-Z0-9\._/:-]+$ ]]; then
      echo "ERROR: invalid image name: $1" >&2
      exit 1
    fi
    bash scripts/test-distros.sh "$1"
    ;;
  help | -h | --help)
    sed -n '2,/^set /p' "$0" | grep -E '^# ' | sed 's/^# \?//'
    ;;
  *)
    # Security: validate job name
    if [[ ! "$cmd" =~ ^[a-zA-Z0-9_-]+$ ]]; then
      echo "ERROR: invalid job name: $cmd" >&2
      exit 1
    fi
    # Treat as a job name
    command -v act >/dev/null 2>&1 || {
      echo "ERROR: install act"
      exit 1
    }
    act -j "$cmd" "$@"
    ;;
esac
