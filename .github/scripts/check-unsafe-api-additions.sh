#!/usr/bin/env bash
set -euo pipefail

base_commit=""

if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
  git fetch --no-tags --depth=1 origin "${GITHUB_BASE_REF}" || true
  base_commit="$(git merge-base HEAD "origin/${GITHUB_BASE_REF}" 2>/dev/null || true)"
fi

if [[ -z "${base_commit}" ]]; then
  base_commit="$(git rev-parse HEAD~1 2>/dev/null || git rev-list --max-parents=0 HEAD)"
fi

banned_regex='(sprintf|vsprintf|strcpy|strcat|gets)\s*\('

new_hits="$(
  git diff --unified=0 "${base_commit}"...HEAD -- '*.c' '*.h' |
    grep -E '^\+[^+]' |
    grep -E "${banned_regex}" || true
)"

if [[ -n "${new_hits}" ]]; then
  echo "Unsafe C APIs were newly added in this change:"
  echo "${new_hits}"
  exit 1
fi

echo "No newly added banned C APIs detected."
