#!/usr/bin/env bash
# Run shfmt + shellcheck against the tracked shell script allowlist.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly SHELL_FILELIST="${REPO_ROOT}/.github/lint-shell-files.txt"

main() {
  cd "${REPO_ROOT}"

  if [[ ! -f "${SHELL_FILELIST}" ]]; then
    echo "ERROR: missing ${SHELL_FILELIST}" >&2
    exit 1
  fi

  local -a shell_files=()
  while IFS= read -r file; do
    [[ -z "${file}" ]] && continue
    [[ "${file}" == \#* ]] && continue
    if [[ ! -f "${file}" ]]; then
      echo "ERROR: lint-shell allowlist entry does not exist: ${file}" >&2
      exit 1
    fi
    shell_files+=("${file}")
  done <"${SHELL_FILELIST}"

  if [[ "${#shell_files[@]}" -eq 0 ]]; then
    echo "No shell files found for linting."
    return 0
  fi

  shfmt -d -i 2 -ci "${shell_files[@]}"
  shellcheck -x "${shell_files[@]}"
}

main "$@"
