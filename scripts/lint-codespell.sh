#!/usr/bin/env bash
# Run codespell against a deterministic tracked-file glob list.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly CODESPELL_GLOBS_FILE="${REPO_ROOT}/.github/lint-codespell-globs.txt"
readonly IGNORE_WORDS_FILE="${REPO_ROOT}/.codespell-ignore-words.txt"

collect_files() {
  local -a globs=()
  while IFS= read -r pattern; do
    [[ -z "${pattern}" ]] && continue
    [[ "${pattern}" == \#* ]] && continue
    globs+=("${pattern}")
  done <"${CODESPELL_GLOBS_FILE}"

  if [[ "${#globs[@]}" -eq 0 ]]; then
    return 0
  fi

  git ls-files -- "${globs[@]}" | sort -u
}

main() {
  cd "${REPO_ROOT}"

  if [[ ! -f "${CODESPELL_GLOBS_FILE}" ]]; then
    echo "ERROR: missing ${CODESPELL_GLOBS_FILE}" >&2
    exit 1
  fi
  if [[ ! -f "${IGNORE_WORDS_FILE}" ]]; then
    echo "ERROR: missing ${IGNORE_WORDS_FILE}" >&2
    exit 1
  fi

  local -a files=()
  mapfile -t files < <(collect_files)
  if [[ "${#files[@]}" -eq 0 ]]; then
    echo "No eligible files found for codespell."
    return 0
  fi

  codespell \
    --quiet-level=2 \
    --ignore-words="${IGNORE_WORDS_FILE}" \
    "${files[@]}"
}

main "$@"
