#!/usr/bin/env bash
set -euo pipefail

echo "=== cppcheck ==="
source_list=$(mktemp)
trap 'rm -f "$source_list"' EXIT
find . -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \) \
  -print0 > "$source_list"
find src -type f \( -name '*.c' -o -name '*.h' \) \
  -print0 >> "$source_list"
source_files=()
while IFS= read -r -d '' source_file; do
  source_files+=("$source_file")
done < "$source_list"
if (( ${#source_files[@]} == 0 )); then
  echo "ERROR: no C sources or headers found" >&2
  exit 1
fi
cppcheck --enable=all --std=c11 --error-exitcode=1 \
  -I. -Isrc/core \
  --suppress=missingIncludeSystem \
  --suppress=unusedFunction \
  --suppress=checkersReport \
  --suppress=toomanyconfigs \
  -- "${source_files[@]}" 2>&1 | tee /tmp/cppcheck.txt

if [[ "${VERIFY_CPPCHECK_ONLY:-0}" == "1" ]]; then
  exit 0
fi

echo ""
echo "=== scan-build ==="
make clean
scan-build -o /tmp/scan-results --status-bugs make -j"$(nproc)" 2>&1

echo ""
echo "=== smoke tests ==="
./spine --help > /dev/null 2>&1
echo "spine --help: OK"
./spine --version > /dev/null 2>&1
echo "spine --version: OK"

echo ""
echo "=== All checks passed ==="
