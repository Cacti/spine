#!/usr/bin/env bash
set -euo pipefail

echo "=== cppcheck ==="
mapfile -d '' source_files < <(
  find . \
    -path './autom4te.cache' -prune -o \
    -path './config' -prune -o \
    -path './m4' -prune -o \
    -path './spine-*' -prune -o \
    -path './tests' -prune -o \
    -type f \( -name '*.c' -o -name '*.h' \) -print0
)
cppcheck --enable=all --std=c11 --error-exitcode=1 \
  -I. -Isrc/core \
  --suppress=missingIncludeSystem \
  --suppress=unusedFunction \
  --suppress=checkersReport \
  --suppress=toomanyconfigs \
  -- "${source_files[@]}" 2>&1 | tee /tmp/cppcheck.txt

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
