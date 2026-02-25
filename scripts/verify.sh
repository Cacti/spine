#!/usr/bin/env bash
set -euo pipefail

echo "=== cppcheck ==="
cppcheck --enable=all --std=c11 --error-exitcode=1 \
  --suppress=missingIncludeSystem \
  --suppress=unusedFunction \
  --suppress=checkersReport \
  --suppress=toomanyconfigs \
  *.c *.h 2>&1 | tee /tmp/cppcheck.txt

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
