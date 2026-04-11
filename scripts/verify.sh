#!/usr/bin/env bash
set -euo pipefail

echo "=== cppcheck ==="
cppcheck --enable=all --std=c11 --error-exitcode=1 \
  --suppress=missingIncludeSystem \
  --suppress=unusedFunction \
  --suppress=checkersReport \
  --suppress=toomanyconfigs \
  -- *.c *.h 2>&1 | tee /tmp/cppcheck.txt

echo ""
echo "=== scan-build ==="
rm -rf build
scan-build -o /tmp/scan-results --status-bugs \
  cmake -G Ninja -S . -B build -DSPINE_BUILD_MAIN=ON 2>&1
scan-build -o /tmp/scan-results --status-bugs \
  cmake --build build 2>&1

echo ""
echo "=== smoke tests ==="
./build/spine --help > /dev/null 2>&1
echo "spine --help: OK"
./build/spine --version > /dev/null 2>&1
echo "spine --version: OK"

echo ""
echo "=== All checks passed ==="
