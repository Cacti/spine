#!/usr/bin/env bash
# Reports which lines of the poller the integration fixture actually reaches.
#
# Builds spine with gcov instrumentation in a single stage so the .gcda files
# survive in the container, runs the fixture, then reports per-file coverage.
set -euo pipefail

cd "$(dirname "$0")/.."
out=${1:-/tmp/spine-coverage}

cleanup() { docker compose -f docker-compose.yml -f docker-compose.coverage.yml down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker compose -f docker-compose.yml -f docker-compose.coverage.yml up --build -d
sid=$(docker compose -f docker-compose.yml -f docker-compose.coverage.yml ps -qa spine)
docker wait "$sid" >/dev/null

rm -rf "$out" && mkdir -p "$out"
docker cp "$sid:/src" "$out/src"

docker run --rm -v "$out/src:/src" debian:bookworm-slim sh -c '
	apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq gcc >/dev/null 2>&1
	cd /src && gcov -n *.c 2>/dev/null | grep -B1 "^Lines executed" | grep -A1 "^File .\(poller\|ping\|snmp\|util\|php\)\.c"
'
