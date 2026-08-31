#!/usr/bin/env bash
# Drives the SNMPv3 fixture.
#
# --abort-on-container-exit cannot be used: it tears the database down the
# moment spine exits, before the verifier can query what spine wrote.
set -euo pipefail

cd "$(dirname "$0")/.."

cleanup() { docker compose down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Start from an empty database. Without this the verifier can pass on rows the
# previous run wrote, so a poll that produced nothing still looks green.
cleanup

docker compose up --build -d

verify_id=$(docker compose ps -qa verify)
[ -n "$verify_id" ] || { echo "verify container was never created"; docker compose logs --no-color; exit 1; }

code=$(docker wait "$verify_id")

docker compose logs --no-color spine verify

exit "$code"
