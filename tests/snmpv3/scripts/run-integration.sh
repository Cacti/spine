#!/usr/bin/env bash
# Drives the SNMPv3 fixture.
#
# --abort-on-container-exit cannot be used: it tears the database down the
# moment spine exits, before the verifier can query what spine wrote.
set -euo pipefail

cd "$(dirname "$0")/.."

compose=(docker compose)
case "${SPINE_TEST_DATABASE:-mariadb}" in
	mariadb) ;;
	mysql) compose+=(-f docker-compose.yml -f docker-compose.mysql.yml) ;;
	*) echo "unsupported SPINE_TEST_DATABASE: ${SPINE_TEST_DATABASE}" >&2; exit 2 ;;
esac

cleanup() { "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Start from an empty database. Without this the verifier can pass on rows the
# previous run wrote, so a poll that produced nothing still looks green.
cleanup

"${compose[@]}" up --build -d

verify_id=$("${compose[@]}" ps -qa verify)
[ -n "$verify_id" ] || { echo "verify container was never created"; "${compose[@]}" logs --no-color; exit 1; }

code=$(docker wait "$verify_id")

"${compose[@]}" logs --no-color spine verify

exit "$code"
