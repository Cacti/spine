#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
export COMPOSE_PROJECT_NAME=${SPINE_TEST_PROJECT:-spine-upsert-$$}
compose=(docker compose -f "$root/tests/snmpv3/docker-compose.yml" -f "$root/tests/snmpv3/docker-compose.policy.yml")
cleanup() { "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1; }
trap cleanup EXIT
"${compose[@]}" build policy
"${compose[@]}" up -d --wait db dbmysql dbmaria2 dbmysql2
for pair in 'db dbmaria2' 'dbmysql dbmysql2' 'db dbmysql' 'dbmysql db'; do
  read -r source destination <<< "$pair"
  "${compose[@]}" run --rm policy "$source" "$destination"
done
echo 'All four MySQL/MariaDB destination combinations passed'
