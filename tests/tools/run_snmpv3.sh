#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
# Run only against the owned local agent and public regression credentials.
set -euo pipefail
: "${SPINE_SNMPV3_EVIDENCE_DIR:?Set the owned agent evidence directory}"
command -v snmpd >/dev/null
mkdir -p "$SPINE_SNMPV3_EVIDENCE_DIR"
snmpv3_persistent="$(mktemp -d "${TMPDIR:-/tmp}/spine-snmpv3.XXXXXX")"
snmpv3_agent_pid=''
cleanup_snmpv3() {
    status=$?
    if [[ -n "$snmpv3_agent_pid" ]]; then
        kill "$snmpv3_agent_pid" 2>/dev/null || true
        wait "$snmpv3_agent_pid" || true
    fi
    cp "$snmpv3_persistent/agent.log" "$SPINE_SNMPV3_EVIDENCE_DIR/snmpv3-agent.log" || status=1
    rm -rf -- "$snmpv3_persistent"
    exit "$status"
}
trap cleanup_snmpv3 EXIT
cp tests/fixtures/snmpv3-users.conf "$snmpv3_persistent/snmpd.conf"
SNMP_PERSISTENT_DIR="$snmpv3_persistent" snmpd -f -Lo -C -c "$snmpv3_persistent/snmpd.conf,tests/fixtures/snmpv3-agent.conf" > "$snmpv3_persistent/agent.log" 2>&1 &
snmpv3_agent_pid=$!
sleep 1
kill -0 "$snmpv3_agent_pid"
SPINE_TEST_SNMPV3_HOST=127.0.0.1 ./test_spine_regressions --snmpv3-agent
