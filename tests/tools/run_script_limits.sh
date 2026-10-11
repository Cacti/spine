#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
probe_directory=$(mktemp -d)
trap 'rm -rf -- "$probe_directory"' EXIT
# This is an external workload, like /usr/bin/printf. ASan reserves enormous
# virtual address ranges and cannot serve as the memory-limited child probe.
"${CC:-cc}" -std=gnu17 -O0 -g0 tests/fixtures/script_resource_probe.c -o "$probe_directory/probe"
SPINE_SCRIPT_RESOURCE_PROBE="$probe_directory/probe" ./test_spine_regressions --script-limits
