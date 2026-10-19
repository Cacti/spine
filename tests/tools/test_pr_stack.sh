#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
exec python3 "${srcdir:-.}/tests/tools/test_pr_stack.py"
