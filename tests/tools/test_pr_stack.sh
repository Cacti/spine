#!/bin/sh
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
exec python3 "${srcdir:-.}/tests/tools/test_pr_stack.py"
