#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Source files carry SPDX headers and packaging/debian/copyright agrees with them.
set -eu
root=$(cd "${srcdir:-.}" && pwd)
command -v python3 >/dev/null 2>&1 || exit 77
exec python3 "$root/tests/tools/check_licensing.py"
