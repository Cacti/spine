#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-only
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
# Stands in for a Cacti data-input script: echoes the value it was handed, so
# the integration check can assert the poller stored exactly what the script
# printed.
echo "$1"
