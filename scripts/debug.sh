#!/bin/bash
# SPDX-FileCopyrightText: 2004-2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.
#

if [[ -z ${SPINE_CONFIG:-} ]]; then
	export SPINE_CONFIG="/etc/spine.conf";
fi

if make; then
	echo
	echo ------
	echo "Debugging using SPINE_CONFIG = $SPINE_CONFIG"
	echo
	echo
	gdb -quiet -ex run --args ./spine -R -V 6 -C "$SPINE_CONFIG"
else
	exit 1
fi
