/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#include "app/runtime.h"
#include "internal/common.h"
#include "app/spine.h"
#include "process/resource.h"

int main(int argc, char *argv[]) {
	if (argc > 1 && strcmp(argv[1], "--internal-script-child") == 0) {
		/* This entry point must never bypass the setuid privilege boundary. */
		drop_privileges();
		return spine_script_resource_child(argc, argv);
	}
	spine_run(argc, argv);
}
