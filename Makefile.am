# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2024 The Cacti Group                                 |
# |                                                                         |
# | This program is free software; you can redistribute it and/or           |
# | modify it under the terms of the GNU General Public License             |
# | as published by the Free Software Foundation; either version 2          |
# | of the License, or (at your option) any later version.                  |
# |                                                                         |
# | This program is distributed in the hope that it will be useful,         |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
# | GNU General Public License for more details.                            |
# +-------------------------------------------------------------------------+
# | Cacti: The Complete RRDtool-based Graphing Solution                     |
# +-------------------------------------------------------------------------+
# | This code is designed, written, and maintained by the Cacti Group. See  |
# | about.php and/or the AUTHORS file for specific developer information.   |
# +-------------------------------------------------------------------------+
# | http://www.cacti.net/                                                   |
# +-------------------------------------------------------------------------+

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4

spine_SOURCES = sql.c spine.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

# Seed a live config on first install without ever overwriting an existing one.
install-data-hook:
	if [ ! -f "$(DESTDIR)$(configdir)/spine.conf" ]; then \
		$(INSTALL_DATA) "$(srcdir)/spine.conf.dist" "$(DESTDIR)$(configdir)/spine.conf"; \
	fi

# Mirror image of the hook above: only remove spine.conf if it was never
# customized (still identical to the .dist it was seeded from), so a real
# uninstall never discards a live config, while distcheck's install/uninstall
# symmetry check still passes against its untouched sandbox copy.
uninstall-hook:
	if cmp -s "$(DESTDIR)$(configdir)/spine.conf" "$(srcdir)/spine.conf.dist" 2>/dev/null; then \
		rm -f "$(DESTDIR)$(configdir)/spine.conf"; \
	fi

bin_PROGRAMS = spine

check_PROGRAMS = tests/test_nft_popen
TESTS = $(check_PROGRAMS)
tests_test_nft_popen_SOURCES = tests/test_nft_popen.c nft_popen.c
tests_test_nft_popen_CPPFLAGS = $(AM_CPPFLAGS) -Dwaitpid=nft_test_waitpid -Dclock_gettime=nft_test_clock_gettime

EXTRA_PROGRAMS = tests/spine_alloc_fault
tests_spine_alloc_fault_SOURCES = $(spine_SOURCES) tests/alloc_fault.c
tests_spine_alloc_fault_LDFLAGS = -Wl,--wrap=calloc
EXTRA_DIST = tests/backport_contracts.py tests/integration.py tests/schema.sql tests/README.md

.PHONY: integration-check
integration-check: spine tests/spine_alloc_fault
	SPINE_TEST_BINARY="$(abs_builddir)/spine" SPINE_TEST_FAULT_BINARY="$(abs_builddir)/tests/spine_alloc_fault" python3 "$(srcdir)/tests/integration.py"

man_MANS = spine.1

spine.1: $(bin_PROGRAMS)
	$(HELP2MAN) --output=$@ --name='Data Collector for Cacti' --no-info --version-option='--version' ./spine
