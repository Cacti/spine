# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2026 The Cacti Group                                 |
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

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

spine_SOURCES = sql.c spine.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

bin_PROGRAMS = spine

man_MANS = spine.1

# Headers are not referenced by any _SOURCES, so automake will not distribute
# them unless they are listed. Without this the release tarball builds nothing.
noinst_HEADERS = common.h error.h keywords.h locks.h nft_popen.h php.h \
	ping.h poller.h snmp.h spine.h spine_sem.h sql.h uthash.h util.h

EXTRA_DIST = spine.1 spine.conf.dist

# Docker targets — require Dockerfile and Dockerfile.dev (from PR #401)
.PHONY: docker docker-dev verify cppcheck

docker:
	docker build -t spine .

docker-dev:
	docker build -f Dockerfile.dev -t spine-dev .

verify: docker-dev
	docker run --rm spine-dev

cppcheck: docker-dev
	docker run --rm spine-dev bash -c \
		"cppcheck --enable=all --std=c11 --error-exitcode=1 \
		--suppress=missingIncludeSystem --suppress=unusedFunction \
		--suppress=checkersReport --suppress=toomanyconfigs $(spine_SOURCES)"

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_builddir)

check_PROGRAMS =

if HAVE_CMOCKA
check_PROGRAMS += \
	tests/unit/test_util_strings \
	tests/unit/test_build_fixes \
	tests/unit/test_safety_fixes \
	tests/unit/test_linked \
	tests/unit/test_log_newline_bound \
	tests/unit/test_util_paths \
	tests/unit/test_snmpv3_session \
	tests/unit/test_ping_icmp

if HAVE_LD_WRAP
check_PROGRAMS += \
	tests/unit/test_poll_host_release \
	tests/unit/test_poller_output
endif
endif

# test_util_strings pulls in common.h and the sources under test, so it needs
# the same libraries spine links against.  The others are self-contained.
tests_unit_test_util_strings_SOURCES = tests/unit/test_util_strings.c
tests_unit_test_util_strings_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_build_fixes_SOURCES  = tests/unit/test_build_fixes.c
tests_unit_test_build_fixes_LDADD    = $(CMOCKA_LIBS)

tests_unit_test_safety_fixes_SOURCES = tests/unit/test_safety_fixes.c
tests_unit_test_safety_fixes_LDADD   = $(CMOCKA_LIBS)

# test_linked exercises the shipped objects rather than a copy of the logic.
# Everything except spine.c is linked as built; tests/fuzz/stubs.c supplies the
# globals that spine.c would define.
tests_unit_test_linked_SOURCES = tests/unit/test_linked.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c
tests_unit_test_linked_LDADD   = $(CMOCKA_LIBS) $(LIBS)

if HAVE_LD_WRAP
# poll_host's teardown calls db_release_connection() and mysql_thread_end(),
# neither of which returns anything to assert on. Interpose on both so the
# release path is reachable from the suite at all.
tests_unit_test_poll_host_release_SOURCES = tests/unit/test_poll_host_release.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c
tests_unit_test_poll_host_release_LDADD   = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_poll_host_release_LDFLAGS = -Wl,--wrap=db_release_connection -Wl,--wrap=mysql_thread_end -Wl,--wrap=usleep
endif

if HAVE_LD_WRAP
# db_escape() needs a live connection, so the tuple builder is only reachable
# with a stand-in escaper in its place.
tests_unit_test_poller_output_SOURCES = tests/unit/test_poller_output.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c
tests_unit_test_poller_output_LDADD   = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_poller_output_LDFLAGS = -Wl,--wrap=db_escape
endif

# snmp_sess_open() builds a session without contacting anything, so the
# security level spine ends up with is assertable directly.
tests_unit_test_snmpv3_session_SOURCES = tests/unit/test_snmpv3_session.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c
tests_unit_test_snmpv3_session_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# ping_icmp() needs a raw ICMP socket, so these skip where that is unavailable.
tests_unit_test_ping_icmp_SOURCES = tests/unit/test_ping_icmp.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c
tests_unit_test_ping_icmp_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_log_newline_bound_SOURCES = tests/unit/test_log_newline_bound.c
tests_unit_test_log_newline_bound_LDADD   = $(CMOCKA_LIBS)

# includes util.c, so it needs the same libraries spine links against
tests_unit_test_util_paths_SOURCES = tests/unit/test_util_paths.c
tests_unit_test_util_paths_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# Shell tests run alongside the cmocka binaries. Each exits 77 when its
# fixture is unavailable, which automake reports as SKIP, so `make check` is
# meaningful on a laptop without docker and complete in CI with it.
#
# tests/regression/test_child_process_safety.sh was in the tree but in no
# TESTS list, and had been failing on develop since #542 removed the code it
# guards. Nothing ran it. That is the reason these are wired in here.
SHELL_TESTS = \
	tests/regression/test_remote_upsert_syntax.sh \
	tests/integration/smoke_test.sh \
	tests/integration/test_alloc_failure.sh \
	tests/integration/test_cli_args.sh \
	tests/integration/test_db_column_detect.sh \
	tests/integration/test_output_regex.sh \
	tests/integration/test_script_server_reap.sh \
	tests/regression/test_child_process_safety.sh

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)

TESTS = $(check_PROGRAMS) $(SHELL_TESTS)

EXTRA_DIST += $(SHELL_TESTS) tests/golden/poll_host_queries.golden tests/golden/README.md

# Per-function coverage for the code that has been pulled out of the large
# functions, which is the number worth watching. Requires a build configured
# with --enable-coverage.
.PHONY: coverage
coverage:
	@if [ ! -f poller.gcno ] && [ ! -f .libs/poller.gcno ]; then \
		echo "configure with --enable-coverage first"; exit 1; \
	fi
	@$(MAKE) check >/dev/null 2>&1 || true
	@echo "function coverage:"
	@gcov -n -f $(srcdir)/poller.c $(srcdir)/util.c $(srcdir)/sql.c 2>/dev/null \
		| grep -A1 "^Function" | paste - - - \
		| sed "s/Function //; s/Lines executed://" \
		| awk -F'\t' '{ printf "  %-38s %s\n", $$1, $$2 }' \
		| sort -k2 -t: -n
