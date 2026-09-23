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

spine_SOURCES = sql.c spine.c util.c snmp.c src/core/locks.c poller.c \
	nft_popen.c php.c ping.c src/core/keywords.c error.c

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

man_MANS = spine.1

# Headers are not referenced by any _SOURCES, so automake will not distribute
# them unless they are listed. Without this the release tarball builds nothing.
noinst_HEADERS = common.h error.h src/core/keywords.h src/core/locks.h \
	nft_popen.h php.h ping.h poller.h snmp.h spine.h spine_sem.h sql.h \
	uthash.h util.h

EXTRA_DIST = spine.1 spine.conf.dist \
	tests/README.md \
	tests/test-harness.sh \
	tests/integration/test_concurrency.sh \
	tests/integration/test_network_faults.sh

# Docker targets — require Dockerfile and Dockerfile.dev (from PR #401)
.PHONY: docker docker-dev verify cppcheck

docker:
	docker build -t spine .

docker-dev:
	docker build -f Dockerfile.dev -t spine-dev .

verify: docker-dev
	docker run --rm spine-dev

cppcheck: docker-dev
	docker run --rm -e VERIFY_CPPCHECK_ONLY=1 spine-dev

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/core -I$(top_builddir)

check_PROGRAMS =

if HAVE_CMOCKA
check_PROGRAMS += \
	tests/unit/test_util_strings \
	tests/unit/test_build_fixes \
	tests/unit/test_safety_fixes \
	tests/unit/test_linked \
	tests/unit/test_ping_icmp

# A small executable which speaks the subset of the PHP Script Server protocol
# needed by test_php_runtime. Keeping it as a real child covers the shipped
# pipe, spawn, command, response, shutdown and reap paths.
noinst_PROGRAMS = tests/unit/php_test_server
tests_unit_php_test_server_SOURCES = tests/unit/php_test_server.c

if HAVE_LD_WRAP
check_PROGRAMS += tests/unit/test_php_runtime
endif
endif

# test_util_strings pulls in common.h and the sources under test, so it needs
# the same libraries spine links against.  The other two are self-contained.
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
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_linked_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_ping_icmp_SOURCES = tests/unit/test_ping_icmp.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c \
	src/core/keywords.c error.c
tests_unit_test_ping_icmp_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_php_runtime_SOURCES = tests/unit/test_php_runtime.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_php_runtime_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_php_runtime_LDFLAGS = \
	-Wl,--wrap=posix_spawn -Wl,--wrap=dup -Wl,--wrap=fcntl \
	-Wl,--wrap=pthread_sigmask -Wl,--wrap=write \
	-Wl,--wrap=posix_spawnattr_setsigdefault -Wl,--wrap=posix_spawnattr_destroy
tests_unit_test_php_runtime_CPPFLAGS = $(AM_CPPFLAGS) \
	-DPHP_TEST_SERVER_PATH='"$(abs_builddir)/tests/unit/php_test_server"' \
	-DSPINE_PHP_RUNTIME_TESTING
tests_unit_test_php_runtime_DEPENDENCIES = tests/unit/php_test_server$(EXEEXT)

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)
TESTS = $(check_PROGRAMS) tests/regression/test_child_process_safety.sh
EXTRA_DIST += tests/regression/test_child_process_safety.sh
