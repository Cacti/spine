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

spine_shared_sources = sql.c util.c snmp.c src/core/locks.c poller.c \
	nft_popen.c php.c ping.c src/core/keywords.c error.c
spine_SOURCES = $(spine_shared_sources) spine.c

configdir = $(sysconfdir)
dist_config_DATA = spine.conf.dist

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
DISTCLEANFILES = spine.1

check_PROGRAMS = test_spine_regressions
dist_noinst_DATA = tests/fixtures/configuration.sql tests/fixtures/poller.sql tests/fixtures/snmpd.conf tests/fixtures/snmpv3-agent.conf tests/fixtures/snmpv3-users.conf
TESTS = $(check_PROGRAMS)
test_spine_regressions_SOURCES = $(spine_SOURCES) tests/test_spine_regressions.c tests/test_spine_contracts.c tests/test_spine_reindex_contracts.c tests/test_spine_snmpv3_contracts.c tests/test_spine_settings_contracts.c tests/test_spine_cli_contracts.c tests/test_spine_stream_contracts.c tests/test_spine_output_contracts.c tests/test_spine_privilege_contracts.c
# Link the real production translation units and globals, with a separate test
# entry point. Only spine.c maps its own entry point in the test build.
test_spine_regressions_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir) -DSPINE_TEST_PROGRAM_ENTRY

if HAVE_LINKER_WRAP
check_PROGRAMS += test_spine_faults
# Reuse the real renamed spine object for its production globals, avoiding
# another production main-renaming flag on the fault-test translation units.
test_spine_faults_SOURCES = $(spine_shared_sources) tests/test_spine_faults.c
test_spine_faults_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)
test_spine_faults_LDADD = test_spine_regressions-spine.$(OBJEXT)
test_spine_faults_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=strftime -Wl,--wrap=mysql_query -Wl,--wrap=mysql_ping -Wl,--wrap=mysql_errno \
 -Wl,--wrap=mysql_real_connect -Wl,--wrap=mysql_thread_id -Wl,--wrap=mysql_store_result \
 -Wl,--wrap=mysql_num_rows -Wl,--wrap=mysql_fetch_row -Wl,--wrap=mysql_free_result -Wl,--wrap=mysql_num_fields \
 -Wl,--wrap=pipe -Wl,--wrap=socketpair -Wl,--wrap=posix_spawn -Wl,--wrap=posix_spawnattr_setpgroup \
 -Wl,--wrap=malloc -Wl,--wrap=strdup \
 -Wl,--wrap=snmp_sess_open -Wl,--wrap=snmp_sess_close -Wl,--wrap=pthread_create \
 -Wl,--wrap=getuid -Wl,--wrap=geteuid -Wl,--wrap=getgid -Wl,--wrap=getegid \
 -Wl,--wrap=setuid -Wl,--wrap=setgid -Wl,--wrap=seteuid -Wl,--wrap=setegid -Wl,--wrap=socket
endif


# Headers are not referenced by any _SOURCES, so automake will not distribute
# them unless they are listed. Without this the release tarball builds nothing.
noinst_HEADERS = common.h error.h src/core/keywords.h src/core/locks.h \
	nft_popen.h php.h ping.h poller.h snmp.h spine.h spine_sem.h spine_types.h \
	sql.h uthash.h util.h

EXTRA_DIST = spine.1 spine.conf.dist \
	tests/README.md \
	tests/test-harness.sh \
	tests/integration/test_concurrency.sh \
	tests/integration/test_network_faults.sh

EXTRA_DIST += tests/tools/run_snmpv3.sh tests/tools/run_coverage.sh tests/tools/coverage_process_exit.h \
 tests/tools/verify_coverage.sh tests/tools/test_coverage_verifier.sh
.PHONY: coverage-source-list coverage-test-source-list
coverage-source-list:
	@printf '%s\n' $(spine_SOURCES)

coverage-test-source-list:
	@printf '%s\n' $(test_spine_regressions_SOURCES)

.PHONY: coverage-fault-source-list
coverage-fault-source-list:
	@printf '%s\n' $(test_spine_faults_SOURCES)
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

if HAVE_CMOCKA
check_PROGRAMS += \
	tests/unit/test_util_strings \
	tests/unit/test_build_fixes \
	tests/unit/test_safety_fixes \
	tests/unit/test_linked \
	tests/unit/test_classify_result \
	tests/unit/test_util_paths \
	tests/unit/test_snmpv3_session \
	tests/unit/test_ping_icmp \
	tests/unit/test_ping_timing \
	tests/unit/test_log_config

# A small executable which speaks the subset of the PHP Script Server protocol
# needed by test_php_runtime. Keeping it as a real child covers the shipped
# pipe, spawn, command, response, shutdown and reap paths.
noinst_PROGRAMS = tests/unit/php_test_server
tests_unit_php_test_server_SOURCES = tests/unit/php_test_server.c

if HAVE_LD_WRAP
check_PROGRAMS += tests/unit/test_php_runtime tests/unit/test_poll_host
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
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_linked_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# waitpid() failing with anything other than ECHILD/EINTR has no reachable
# real-syscall trigger (WNOHANG is always a valid options value), so covering
# nft_pclose()'s defensive "waitpid itself failed" path needs a wrapped call.
#
# The base assignment must stay unconditional: once a target defines its own
# _CPPFLAGS anywhere, automake stops falling back to AM_CPPFLAGS for it on
# every configuration, including ones where HAVE_LD_WRAP is false (e.g.
# macOS's linker doesn't support --wrap) - that dropped the -I flags spine.h
# needs to find locks.h there.
tests_unit_test_linked_CPPFLAGS = $(AM_CPPFLAGS)
if HAVE_LD_WRAP
tests_unit_test_linked_LDFLAGS = -Wl,--wrap=waitpid
tests_unit_test_linked_CPPFLAGS += -DSPINE_TEST_WRAP_WAITPID
endif

tests_unit_test_classify_result_SOURCES = tests/unit/test_classify_result.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_classify_result_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# includes util.c, so it needs the same libraries spine links against
tests_unit_test_util_paths_SOURCES = tests/unit/test_util_paths.c
tests_unit_test_util_paths_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_snmpv3_session_SOURCES = tests/unit/test_snmpv3_session.c tests/fuzz/stubs.c \
	sql.c util.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_snmpv3_session_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_ping_icmp_SOURCES = tests/unit/test_ping_icmp.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c \
	src/core/keywords.c error.c
tests_unit_test_ping_icmp_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# poll_host() against an in-memory database and SNMP agent: the wrapped
# calls are the ones poller.o makes into sql.o, snmp.o, ping.o and libmysql.
tests_unit_test_poll_host_SOURCES = tests/unit/test_poll_host.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_poll_host_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_poll_host_LDFLAGS = \
	-Wl,--wrap=db_query -Wl,--wrap=db_insert -Wl,--wrap=db_escape \
	-Wl,--wrap=db_get_connection -Wl,--wrap=db_release_connection \
	-Wl,--wrap=db_free_result -Wl,--wrap=mysql_num_rows -Wl,--wrap=mysql_fetch_row \
	-Wl,--wrap=snmp_host_init -Wl,--wrap=snmp_host_cleanup -Wl,--wrap=snmp_get_base \
	-Wl,--wrap=snmp_get -Wl,--wrap=snmp_get_allow_fail -Wl,--wrap=snmp_get_multi \
	-Wl,--wrap=ping_host

# Includes ping.c directly so its socket calls can be steered; see the file.
tests_unit_test_ping_timing_SOURCES = tests/unit/test_ping_timing.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c \
	src/core/keywords.c error.c
tests_unit_test_ping_timing_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_log_config_SOURCES = tests/unit/test_log_config.c tests/fuzz/stubs.c \
	sql.c util.c snmp.c src/core/locks.c poller.c nft_popen.c php.c ping.c \
	src/core/keywords.c error.c
tests_unit_test_log_config_LDADD   = $(CMOCKA_LIBS) $(LIBS)

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
TESTS += tests/regression/test_remote_push.sh tests/integration/test_alloc_failure.sh tests/regression/test_child_process_safety.sh tests/regression/test_setuid_privilege_drop.sh
TESTS_ENVIRONMENT = top_builddir='$(abs_top_builddir)'
EXTRA_DIST += tests/regression/test_remote_push.sh tests/integration/test_alloc_failure.sh tests/regression/test_child_process_safety.sh tests/regression/test_setuid_privilege_drop.sh

EXTRA_DIST += scripts/cppcheck/spine.cfg
