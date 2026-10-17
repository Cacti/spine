# SPDX-FileCopyrightText: 2004-2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This code is designed, written, and maintained by the Cacti Group. See
# CONTRIBUTORS.md for developer information.
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

spine_support_sources = src/app/buffer.c \
	src/platform/clock.c \
	src/platform/socket.c \
	src/platform/thread.c \
	src/platform/descriptor.c \
	src/config/text.c \
	src/config/validate.c \
	src/log/debug.c \
	src/log/sanitize.c \
	src/script/escape.c \
	src/config/settings.c src/config/options.c src/config/file.c \
	src/log/log.c src/log/json.c src/poller/result.c \
	src/platform/privileges.c src/poller/regex.c
spine_database_sources = src/database/sql.c \
	src/database/connection.c src/database/upsert.c src/database/tls.c src/database/lease.c \
	src/database/pool.c src/database/transfer.c \
	src/database/cacti_query.c src/database/persistence.c
spine_snmp_sources = src/snmp/requests.c src/snmp/response.c \
	src/snmp/session.c
spine_ping_sources = src/poller/availability.c \
	src/ping/icmp_shared.c \
	src/ping/icmp4.c \
	src/ping/icmp6.c \
	src/ping/udp.c src/ping/tcp.c \
	src/ping/address.c
spine_poller_sources = src/poller/poller.c \
	src/script/external.c src/poller/host.c src/poller/reindex.c src/poller/items.c src/poller/system.c

spine_php_sources = src/script/protocol.c src/script/read.c src/script/server.c
spine_process_sources = src/process/nft_popen.c src/process/fd.c src/process/resource.c

spine_shared_sources = $(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) \
	$(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) src/config/keywords.c src/app/signals.c
spine_runtime_sources = $(spine_shared_sources) src/platform/worker_set.c src/app/runtime.c src/app/cli.c src/app/startup.c src/poller/workers.c
spine_SOURCES = $(spine_runtime_sources) src/app/main.c

configdir = $(sysconfdir)
dist_config_DATA = etc/spine.conf.dist

# Seed a live config on first install without ever overwriting an existing one.
install-data-hook:
	if [ ! -f "$(DESTDIR)$(configdir)/spine.conf" ]; then \
		$(INSTALL_DATA) "$(srcdir)/etc/spine.conf.dist" "$(DESTDIR)$(configdir)/spine.conf"; \
	fi

# Mirror image of the hook above: only remove spine.conf if it was never
# customized (still identical to the .dist it was seeded from), so a real
# uninstall never discards a live config, while distcheck's install/uninstall
# symmetry check still passes against its untouched sandbox copy.
uninstall-hook:
	if cmp -s "$(DESTDIR)$(configdir)/spine.conf" "$(srcdir)/etc/spine.conf.dist" 2>/dev/null; then \
		rm -f "$(DESTDIR)$(configdir)/spine.conf"; \
	fi

bin_PROGRAMS = spine
noinst_PROGRAMS = tests/support/resource_fixture
noinst_PROGRAMS += tests/contracts/test_database_destinations
tests_contracts_test_database_destinations_SOURCES = $(spine_runtime_sources) tests/contracts/test_database_destinations.c
tests_support_resource_fixture_SOURCES = tests/support/resource_fixture.c

man_MANS = docs/man/spine.1

check_PROGRAMS = test_spine_regressions
dist_noinst_DATA = tests/fixtures/configuration.sql tests/fixtures/poller.sql tests/fixtures/snmpd.conf tests/fixtures/snmpv3-agent.conf tests/fixtures/snmpv3-users.conf
TESTS = $(check_PROGRAMS)
test_spine_regressions_SOURCES = $(spine_runtime_sources) tests/regression/test_spine_regressions.c tests/contracts/test_spine_contracts.c tests/contracts/test_spine_reindex_contracts.c tests/contracts/test_spine_snmpv3_contracts.c tests/contracts/test_spine_settings_contracts.c tests/contracts/test_spine_cli_contracts.c tests/contracts/test_spine_stream_contracts.c tests/contracts/test_spine_output_contracts.c tests/contracts/test_spine_privilege_contracts.c
test_spine_regressions_SOURCES += tests/contracts/test_execution_policy.c
test_spine_regressions_SOURCES += tests/contracts/test_spine_tls_contracts.c
# Link the real production translation units and globals, with a separate test
# entry point. Production and regression binaries share the runtime objects.

if HAVE_LINKER_WRAP
check_PROGRAMS += test_spine_faults
# Link the same runtime implementation with a separate fault-test entry point.
test_spine_faults_SOURCES = $(spine_runtime_sources) tests/regression/test_spine_faults.c
test_spine_faults_LDFLAGS = $(AM_LDFLAGS) -Wl,--wrap=write -Wl,--wrap=mysql_init -Wl,--wrap=mysql_get_ssl_cipher \
 -Wl,--wrap=pthread_mutex_lock -Wl,--wrap=spine_worker_set_init -Wl,--wrap=spine_worker_set_destroy -Wl,--wrap=spine_worker_set_reap \
 -Wl,--wrap=strftime -Wl,--wrap=mysql_query -Wl,--wrap=mysql_ping -Wl,--wrap=mysql_errno \
 -Wl,--wrap=mysql_real_connect -Wl,--wrap=mysql_thread_id -Wl,--wrap=mysql_store_result \
 -Wl,--wrap=mysql_num_rows -Wl,--wrap=mysql_fetch_row -Wl,--wrap=mysql_free_result -Wl,--wrap=mysql_num_fields \
 -Wl,--wrap=pipe -Wl,--wrap=socketpair -Wl,--wrap=posix_spawn -Wl,--wrap=posix_spawnattr_setpgroup \
 -Wl,--wrap=malloc -Wl,--wrap=strdup \
 -Wl,--wrap=snmp_sess_open -Wl,--wrap=snmp_sess_close -Wl,--wrap=pthread_create -Wl,--wrap=pthread_attr_setstacksize \
 -Wl,--wrap=getuid -Wl,--wrap=geteuid -Wl,--wrap=getgid -Wl,--wrap=getegid \
 -Wl,--wrap=setuid -Wl,--wrap=setgid -Wl,--wrap=seteuid -Wl,--wrap=setegid -Wl,--wrap=socket
endif


# Headers are not referenced by any _SOURCES, so automake will not distribute
# them unless they are listed. Without this the release tarball builds nothing.
noinst_HEADERS = src/internal/common.h src/app/signals.h src/config/keywords.h src/platform/locks.h \
	src/process/resource.h \
	src/process/nft_popen.h src/script/server.h src/ping/ping.h src/poller/poller.h \
	src/snmp/snmp.h src/app/spine.h src/platform/spine_sem.h src/internal/spine_types.h \
	src/database/sql.h vendor/uthash/uthash.h src/internal/util.h
noinst_HEADERS += src/database/lease.h src/platform/worker_set.h

EXTRA_DIST = docs/man/spine.1 etc/spine.conf.dist \
	CONTRIBUTORS.md docs/licensing.md LICENSES/LicenseRef-Xenadyne.txt LICENSES/LicenseRef-Xenadyne-Header.txt \
	LICENSES/BSD-1-Clause.txt LICENSES/GPL-2.0-or-later.txt LICENSES/LGPL-2.1-or-later.txt LICENSES/LGPL-2.1-only.txt \
	tests/README.md \
	tests/support/test-harness.sh \
	tests/integration/test_concurrency.sh \
	tests/integration/test_network_faults.sh

EXTRA_DIST += tests/integration/test_memory_soak.sh
EXTRA_DIST += tests/integration/test_destination_upserts.sh tests/snmpv3/docker-compose.policy.yml \
	tests/snmpv3/Dockerfile.policy tests/snmpv3/Dockerfile.policy.dockerignore

EXTRA_DIST += tests/tools/run_snmpv3.sh tests/tools/run_coverage.sh tests/tools/coverage_process_exit.h \
 tests/tools/verify_coverage.sh tests/tools/test_coverage_verifier.sh \
 tests/tools/normalize_entry_coverage.py tests/tools/test_entry_coverage.py
.PHONY: coverage-source-list coverage-test-source-list
coverage-source-list:
	@printf '%s\n' $(spine_SOURCES)

coverage-test-source-list:
	@printf '%s\n' $(test_spine_regressions_SOURCES)

.PHONY: coverage-fault-source-list coverage-object-list
coverage-fault-source-list:
	@printf '%s\n' $(test_spine_faults_SOURCES)

# Production and linked tests share runtime objects. Report real object names.
coverage-object-list:
	@printf '%s\n' $(spine_OBJECTS) $(test_spine_regressions_OBJECTS) $(test_spine_faults_OBJECTS) | LC_ALL=C sort -u

# The cmocka suites exercise shipped code, including socket/error paths via
# syscall interception. Keep their measured producers separate from the
# unmodified production-linked regression/fault producers above.
.PHONY: coverage-unit-program-list coverage-unit-object-list
coverage-unit-program-list:
	@printf '%s\n' $(filter tests/unit/%,$(check_PROGRAMS))

.PHONY: coverage-helper-program-list coverage-helper-object-list
coverage-helper-program-list:
	@printf '%s\n' tests/support/php_test_server$(EXEEXT) tests/support/resource_fixture$(EXEEXT)
coverage-helper-object-list:
	@printf '%s\n' $(tests_support_php_test_server_OBJECTS) $(tests_support_resource_fixture_OBJECTS)

# spine_runtime.c contains only test globals and generates no executable
# coverage profile. All production sources remain in coverage-object-list.
coverage-unit-object-list:
	@printf '%s\n' $(filter-out tests/support/spine_runtime.o tests/support/%-spine_runtime.o, \
	 $(foreach program,$(filter tests/unit/%,$(check_PROGRAMS)),$($(subst /,_,$(program))_OBJECTS))) | LC_ALL=C sort -u
# Docker targets — require Dockerfile and docker/dev.Dockerfile (from PR #401)
.PHONY: docker docker-dev verify cppcheck

docker:
	docker build -t spine .

docker-dev:
	docker build -f docker/dev.Dockerfile -t spine-dev .

verify: docker-dev
	docker run --rm spine-dev

cppcheck: docker-dev
	docker run --rm -e VERIFY_CPPCHECK_ONLY=1 spine-dev

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src \
	-I$(top_srcdir)/vendor/uthash -I$(top_builddir)

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
	tests/unit/test_log_config \
	tests/unit/test_resource_policy \
	tests/unit/test_external_policy \
	tests/unit/test_worker_set \
	tests/unit/test_db_lease \
	tests/unit/test_tls_policy

# A small executable which speaks the subset of the PHP Script Server protocol
# needed by test_php_runtime. Keeping it as a real child covers the shipped
# pipe, spawn, command, response, shutdown and reap paths.
noinst_PROGRAMS += tests/support/php_test_server
tests_support_php_test_server_SOURCES = tests/support/php_test_server.c

if HAVE_LD_WRAP
check_PROGRAMS += tests/unit/test_php_runtime tests/unit/test_poll_host
endif
endif

# test_util_strings pulls in common.h and the sources under test, so it needs
# the same libraries spine links against.  The others are self-contained.
tests_unit_test_util_strings_SOURCES = tests/unit/test_util_strings.c src/log/json.c
tests_unit_test_util_strings_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_build_fixes_SOURCES  = tests/unit/test_build_fixes.c
tests_unit_test_build_fixes_LDADD    = $(CMOCKA_LIBS)

tests_unit_test_safety_fixes_SOURCES = tests/unit/test_safety_fixes.c
tests_unit_test_safety_fixes_LDADD   = $(CMOCKA_LIBS)

# test_linked exercises the shipped objects rather than a copy of the logic.
# Everything except src/app/runtime.c is linked as built; tests/support/spine_runtime.c supplies the
# globals that src/app/runtime.c would define.
tests_unit_test_linked_SOURCES = tests/unit/test_linked.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
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

tests_unit_test_classify_result_SOURCES = tests/unit/test_classify_result.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_classify_result_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# Includes production helpers, so it needs the same libraries as Spine
tests_unit_test_util_paths_SOURCES = tests/unit/test_util_paths.c src/log/json.c
tests_unit_test_util_paths_LDADD   = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_resource_policy_SOURCES = tests/unit/test_resource_policy.c
tests_unit_test_resource_policy_LDADD = $(CMOCKA_LIBS)
tests_unit_test_external_policy_SOURCES = tests/unit/test_external_policy.c tests/support/spine_runtime.c \
	src/database/sql.c src/database/connection.c src/database/upsert.c src/database/tls.c src/database/lease.c src/database/pool.c \
	src/database/transfer.c src/database/cacti_query.c $(spine_support_sources) $(spine_snmp_sources) \
	src/platform/locks.c src/poller/poller.c src/poller/host.c src/poller/reindex.c \
	src/poller/items.c src/poller/system.c $(spine_process_sources) $(spine_php_sources) \
	$(spine_ping_sources) src/config/keywords.c src/app/signals.c
tests_unit_test_external_policy_LDADD = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_snmpv3_session_SOURCES = tests/unit/test_snmpv3_session.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_snmpv3_session_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_ping_icmp_SOURCES = tests/unit/test_ping_icmp.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_ping_icmp_LDADD   = $(CMOCKA_LIBS) $(LIBS)

# poll_host() against an in-memory database and SNMP agent: the wrapped
# calls are the ones poller.o makes into sql.o, snmp.o, ping.o and libmysql.
tests_unit_test_poll_host_SOURCES = tests/unit/test_poll_host.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_poll_host_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_poll_host_LDFLAGS = \
	-Wl,--wrap=db_query -Wl,--wrap=db_insert -Wl,--wrap=db_escape \
	-Wl,--wrap=db_acquire_lease -Wl,--wrap=db_release_lease \
	-Wl,--wrap=db_free_result -Wl,--wrap=mysql_num_rows -Wl,--wrap=mysql_fetch_row \
	-Wl,--wrap=snmp_host_init -Wl,--wrap=snmp_host_cleanup -Wl,--wrap=snmp_get_base \
	-Wl,--wrap=snmp_get -Wl,--wrap=snmp_get_allow_fail -Wl,--wrap=snmp_get_multi \
	-Wl,--wrap=ping_host

# Includes src/poller/availability.c directly so its socket calls can be steered; see the file.
tests_unit_test_ping_timing_SOURCES = tests/unit/test_ping_timing.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_ping_timing_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_log_config_SOURCES = tests/unit/test_log_config.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_log_config_LDADD   = $(CMOCKA_LIBS) $(LIBS)

tests_unit_test_worker_set_SOURCES = tests/unit/test_worker_set.c src/platform/worker_set.c
tests_unit_test_worker_set_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_worker_set_CPPFLAGS = $(AM_CPPFLAGS)
if HAVE_LINKER_WRAP
tests_unit_test_worker_set_CPPFLAGS += -DSPINE_WORKER_TEST_WRAP
tests_unit_test_worker_set_LDFLAGS = -Wl,--wrap=calloc -Wl,--wrap=pthread_mutex_init \
	-Wl,--wrap=pthread_mutex_destroy -Wl,--wrap=pthread_create -Wl,--wrap=pthread_join \
	-Wl,--wrap=pthread_attr_getdetachstate
endif

tests_unit_test_db_lease_SOURCES = tests/unit/test_db_lease.c src/database/lease.c
tests_unit_test_db_lease_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_db_lease_CPPFLAGS = $(AM_CPPFLAGS)
tests_unit_test_tls_policy_SOURCES = tests/unit/test_tls_policy.c
tests_unit_test_tls_policy_LDADD = $(CMOCKA_LIBS) $(LIBS)
if HAVE_LINKER_WRAP
tests_unit_test_db_lease_CPPFLAGS += -DSPINE_LEASE_TEST_WRAP
tests_unit_test_db_lease_LDFLAGS = -Wl,--wrap=calloc -Wl,--wrap=pthread_mutex_init -Wl,--wrap=pthread_mutex_destroy
endif

tests_unit_test_php_runtime_SOURCES = tests/unit/test_php_runtime.c tests/support/spine_runtime.c \
	$(spine_database_sources) $(spine_support_sources) $(spine_snmp_sources) src/platform/locks.c $(spine_poller_sources) $(spine_process_sources) $(spine_php_sources) $(spine_ping_sources) \
	src/config/keywords.c src/app/signals.c
tests_unit_test_php_runtime_LDADD = $(CMOCKA_LIBS) $(LIBS)
tests_unit_test_php_runtime_LDFLAGS = \
	-Wl,--wrap=posix_spawn -Wl,--wrap=dup -Wl,--wrap=fcntl \
	-Wl,--wrap=write \
	-Wl,--wrap=posix_spawnattr_setsigdefault -Wl,--wrap=posix_spawnattr_destroy
tests_unit_test_php_runtime_CPPFLAGS = $(AM_CPPFLAGS) \
	-DPHP_TEST_SERVER_PATH='"$(abs_builddir)/tests/support/php_test_server"' \
	-DSPINE_PHP_RUNTIME_TESTING
tests_unit_test_php_runtime_DEPENDENCIES = tests/support/php_test_server$(EXEEXT)

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER = $(SHELL)
TESTS += tests/regression/test_remote_push.sh tests/integration/test_alloc_failure.sh tests/regression/test_child_process_safety.sh tests/regression/test_setuid_privilege_drop.sh
TESTS_ENVIRONMENT = top_builddir='$(abs_top_builddir)'
EXTRA_DIST += tests/regression/test_remote_push.sh tests/integration/test_alloc_failure.sh tests/regression/test_child_process_safety.sh tests/regression/test_setuid_privilege_drop.sh

EXTRA_DIST += tests/fixtures/c17_develop_behavior_baseline.json

EXTRA_DIST += scripts/debug.sh scripts/package.sh

TESTS += tests/regression/test_helper_scripts.sh
EXTRA_DIST += tests/regression/test_helper_scripts.sh

noinst_HEADERS += src/config/settings_internal.h src/ping/ping_internal.h src/app/cli_internal.h

noinst_HEADERS += src/poller/poller_internal.h src/app/startup_internal.h

noinst_HEADERS += src/script/server_internal.h

noinst_HEADERS += src/process/process_internal.h

EXTRA_DIST += docs/architecture/source-modules.md


noinst_HEADERS += src/app/buffer.h \
	src/app/runtime.h \
	src/config/model.h \
	src/config/state.h \
	src/config/text.h \
	src/config/validate.h \
	src/internal/constants.h \
	src/log/debug.h \
	src/log/log.h \
	src/log/sanitize.h \
	src/platform/clock.h \
	src/platform/descriptor.h \
	src/platform/socket.h \
	src/platform/thread.h \
	src/poller/result.h \
	src/script/escape.h \
	src/snmp/response.h

noinst_HEADERS += src/database/cacti_query.h src/database/persistence.h

EXTRA_DIST += tests/tools/test_configure_contracts.sh
EXTRA_DIST += tests/tools/test_clang_tidy_gate.py

EXTRA_DIST += scripts/cppcheck/spine.cfg
TESTS += tests/tools/test_nightly_suites.sh
EXTRA_DIST += tests/tools/test_nightly_suites.sh .github/scripts/verify-nightly-suites.sh
EXTRA_DIST += tests/tools/verify_changed_coverage.py tests/tools/test_changed_coverage.py

EXTRA_DIST += tests/tools/test_json_encoder.py

EXTRA_DIST += tests/tools/run_database_tls.sh tests/tools/ownership-coverage-sources.txt

EXTRA_DIST += tests/tools/benchmark_builds.py \
	tests/tools/build_benchmark_pair.sh \
	tests/tools/test_benchmark_record.py \
	tests/tools/verify_benchmark_record.py \
	docs/benchmarks/README.md \
	docs/benchmarks/results/2026-10-11-default-logging/README.md \
	docs/benchmarks/results/2026-10-11-default-logging/build-settings.txt \
	docs/benchmarks/results/2026-10-11-default-logging/builds.sha256 \
	docs/benchmarks/results/2026-10-11-default-logging/compiler.txt \
	docs/benchmarks/results/2026-10-11-default-logging/cpu-quota.txt \
	docs/benchmarks/results/2026-10-11-default-logging/cycles.csv \
	docs/benchmarks/results/2026-10-11-default-logging/dependencies.txt \
	docs/benchmarks/results/2026-10-11-default-logging/metadata.json \
	docs/benchmarks/results/2026-10-11-default-logging/revisions.txt \
	docs/benchmarks/results/2026-10-11-default-logging/summary.json
EXTRA_DIST += docs/platforms.md

TESTS += tests/tools/test_memory_soak_fit.sh
EXTRA_DIST += tests/tools/test_memory_soak_fit.sh tests/tools/memory_soak_fit.awk
TESTS += tests/tools/test_licensing.sh
EXTRA_DIST += tests/tools/test_licensing.sh tests/tools/check_licensing.py
