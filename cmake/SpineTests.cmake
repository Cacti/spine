include_guard(GLOBAL)

# All focused tests include common.h directly; expose the generated config
# header to every test target, including minimal standalone fixtures.
include_directories(${CMAKE_BINARY_DIR})

function(spine_add_platform_test test_name)
  add_executable(test_platform_${test_name} tests/unit/test_platform_${test_name}.c)
  target_include_directories(
    test_platform_${test_name}
    PRIVATE ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform
            ${CMAKE_SOURCE_DIR}/third_party)
  target_link_libraries(
    test_platform_${test_name}
    PRIVATE spine_platform_test_support
            Threads::Threads
            spine_hardening)
  if(TARGET spine_build_options)
    target_link_libraries(test_platform_${test_name} PRIVATE spine_build_options)
  endif()
  if(WIN32)
    target_link_libraries(test_platform_${test_name} PRIVATE ws2_32 iphlpapi advapi32)
  else()
    target_link_libraries(test_platform_${test_name} PRIVATE m ${CMAKE_DL_LIBS} spine_posix_features)
    if(SPINE_HAVE_LIBSECCOMP)
      target_link_libraries(test_platform_${test_name} PRIVATE ${SECCOMP_LIB})
    endif()
  endif()
  add_test(NAME platform_${test_name} COMMAND test_platform_${test_name})
endfunction()

function(spine_add_tests)
  set(SPINE_UTIL_SUPPORT_SOURCES
      src/config_repository.c
      src/config_builder.c
      src/config_apply.c
      src/log_formatter.c
      src/log_sink.c
      src/systemd_notify.c)

  foreach(test_name IN LISTS SPINE_TEST_NAMES)
    spine_add_platform_test(${test_name})
  endforeach()

  # Ping validation: links against the standalone validator TU only.
  add_executable(test_ping_reply_validation tests/unit/test_ping_reply_validation.c src/ping_validate.c)
  target_include_directories(test_ping_reply_validation PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_ping_reply_validation PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_ping_reply_validation PRIVATE spine_hardening)
  add_test(NAME ping_reply_validation COMMAND test_ping_reply_validation)

  # IPv6 scope resolver: POSIX only (Windows build compiles a no-op main).
  add_executable(test_ping_ipv6_scope tests/unit/test_ping_ipv6_scope.c src/ping_ipv6_scope.c)
  target_include_directories(test_ping_ipv6_scope PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_ping_ipv6_scope PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_ping_ipv6_scope PRIVATE spine_hardening)
  add_test(NAME ping_ipv6_scope COMMAND test_ping_ipv6_scope)

  # systemd_notify: idempotency + null-safety. Builds against the wrapper TU
  # with or without libsystemd; when libsystemd is linked, sd_notify no-ops
  # because NOTIFY_SOCKET is unset in the test harness.
  add_executable(test_systemd_notify tests/unit/test_systemd_notify.c src/systemd_notify.c)
  target_include_directories(test_systemd_notify PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_systemd_notify PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_systemd_notify PRIVATE spine_hardening)
  if(SPINE_HAVE_LIBSYSTEMD)
    target_compile_definitions(test_systemd_notify PRIVATE HAVE_LIBSYSTEMD=1)
    target_include_directories(test_systemd_notify SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIRS})
    target_link_libraries(test_systemd_notify PRIVATE ${SYSTEMD_LIBRARIES})
    if(SYSTEMD_LDFLAGS_OTHER)
      target_link_options(test_systemd_notify PRIVATE ${SYSTEMD_LDFLAGS_OTHER})
    endif()
  endif()
  add_test(NAME systemd_notify COMMAND test_systemd_notify)

  # Sandbox: NULL-safe unveil_paths() plus forked restrict() smoke test.
  add_executable(test_sandbox tests/unit/test_sandbox.c)
  target_include_directories(
    test_sandbox
    PRIVATE ${CMAKE_BINARY_DIR}
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/platform
            ${CMAKE_SOURCE_DIR}/tests/unit
            ${CMAKE_SOURCE_DIR}/third_party)
  target_link_libraries(test_sandbox PRIVATE spine_platform_test_support Threads::Threads spine_hardening)
  if(TARGET spine_build_options)
    target_link_libraries(test_sandbox PRIVATE spine_build_options)
  endif()
  if(WIN32)
    # spine_platform pulls in WSA* and IP Helper symbols; tests linking it
    # on MinGW/MSVC need the same import libs the main binary gets.
    target_link_libraries(test_sandbox PRIVATE iphlpapi ws2_32)
  else()
    target_link_libraries(test_sandbox PRIVATE m ${CMAKE_DL_LIBS} spine_posix_features)
    if(SPINE_HAVE_LIBSECCOMP)
      target_link_libraries(test_sandbox PRIVATE ${SECCOMP_LIB})
    endif()
  endif()
  add_test(NAME sandbox COMMAND test_sandbox)

  # json_log: free-standing JSON escaper. The function has no set/spine_log
  # dependencies so we recompile it from a tiny helper TU to avoid pulling
  # the whole util.c + mysql + net-snmp chain just for a pure-string test.
  add_executable(test_json_log tests/unit/test_json_log.c tests/unit/json_escape_tu.c)
  target_include_directories(test_json_log PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_json_log PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_json_log PRIVATE spine_hardening)
  add_test(NAME json_log COMMAND test_json_log)

  # icmp_win_loader: race the IP Helper one-shot loader across N threads.
  if(WIN32)
    add_executable(test_icmp_win_loader tests/unit/test_icmp_win_loader.c ${SPINE_ICMP_SOURCES})
    target_include_directories(
      test_icmp_win_loader
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit
              ${CMAKE_SOURCE_DIR}/third_party)
    target_link_libraries(
      test_icmp_win_loader
      PRIVATE spine_platform_test_support
              Threads::Threads
              ws2_32
              iphlpapi
              advapi32
              spine_hardening)
    if(TARGET spine_build_options)
      target_link_libraries(test_icmp_win_loader PRIVATE spine_build_options)
    endif()
    add_test(NAME icmp_win_loader COMMAND test_icmp_win_loader)
  endif()

  # env_scrub: exercise spine_build_child_env's LD_*/DYLD_*/BASH_ENV scrub
  # on a poisoned environ.
  if(NOT WIN32)
    add_executable(test_env_scrub tests/unit/test_env_scrub.c tests/unit/build_child_env_tu.c)
    target_include_directories(test_env_scrub PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
    if(TARGET spine_build_options)
      target_link_libraries(test_env_scrub PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_env_scrub PRIVATE spine_hardening)
    add_test(NAME env_scrub COMMAND test_env_scrub)
  endif()

  add_executable(test_async_coverage tests/unit/test_async_coverage.c tests/unit/test_spine_stubs.c)
  target_include_directories(test_async_coverage PRIVATE 
    ${CMAKE_BINARY_DIR} 
    ${CMAKE_BINARY_DIR}/config 
    ${CMAKE_SOURCE_DIR} 
    ${CMAKE_SOURCE_DIR}/src 
    ${CMAKE_SOURCE_DIR}/tests/unit 
    ${CMAKE_SOURCE_DIR}/third_party
    ${LIBUV_INCLUDE_DIRS}
    ${CARES_INCLUDE_DIRS}
  )
  if(TARGET spine_build_options)
    target_link_libraries(test_async_coverage PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_async_coverage PRIVATE spine_platform spine_hardening spine_netsnmp spine_mysql)
  target_sources(test_async_coverage PRIVATE
    src/async_exec.c src/async_snmp.c src/async_mysql.c src/async_batch.c src/async_dns.c src/async_php.c src/telemetry.c
    src/task_scheduler.c src/task_governor.c src/task_executor.c
    src/config_repository.c src/config_builder.c src/config_apply.c
    src/log_formatter.c src/log_sink.c src/systemd_notify.c
    # Configuration repository/build helpers call the shared utility
    # implementations (strpos, get_cacti_version, ...).  Include util.c so
    # this focused executable links the same production code paths it tests.
    src/util.c
  )

  add_executable(test_spine_audit tests/unit/test_spine_audit.c src/spine_audit.c)
  if(LIBUV_FOUND)
    target_link_libraries(test_async_coverage PRIVATE ${LIBUV_LIBRARIES})
  endif()
  if(CARES_FOUND)
    target_link_libraries(test_async_coverage PRIVATE ${CARES_LIBRARIES})
    target_include_directories(test_async_coverage PRIVATE ${CARES_INCLUDE_DIRS})
  endif()
  if(OpenSSL_FOUND)
    target_link_libraries(test_async_coverage PRIVATE OpenSSL::SSL OpenSSL::Crypto)
  endif()
  add_test(NAME async_coverage COMMAND test_async_coverage)

  target_include_directories(test_spine_audit PRIVATE ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_spine_audit PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_spine_audit PRIVATE spine_hardening)
  add_test(NAME spine_audit COMMAND test_spine_audit)

  # Circuit breaker, dump_config, check_mode, and dry_run all depend on
  # the spine config struct and/or MySQL. Gate them behind the same main
  # build so we only wire them when mysql + net-snmp were discovered.
  if(SPINE_BUILD_MAIN)
    add_executable(test_circuit_breaker tests/unit/test_circuit_breaker.c src/circuit_breaker.c src/spine_audit.c)
    target_include_directories(
      test_circuit_breaker
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit
              ${CMAKE_SOURCE_DIR}/third_party)
    target_link_libraries(test_circuit_breaker PRIVATE spine_platform spine_mysql spine_netsnmp Threads::Threads)
    if(OpenSSL_FOUND)
      target_link_libraries(test_circuit_breaker PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(TARGET spine_build_options)
      target_link_libraries(test_circuit_breaker PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_circuit_breaker PRIVATE spine_hardening)
    if(SPINE_HAVE_LIBAUDIT)
      target_compile_definitions(test_circuit_breaker PRIVATE HAVE_LIBAUDIT=1)
      target_include_directories(test_circuit_breaker SYSTEM PRIVATE ${AUDIT_INCLUDE_DIR})
      target_link_libraries(test_circuit_breaker PRIVATE ${AUDIT_LIB})
    endif()
    add_test(NAME circuit_breaker COMMAND test_circuit_breaker)

    add_executable(
      test_dump_config
      tests/unit/test_dump_config.c
      tests/unit/test_spine_stubs.c
      src/util.c
      ${SPINE_UTIL_SUPPORT_SOURCES})
    target_include_directories(
      test_dump_config
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit
              ${CMAKE_SOURCE_DIR}/third_party)
    target_link_libraries(test_dump_config PRIVATE spine_platform spine_mysql spine_netsnmp Threads::Threads)
    if(OpenSSL_FOUND)
      target_link_libraries(test_dump_config PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(TARGET spine_build_options)
      target_link_libraries(test_dump_config PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_dump_config PRIVATE spine_hardening)
    add_test(NAME dump_config COMMAND test_dump_config)

    add_executable(
      test_check_mode
      tests/unit/test_check_mode.c
      tests/unit/test_spine_stubs.c
      src/util.c
      ${SPINE_UTIL_SUPPORT_SOURCES})
    target_include_directories(
      test_check_mode
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit
              ${CMAKE_SOURCE_DIR}/third_party)
    target_link_libraries(test_check_mode PRIVATE spine_platform spine_mysql spine_netsnmp Threads::Threads)
    if(OpenSSL_FOUND)
      target_link_libraries(test_check_mode PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(TARGET spine_build_options)
      target_link_libraries(test_check_mode PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_check_mode PRIVATE spine_hardening)
    add_test(NAME check_mode COMMAND test_check_mode)
    # 3s connect timeout + a touch of slack so cold CI runners do not
    # flake when the route takes an extra second to time out.
    set_tests_properties(check_mode PROPERTIES TIMEOUT 30)

    add_executable(test_dry_run tests/unit/test_dry_run.c tests/unit/test_sql_stubs.c src/sql.c src/db_session.c)
    target_include_directories(
      test_dry_run
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit
              ${CMAKE_SOURCE_DIR}/third_party)
    target_link_libraries(test_dry_run PRIVATE spine_platform spine_mysql spine_netsnmp Threads::Threads)
    if(OpenSSL_FOUND)
      target_link_libraries(test_dry_run PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(TARGET spine_build_options)
      target_link_libraries(test_dry_run PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_dry_run PRIVATE spine_hardening)
    add_test(NAME dry_run COMMAND test_dry_run)
  endif()

  # Windows-only Job Object lifecycle test.
  if(WIN32)
    add_executable(test_job_object tests/unit/test_job_object.c)
    target_include_directories(
      test_job_object
      PRIVATE ${CMAKE_BINARY_DIR}
              ${CMAKE_SOURCE_DIR}
              ${CMAKE_SOURCE_DIR}/src
              ${CMAKE_SOURCE_DIR}/src/platform
              ${CMAKE_SOURCE_DIR}/tests/unit)
    target_link_libraries(test_job_object PRIVATE spine_platform_test_support Threads::Threads ws2_32 iphlpapi advapi32)
    if(TARGET spine_build_options)
      target_link_libraries(test_job_object PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_job_object PRIVATE spine_hardening)
    add_test(NAME job_object COMMAND test_job_object)
  endif()

  # BSD-only arc4random divergence test.
  if(CMAKE_SYSTEM_NAME MATCHES "^(FreeBSD|OpenBSD|NetBSD|DragonFly)$")
    add_executable(test_arc4random tests/unit/test_arc4random.c)
    target_include_directories(test_arc4random PRIVATE ${CMAKE_SOURCE_DIR}/tests/unit)
    if(TARGET spine_build_options)
      target_link_libraries(test_arc4random PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_arc4random PRIVATE spine_hardening)
    add_test(NAME arc4random COMMAND test_arc4random)
  endif()

  add_executable(test_scheduler tests/unit/test_scheduler.c src/task_scheduler.c src/task_governor.c src/task_executor.c)
  if(TARGET spine_build_options)
    target_link_libraries(test_scheduler PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_scheduler PRIVATE spine_platform)
  if(LIBUV_FOUND)
    target_link_libraries(test_scheduler PRIVATE ${LIBUV_LIBRARIES})
  endif()
  add_test(NAME scheduler COMMAND test_scheduler)

  # spine_redact_args: flag allowlist, truncation, null-safety coverage.
  # util.c pulls in mysql.h and net-snmp.h transitively via spine.h, so
  # the test needs those INTERFACE targets even though the code under
  # test never touches a real handle.
  spine_require_mysql()
  spine_require_netsnmp()
  add_executable(test_spine_redact_args tests/unit/test_spine_redact_args.c
                 src/util.c tests/unit/test_spine_stubs.c
                 src/config_repository.c src/config_builder.c src/config_apply.c
                 src/log_formatter.c src/log_sink.c src/systemd_notify.c
                 src/platform/platform_process_posix.c src/platform/platform_posix.c)
  target_include_directories(test_spine_redact_args PRIVATE
      ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_spine_redact_args PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_spine_redact_args PRIVATE
      spine_hardening spine_mysql spine_netsnmp Threads::Threads m)
  add_test(NAME spine_redact_args COMMAND test_spine_redact_args)

  # CB age-reap: mock-clock driven. test_spine_stubs provides config_t set
  # and the spine_audit stubs required by circuit_breaker.c. libaudit is
  # an optional link when HAVE_LIBAUDIT is set.
  add_executable(test_spine_cb_reap tests/unit/test_spine_cb_reap.c
                 src/circuit_breaker.c src/spine_audit.c
                 tests/unit/test_spine_stubs.c)
  target_include_directories(test_spine_cb_reap PRIVATE
      ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_spine_cb_reap PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_spine_cb_reap PRIVATE
      spine_hardening spine_mysql spine_netsnmp Threads::Threads)
  if(SPINE_HAVE_LIBAUDIT)
    target_compile_definitions(test_spine_cb_reap PRIVATE HAVE_LIBAUDIT=1)
    target_include_directories(test_spine_cb_reap SYSTEM PRIVATE ${AUDIT_INCLUDE_DIR})
    target_link_libraries(test_spine_cb_reap PRIVATE ${AUDIT_LIB})
  endif()
  add_test(NAME spine_cb_reap COMMAND test_spine_cb_reap)

  # async_mysql shutdown fence: API-only, no real uv/mysql handle opened.
  add_executable(test_async_mysql_shutdown tests/unit/test_async_mysql_shutdown.c
                 src/async_mysql.c tests/unit/test_spine_stubs.c)
  target_include_directories(test_async_mysql_shutdown PRIVATE
      ${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_async_mysql_shutdown PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_async_mysql_shutdown PRIVATE
      spine_hardening spine_mysql Threads::Threads)
  if(LIBUV_FOUND)
    target_link_libraries(test_async_mysql_shutdown PRIVATE ${LIBUV_LIBRARIES})
  endif()
  add_test(NAME async_mysql_shutdown COMMAND test_async_mysql_shutdown)

  # async_exec + spine.c invariants: source-scan asserts that the argv
  # tokenizer stays out and the flush-before-fence shutdown order holds.
  # SPINE_SOURCE_ROOT pins the file paths at configure time so the test
  # works from any ctest CWD.
  add_executable(test_async_exec_shell tests/unit/test_async_exec_shell.c)
  target_compile_definitions(test_async_exec_shell PRIVATE
      SPINE_SOURCE_ROOT="${CMAKE_SOURCE_DIR}")
  target_include_directories(test_async_exec_shell PRIVATE
      ${CMAKE_SOURCE_DIR}/tests/unit)
  if(TARGET spine_build_options)
    target_link_libraries(test_async_exec_shell PRIVATE spine_build_options)
  endif()
  target_link_libraries(test_async_exec_shell PRIVATE spine_hardening)
  add_test(NAME async_exec_shell COMMAND test_async_exec_shell)

endfunction()
