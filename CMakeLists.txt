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
# | http://www.cacti.net/                                                   |
# +-------------------------------------------------------------------------+

cmake_minimum_required(VERSION 3.15)

# Source of truth for the project version is the VERSION file at the repo root.
# git describe is consulted opportunistically so CI artifacts carry a meaningful
# tag-based version without requiring a VERSION bump for every release candidate.
file(STRINGS "${CMAKE_SOURCE_DIR}/VERSION" _spine_version_file LIMIT_COUNT 1)
string(STRIP "${_spine_version_file}" _spine_version_file)
set(_spine_version "${_spine_version_file}")

find_package(Git QUIET)
if(Git_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE _spine_git_describe
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _spine_git_rc
    )
    if(_spine_git_rc EQUAL 0 AND _spine_git_describe MATCHES "^v?([0-9]+\\.[0-9]+\\.[0-9]+)")
        set(_spine_version "${CMAKE_MATCH_1}")
    endif()
endif()

project(spine VERSION ${_spine_version} LANGUAGES C)

# Reproducible-builds epoch. Honour SOURCE_DATE_EPOCH (Debian, Fedora, Nix,
# Gentoo, Arch all set this when building reproducibly) so generated headers
# and install-tree metadata don't carry wall-clock stamps. Falls back to the
# configure-time UTC timestamp when the environment variable is unset.
if(DEFINED ENV{SOURCE_DATE_EPOCH})
    set(SPINE_BUILD_EPOCH "$ENV{SOURCE_DATE_EPOCH}")
else()
    string(TIMESTAMP SPINE_BUILD_EPOCH "%s" UTC)
endif()

include(CTest)
include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckLinkerFlag OPTIONAL)
include(CheckTypeSize)
include(cmake/SpineDependencies.cmake)
include(cmake/SpinePackaging.cmake)
include(cmake/SpineTests.cmake)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(SPINE_BUILD_MAIN "Build the spine executable" ON)
option(ENABLE_WARNINGS "Enable compiler warnings" ON)
option(ENABLE_LCAP "Enable Linux capability checks" ON)
option(WITH_SYSTEMD "Enable systemd sd_notify integration (Linux only)" ON)
option(WITH_SECCOMP "Enable Linux seccomp-bpf syscall allowlist (Linux only)" ON)
option(WITH_LANDLOCK "Enable Linux Landlock filesystem confinement (Linux only)" ON)
option(WITH_AUDIT "Enable Linux audit subsystem integration (Linux only)" ON)

set(RESULTS_BUFFER 2048 CACHE STRING "Size of the spine results buffer")
set(MAX_SIMULTANEOUS_SCRIPTS 20 CACHE STRING "Maximum simultaneous spine scripts")
set(MAX_MYSQL_BUF_SIZE 131072 CACHE STRING "Maximum MySQL insert buffer size")

set(SPINE_PLATFORM_SOURCES
    src/platform/platform_common.c
    src/platform/platform_posix.c
    src/platform/platform_win.c
    src/platform/platform_socket_posix.c
    src/platform/platform_socket_win.c
    src/platform/platform_error_posix.c
    src/platform/platform_error_win.c
    src/platform/platform_win_error.c
    src/platform/platform_process_posix.c
    src/platform/platform_process_win.c
    src/platform/platform_fd_posix.c
    src/platform/platform_fd_win.c
    src/platform/platform_sandbox_posix.c
    src/platform/platform_sandbox_openbsd.c
    src/platform/platform_sandbox_linux.c
    src/platform/platform_sandbox_freebsd.c
    src/platform/platform_sandbox_win.c
)

# Kept out of the shared spine_platform object because the POSIX
# implementation forwards into ping.c helpers, which drag in the full
# spine dependency chain (mysql, net-snmp, the poller). Unit tests
# that link only the platform layer must stay free of that chain.
if(WIN32)
    set(SPINE_ICMP_SOURCES src/platform/platform_icmp_win.c)
else()
    set(SPINE_ICMP_SOURCES src/platform/platform_icmp_posix.c)
endif()

set(SPINE_CORE_SOURCES
    src/sql.c
    src/spine.c
    src/util.c
    src/snmp.c
    src/runtime_context.c
    src/availability_policy.c
    src/config_repository.c
    src/config_builder.c
    src/config_apply.c
    src/db_session.c
    src/snmp_session_factory.c
    src/snmp_client.c
    src/snmp_result_parser.c
    src/log_formatter.c
    src/log_sink.c
    src/host_polling_service.c
    src/host_polling_stages.c
    src/host_status_service.c
    src/results_flush_service.c
    src/script_server_service.c
    src/locks.c
    src/poller.c
    src/nft_popen.c
    src/async_exec.c
    src/async_snmp.c
    src/async_mysql.c
    src/async_batch.c
    src/async_php.c
    src/async_dns.c
    src/telemetry.c
    src/task_governor.c
    src/task_scheduler.c
    src/task_executor.c
    src/php.c
    src/ping.c
    src/ping_validate.c
    src/ping_ipv6_scope.c
    src/keywords.c
    src/error.c
    src/systemd_notify.c
    src/circuit_breaker.c
    src/spine_audit.c
)

set(SPINE_TEST_NAMES env time process socket error fd dns thread_name)

if(ENABLE_WARNINGS)
    add_library(spine_build_options INTERFACE)
    if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        target_compile_options(spine_build_options INTERFACE
            -g -O0
            -Wextra
            -Wformat
            -Werror=implicit-function-declaration
            -Werror=incompatible-pointer-types
            -Wvla
            -Wshadow
        )
    elseif(MSVC)
        target_compile_options(spine_build_options INTERFACE /W3)
    endif()
endif()

# Hardening flags. Applied to spine and every platform test target. Kept
# behind CheckCCompilerFlag because older toolchains reject some options.
# clang on macOS accepts -fstack-clash-protection silently in the flag probe
# but then emits "-Wunused-command-line-argument" at compile time, so the
# probe runs with -Werror to force a hard failure on unsupported flags.
add_library(spine_hardening INTERFACE)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(spine_hardening INTERFACE
        -D_FORTIFY_SOURCE=2
        -fstack-protector-strong
        -Wformat-security
        -fPIE
    )
    set(_spine_prev_required_flags "${CMAKE_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror=unused-command-line-argument")
    check_c_compiler_flag(-fstack-clash-protection SPINE_HAS_STACK_CLASH)
    set(CMAKE_REQUIRED_FLAGS "${_spine_prev_required_flags}")
    if(SPINE_HAS_STACK_CLASH)
        target_compile_options(spine_hardening INTERFACE -fstack-clash-protection)
    endif()
    # AppleClang enables PIE by default and warns that -pie is unused, so
    # skip it on macOS. On Linux and other ELF platforms we still request it
    # explicitly to avoid depending on distro default config.
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_options(spine_hardening INTERFACE -pie)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_options(spine_hardening INTERFACE
            -Wl,-z,relro
            -Wl,-z,now
            -Wl,-z,noexecstack
            -Wl,-z,separate-code
        )
    endif()

    # Zero-init every automatic variable at function entry. Available in
    # gcc 12+ and clang 16+. Closes the class of uninitialised-read bugs
    # that commit 7116f3d fixed one site at a time (flogmessage before
    # strftime). Probe with -Werror so an older toolchain produces a
    # hard failure rather than a silent -Wunused-command-line-argument.
    set(_spine_prev_required_flags "${CMAKE_REQUIRED_FLAGS}")
    set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -Werror=unused-command-line-argument")
    check_c_compiler_flag(-ftrivial-auto-var-init=zero SPINE_HAS_AUTO_INIT)
    set(CMAKE_REQUIRED_FLAGS "${_spine_prev_required_flags}")
    if(SPINE_HAS_AUTO_INIT)
        target_compile_options(spine_hardening INTERFACE -ftrivial-auto-var-init=zero)
    endif()
endif()

check_include_file(sys/sdt.h          HAVE_SYS_SDT_H)
check_include_file(sys/socket.h       HAVE_SYS_SOCKET_H)
check_include_file(sys/select.h       HAVE_SYS_SELECT_H)
check_include_file(sys/wait.h         HAVE_SYS_WAIT_H)
check_include_file(sys/time.h         HAVE_SYS_TIME_H)
check_include_file(netinet/in_systm.h HAVE_NETINET_IN_SYSTM_H)
check_include_file(netinet/in.h       HAVE_NETINET_IN_H)
check_include_file(netinet/ip.h       HAVE_NETINET_IP_H)
check_include_file(netinet/ip_icmp.h  HAVE_NETINET_IP_ICMP_H)
check_include_file(stdint.h           HAVE_STDINT_H)
check_include_file(unistd.h           HAVE_UNISTD_H)

check_function_exists(malloc        HAVE_MALLOC)
check_function_exists(calloc        HAVE_CALLOC)
check_function_exists(gettimeofday  HAVE_GETTIMEOFDAY)
check_function_exists(strerror      HAVE_STRERROR)
check_function_exists(strtoll       HAVE_STRTOLL)

check_type_size("unsigned long long" UNSIGNED_LONG_LONG)
check_type_size("long long" LONG_LONG)
check_type_size("size_t" SIZE_T)

if(HAVE_UNSIGNED_LONG_LONG)
    set(HAVE_UNSIGNED_LONG_LONG 1)
endif()
if(HAVE_LONG_LONG)
    set(HAVE_LONG_LONG 1)
endif()

if(HAVE_SYS_TIME_H)
    set(TIME_WITH_SYS_TIME 1)
endif()

set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    set(HAVE_LIBPTHREAD 1)
endif()

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    set(HAVE_OPENSSL 1)
endif()
if(SPINE_HAVE_CARES)
    set(HAVE_CARES 1)
endif()

if(ENABLE_LCAP AND NOT WIN32)
    find_library(CAP_LIBRARY NAMES cap)
    if(CAP_LIBRARY)
        set(HAVE_LCAP 1)
        # Linux-only capability drop helper in ping.c needs sys/capability.h.
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            set(HAVE_LIBCAP 1)
        endif()
    endif()
endif()

add_library(spine_platform OBJECT ${SPINE_PLATFORM_SOURCES})
target_include_directories(spine_platform PUBLIC
    ${CMAKE_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/platform
    ${CMAKE_SOURCE_DIR}/third_party
)
target_link_libraries(spine_platform PUBLIC Threads::Threads)
if(TARGET spine_build_options)
    target_link_libraries(spine_platform PUBLIC spine_build_options)
endif()
target_link_libraries(spine_platform PUBLIC spine_hardening)
if(WIN32)
    target_link_libraries(spine_platform PUBLIC ws2_32 iphlpapi advapi32)
else()
    # Feature-test macros must be visible to every translation unit that
    # includes platform.h, including unit tests that pull spine_platform
    # via $<TARGET_OBJECTS:>. PUBLIC defs on an OBJECT library only
    # propagate when the consumer LINKS spine_platform, so factor them
    # into an INTERFACE library that every test can link without dragging
    # in the object files.
    #
    # OpenBSD is the one platform where _POSIX_C_SOURCE actively breaks
    # things: its <sys/cdefs.h> forces __BSD_VISIBLE=0 when POSIX mode is
    # strict, which then hides u_int (used in <netinet/ip.h>) and pledge
    # / unveil. Let its libc defaults apply and rely on __BSD_VISIBLE=1
    # below.
    add_library(spine_posix_features INTERFACE)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        target_compile_definitions(spine_posix_features INTERFACE _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE=1)
        target_compile_definitions(spine_platform PUBLIC _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE=1)
    endif()
    # Linux GNU libc gates pthread_setname_np, pipe2, getrandom, strerror_r's
    # GNU variant, and similar extensions behind _GNU_SOURCE. Per-TU #defines
    # only survive as long as every consumer remembers them, and the tests
    # that pull spine_platform's object files into standalone binaries
    # bypass any source-level gate. Centralize the macro here so the feature
    # surface is identical across spine_platform and every test target.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_compile_definitions(spine_posix_features INTERFACE _GNU_SOURCE=1)
        target_compile_definitions(spine_platform PUBLIC _GNU_SOURCE=1)
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(spine_posix_features INTERFACE _DARWIN_C_SOURCE=1)
        target_compile_definitions(spine_platform PUBLIC _DARWIN_C_SOURCE=1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        # Solaris / illumos hides socket and BSD-flavoured APIs behind these.
        # libsocket and libnsl carry getaddrinfo, socket(2), inet_ntop, etc.
        target_compile_definitions(spine_posix_features INTERFACE _POSIX_PTHREAD_SEMANTICS=1 _XOPEN_SOURCE=700 __EXTENSIONS__=1)
        target_compile_definitions(spine_platform PUBLIC _POSIX_PTHREAD_SEMANTICS=1 _XOPEN_SOURCE=700 __EXTENSIONS__=1)
        target_link_libraries(spine_platform PUBLIC socket nsl)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
        # AIX shared objects need runtime linking to resolve cross-library
        # symbols the same way ELF platforms do; without -brtl the loader
        # rejects unresolved refs at exec time.
        target_compile_definitions(spine_posix_features INTERFACE _ALL_SOURCE=1 _XOPEN_SOURCE=700)
        target_compile_definitions(spine_platform PUBLIC _ALL_SOURCE=1 _XOPEN_SOURCE=700)
        target_link_options(spine_platform PUBLIC -Wl,-brtl)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
        # OpenBSD's <sys/cdefs.h> treats any of _POSIX_C_SOURCE /
        # _XOPEN_SOURCE / _ANSI_SOURCE as a hard signal to force
        # __BSD_VISIBLE=0. That hides pledge/unveil/u_int even with a
        # user -D__BSD_VISIBLE=1 override. The cleanest fix is to let
        # libc defaults apply and only pin __BSD_VISIBLE on the sandbox
        # TU itself (see platform_sandbox_openbsd.c).
        target_compile_definitions(spine_posix_features INTERFACE __BSD_VISIBLE=1)
        target_compile_definitions(spine_platform PUBLIC __BSD_VISIBLE=1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR
           CMAKE_SYSTEM_NAME STREQUAL "DragonFly")
        # FreeBSD / NetBSD / DragonFly honor __BSD_VISIBLE=1 alongside
        # _POSIX_C_SOURCE and expose XSI helpers under _XOPEN_SOURCE=700.
        # FreeBSD 14 is Tier 1; NetBSD 10 and DragonFly 6 are Tier 3.
        target_compile_definitions(spine_posix_features INTERFACE
            __BSD_VISIBLE=1
            _XOPEN_SOURCE=700)
        target_compile_definitions(spine_platform PUBLIC
            __BSD_VISIBLE=1
            _XOPEN_SOURCE=700)
    endif()
    target_link_libraries(spine_platform PUBLIC m ${CMAKE_DL_LIBS})
    if(CAP_LIBRARY)
        target_link_libraries(spine_platform PUBLIC ${CAP_LIBRARY})
    endif()
    if(SPINE_HAVE_LIBSECCOMP)
        target_compile_definitions(spine_platform PUBLIC HAVE_LIBSECCOMP=1)
        target_include_directories(spine_platform PUBLIC ${SECCOMP_INCLUDE_DIR})
        target_link_libraries(spine_platform PUBLIC ${SECCOMP_LIB})
    endif()
    if(SPINE_HAVE_LANDLOCK)
        target_compile_definitions(spine_platform PUBLIC HAVE_LANDLOCK=1)
    endif()
    if(SPINE_HAVE_LIBAUDIT)
        target_compile_definitions(spine_platform PUBLIC HAVE_LIBAUDIT=1)
        target_include_directories(spine_platform PUBLIC ${AUDIT_INCLUDE_DIR})
        target_link_libraries(spine_platform PUBLIC ${AUDIT_LIB})
    # c-ares linkage
    if(SPINE_HAVE_CARES)
        target_compile_definitions(spine_platform PUBLIC HAVE_CARES=1)
        target_include_directories(spine_platform PUBLIC ${CARES_INCLUDE_DIRS})
        target_link_libraries(spine_platform PUBLIC ${CARES_LIBRARIES})
    endif()

    # PCRE2 linkage
    if(HAVE_PCRE2)
        target_compile_definitions(spine_platform PUBLIC HAVE_PCRE2=1)
        target_include_directories(spine_platform PUBLIC ${PCRE2_INCLUDE_DIRS})
        target_link_libraries(spine_platform PUBLIC ${PCRE2_LIBRARIES})
    endif()
    endif()
    target_compile_definitions(spine_platform PUBLIC HAVE_LIBUV=1)
    if(LIBUV_FOUND)
        target_include_directories(spine_platform PUBLIC ${LIBUV_INCLUDE_DIRS})
        target_link_libraries(spine_platform PUBLIC ${LIBUV_LIBRARIES})
    else()
        target_include_directories(spine_platform PUBLIC ${LIBUV_INCLUDE_DIR})
        target_link_libraries(spine_platform PUBLIC ${LIBUV_LIBRARY})
    endif()

endif()

add_library(spine_platform_test_support STATIC $<TARGET_OBJECTS:spine_platform>)
target_link_libraries(spine_platform_test_support PUBLIC spine_platform)

if(SPINE_BUILD_MAIN)
    spine_require_mysql()
    spine_require_netsnmp()

    add_executable(spine
        ${SPINE_CORE_SOURCES}
    )
    target_include_directories(spine PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_BINARY_DIR}/config
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/platform
        ${CMAKE_SOURCE_DIR}/third_party
        ${LIBUV_INCLUDE_DIRS}
        ${CARES_INCLUDE_DIRS}
    )
    target_link_libraries(spine PRIVATE
        spine_platform
        spine_mysql
        spine_netsnmp
        spine_hardening
        Threads::Threads
    )

    if(LIBUV_FOUND)
        target_link_libraries(spine PRIVATE ${LIBUV_LIBRARIES})
    endif()

    if(SPINE_HAVE_CARES)
        target_link_libraries(spine PRIVATE ${CARES_LIBRARIES})
    endif()

    if(HAVE_PCRE2)
        target_link_libraries(spine PRIVATE ${PCRE2_LIBRARIES})
    endif()

    # Performance: Link high-performance allocator if available
    if(MIMALLOC_FOUND)
        target_link_libraries(spine PRIVATE ${MIMALLOC_LIBRARIES})
        target_include_directories(spine PRIVATE ${MIMALLOC_INCLUDE_DIRS})
    elseif(JEMALLOC_FOUND)
        target_link_libraries(spine PRIVATE ${JEMALLOC_LIBRARIES})
        target_include_directories(spine PRIVATE ${JEMALLOC_INCLUDE_DIRS})
    endif()

    if(TARGET spine_build_options)
        target_link_libraries(spine PRIVATE spine_build_options)
    endif()
    target_link_libraries(spine PRIVATE spine_hardening)
    if(HAVE_LIBCAP)
        target_compile_definitions(spine PRIVATE HAVE_LIBCAP=1)
    endif()
    if(HAVE_SYS_SDT_H)
        target_compile_definitions(spine PRIVATE HAVE_SYS_SDT_H=1)
    endif()
    if(OpenSSL_FOUND)
        target_link_libraries(spine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()
    if(SPINE_HAVE_LIBSYSTEMD)
        target_compile_definitions(spine PRIVATE HAVE_LIBSYSTEMD=1)
        target_include_directories(spine SYSTEM PRIVATE ${SYSTEMD_INCLUDE_DIRS})
        target_link_libraries(spine PRIVATE ${SYSTEMD_LIBRARIES})
        if(SYSTEMD_LDFLAGS_OTHER)
            target_link_options(spine PRIVATE ${SYSTEMD_LDFLAGS_OTHER})
        endif()
    endif()
    if(SPINE_HAVE_LIBAUDIT)
        target_compile_definitions(spine PRIVATE HAVE_LIBAUDIT=1)
        target_include_directories(spine SYSTEM PRIVATE ${AUDIT_INCLUDE_DIR})
        target_link_libraries(spine PRIVATE ${AUDIT_LIB})
    endif()

    install(TARGETS spine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES etc/spine.conf.dist DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
    spine_install_runtime_assets()
endif()

spine_configure_cpack()
include(CPack)

if(BUILD_TESTING)
    spine_add_tests()
endif()

# When SPINE_BUILD_MAIN is OFF we never call spine_require_netsnmp() so the
# SNMP_LOCALNAME substitution would be empty and produce a malformed
# "#define SNMP_LOCALNAME " in config.h. Default to 0 so the feature macro
# always has a well-formed integer value.
if(NOT DEFINED SNMP_LOCALNAME)
    set(SNMP_LOCALNAME 0)
endif()

find_program(BASH_EXECUTABLE bash)
if(BASH_EXECUTABLE)
    add_custom_target(preflight
        COMMAND ${BASH_EXECUTABLE} ${CMAKE_SOURCE_DIR}/scripts/preflight.sh
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        USES_TERMINAL
    )
endif()

configure_file(
    ${CMAKE_SOURCE_DIR}/config/config.h.cmake.in
    ${CMAKE_BINARY_DIR}/config/config.h
    @ONLY
)
