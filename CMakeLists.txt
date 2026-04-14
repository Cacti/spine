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

include(CTest)
include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckLinkerFlag OPTIONAL)
include(CheckTypeSize)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(SPINE_BUILD_MAIN "Build the spine executable" ON)
option(ENABLE_WARNINGS "Enable compiler warnings" ON)
option(ENABLE_LCAP "Enable Linux capability checks" ON)

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
    src/platform/platform_process_posix.c
    src/platform/platform_process_win.c
    src/platform/platform_fd_posix.c
    src/platform/platform_fd_win.c
)

# Kept out of the shared spine_platform object because the POSIX
# implementation forwards into ping.c helpers, which drag in the full
# spine dependency chain (mysql, net-snmp, the poller). Unit tests
# that link only the platform layer must stay free of that chain.
set(SPINE_ICMP_SOURCES
    src/platform/platform_icmp_posix.c
    src/platform/platform_icmp_win.c
)

set(SPINE_CORE_SOURCES
    src/sql.c
    src/spine.c
    src/util.c
    src/snmp.c
    src/locks.c
    src/poller.c
    src/nft_popen.c
    src/php.c
    src/ping.c
    src/ping_validate.c
    src/ping_ipv6_scope.c
    src/keywords.c
    src/error.c
)

set(SPINE_TEST_NAMES env time process socket error fd dns)

if(ENABLE_WARNINGS)
    add_library(spine_build_options INTERFACE)
    if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        target_compile_options(spine_build_options INTERFACE
            -Wall
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
        target_link_options(spine_hardening INTERFACE -Wl,-z,relro -Wl,-z,now)
    endif()
endif()

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

set(STDC_HEADERS 1)
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

find_package(PkgConfig QUIET)

function(spine_require_mysql)
    if(TARGET spine_mysql)
        return()
    endif()

    set(_mysql_found FALSE)
    set(_mysql_include_dirs "")
    set(_mysql_libraries "")
    set(_mysql_link_options "")

    if(PkgConfig_FOUND)
        pkg_check_modules(MYSQL QUIET mysqlclient)
        if(NOT MYSQL_FOUND)
            pkg_check_modules(MYSQL QUIET mariadb)
        endif()

        if(MYSQL_FOUND)
            set(_mysql_found TRUE)
            set(_mysql_include_dirs "${MYSQL_INCLUDE_DIRS}")
            set(_mysql_libraries "${MYSQL_LIBRARIES}")
            set(_mysql_link_options "${MYSQL_LDFLAGS}")
        endif()
    endif()

    if(NOT _mysql_found)
        find_path(MYSQL_INCLUDE_DIR mysql.h
            PATHS
                /usr/include/mysql
                /usr/include/mariadb
                /usr/local/include/mysql
                /usr/local/include/mariadb
                /usr/local/mysql/include
                /opt/local/include/mysql
                /opt/local/include/mariadb
                /opt/homebrew/include/mysql
                /opt/homebrew/include/mariadb
                /usr/local/opt/mysql-client/include/mysql
                /opt/homebrew/opt/mysql-client/include/mysql
                /usr/local/opt/mariadb-connector-c/include/mariadb
                /opt/homebrew/opt/mariadb-connector-c/include/mariadb
                /opt/csw/include/mysql
                /opt/csw/include/mariadb
                /opt/freeware/include/mysql
                /opt/freeware/include/mariadb
                /opt/mysql/include
                /usr/pkg/include/mysql
                ${MINGW_PREFIX}/include/mariadb
                ${MINGW_PREFIX}/include/mysql
        )
        find_library(MYSQL_LIBRARY
            NAMES mysqlclient mariadbclient mariadb
            PATHS
                /usr/lib
                /usr/lib64
                /usr/lib/x86_64-linux-gnu
                /usr/local/lib
                /usr/local/lib/mysql
                /usr/local/mysql/lib
                /opt/local/lib
                /opt/homebrew/lib
                /usr/local/opt/mysql-client/lib
                /opt/homebrew/opt/mysql-client/lib
                /usr/local/opt/mariadb-connector-c/lib
                /opt/homebrew/opt/mariadb-connector-c/lib
                /opt/csw/lib
                /opt/freeware/lib
                /opt/mysql/lib
                /usr/pkg/lib
                ${MINGW_PREFIX}/lib
        )

        if(MYSQL_INCLUDE_DIR AND MYSQL_LIBRARY)
            set(_mysql_found TRUE)
            set(_mysql_include_dirs "${MYSQL_INCLUDE_DIR}")
            set(_mysql_libraries "${MYSQL_LIBRARY}")
        endif()
    endif()

    if(NOT _mysql_found)
        message(FATAL_ERROR
            "Cannot find MySQL/MariaDB client library. "
            "Install libmysqlclient-dev or libmariadb-dev "
            "(FreeBSD: mysql80-client or mariadb-connector-c), "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    add_library(spine_mysql INTERFACE)
    # SYSTEM silences -Wall/-Wextra noise from mysql client headers we do not
    # own and cannot patch.
    target_include_directories(spine_mysql SYSTEM INTERFACE ${_mysql_include_dirs})
    target_link_libraries(spine_mysql INTERFACE ${_mysql_libraries})
    if(_mysql_link_options)
        target_link_options(spine_mysql INTERFACE ${_mysql_link_options})
    endif()

    set(HAVE_MYSQL 1 PARENT_SCOPE)
endfunction()

function(spine_require_netsnmp)
    if(TARGET spine_netsnmp)
        return()
    endif()

    set(_netsnmp_found FALSE)
    set(_netsnmp_include_dirs "")
    set(_netsnmp_libraries "")
    set(_netsnmp_link_options "")

    if(PkgConfig_FOUND)
        pkg_check_modules(NETSNMP QUIET netsnmp)
        if(NETSNMP_FOUND)
            set(_netsnmp_found TRUE)
            set(_netsnmp_include_dirs "${NETSNMP_INCLUDE_DIRS}")
            set(_netsnmp_libraries "${NETSNMP_LIBRARIES}")
            # NETSNMP_LDFLAGS contains the same -l entries already captured in
            # NETSNMP_LIBRARIES; feeding both to the linker produces duplicate
            # library warnings on macOS. Keep only -L directives from LDFLAGS.
            set(_netsnmp_link_options "")
            foreach(_flag IN LISTS NETSNMP_LDFLAGS)
                if(_flag MATCHES "^-L")
                    list(APPEND _netsnmp_link_options "${_flag}")
                endif()
            endforeach()
        endif()
    endif()

    if(NOT _netsnmp_found)
        # Prefer Homebrew's net-snmp-config over the ancient Apple-shipped
        # /usr/bin/net-snmp-config, whose headers lack sc_get_auth_oid and
        # other modern symbols. Users can override by setting NETSNMP_CONFIG.
        find_program(NETSNMP_CONFIG net-snmp-config
            HINTS
                /opt/homebrew/opt/net-snmp/bin
                /usr/local/opt/net-snmp/bin
            NO_DEFAULT_PATH
        )
        if(NOT NETSNMP_CONFIG)
            find_program(NETSNMP_CONFIG net-snmp-config)
        endif()
        if(NETSNMP_CONFIG)
            execute_process(
                COMMAND ${NETSNMP_CONFIG} --cflags
                OUTPUT_VARIABLE NETSNMP_CFLAGS_RAW
                RESULT_VARIABLE _netsnmp_cflags_rc
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            if(NOT _netsnmp_cflags_rc EQUAL 0)
                message(FATAL_ERROR "net-snmp-config --cflags failed with code ${_netsnmp_cflags_rc}")
            endif()
            execute_process(
                COMMAND ${NETSNMP_CONFIG} --libs
                OUTPUT_VARIABLE NETSNMP_LIBS_RAW
                RESULT_VARIABLE _netsnmp_libs_rc
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            if(NOT _netsnmp_libs_rc EQUAL 0)
                message(FATAL_ERROR "net-snmp-config --libs failed with code ${_netsnmp_libs_rc}")
            endif()

            set(_netsnmp_found TRUE)
            separate_arguments(_snmp_cflags_list UNIX_COMMAND "${NETSNMP_CFLAGS_RAW}")
            foreach(_flag IN LISTS _snmp_cflags_list)
                if(_flag MATCHES "^-I(.*)")
                    list(APPEND _netsnmp_include_dirs "${CMAKE_MATCH_1}")
                endif()
            endforeach()

            separate_arguments(_snmp_libs_list UNIX_COMMAND "${NETSNMP_LIBS_RAW}")
            set(_expect_framework 0)
            foreach(_flag IN LISTS _snmp_libs_list)
                if(_expect_framework)
                    # Translate "-framework Foo" pairs into the absolute path
                    # of the Foo.framework. target_link_options deduplicates
                    # repeated "-framework" tokens when passed through an
                    # INTERFACE target, so a resolved path is the most reliable
                    # form for linking multiple frameworks.
                    if(APPLE)
                        find_library(_fw_${_flag} ${_flag})
                        if(_fw_${_flag})
                            list(APPEND _netsnmp_libraries "${_fw_${_flag}}")
                        endif()
                    endif()
                    set(_expect_framework 0)
                elseif(_flag STREQUAL "-framework")
                    set(_expect_framework 1)
                elseif(_flag MATCHES "^-l(.+)")
                    list(APPEND _netsnmp_libraries "${CMAKE_MATCH_1}")
                elseif(_flag MATCHES "^-L(.+)")
                    list(APPEND _netsnmp_link_options "${_flag}")
                else()
                    list(APPEND _netsnmp_link_options "${_flag}")
                endif()
            endforeach()
        else()
            find_path(NETSNMP_INCLUDE_DIR net-snmp/net-snmp-config.h
                PATHS
                    /usr/include
                    /usr/local/include
                    /opt/local/include
                    /opt/homebrew/include
                    /usr/local/opt/net-snmp/include
                    /opt/homebrew/opt/net-snmp/include
                    /opt/csw/include
                    /opt/freeware/include
                    /usr/pkg/include
                    /opt/net-snmp/include
                    ${MINGW_PREFIX}/include
            )
            find_library(NETSNMP_LIBRARY
                NAMES netsnmp
                PATHS
                    /usr/lib
                    /usr/lib64
                    /usr/local/lib
                    /opt/local/lib
                    /opt/homebrew/lib
                    /usr/local/opt/net-snmp/lib
                    /opt/homebrew/opt/net-snmp/lib
                    /opt/csw/lib
                    /opt/freeware/lib
                    /usr/pkg/lib
                    /opt/net-snmp/lib
                    ${MINGW_PREFIX}/lib
            )
            if(NETSNMP_INCLUDE_DIR AND NETSNMP_LIBRARY)
                set(_netsnmp_found TRUE)
                set(_netsnmp_include_dirs "${NETSNMP_INCLUDE_DIR}")
                set(_netsnmp_libraries "${NETSNMP_LIBRARY}")
            endif()
        endif()
    endif()

    if(NOT _netsnmp_found)
        message(FATAL_ERROR
            "Cannot find Net-SNMP library. "
            "Install libsnmp-dev or net-snmp-devel "
            "(FreeBSD: net-snmp), "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    add_library(spine_netsnmp INTERFACE)
    # SYSTEM silences -Wall/-Wextra noise from net-snmp headers (unused
    # parameter 'token', etc.) that upstream has not cleaned up.
    target_include_directories(spine_netsnmp SYSTEM INTERFACE ${_netsnmp_include_dirs})
    target_link_libraries(spine_netsnmp INTERFACE ${_netsnmp_libraries})
    if(_netsnmp_link_options)
        target_link_options(spine_netsnmp INTERFACE ${_netsnmp_link_options})
    endif()

    set(CMAKE_REQUIRED_INCLUDES "${_netsnmp_include_dirs}")
    check_c_source_compiles("
        #include <net-snmp/net-snmp-config.h>
        #include <net-snmp/utilities.h>
        #include <net-snmp/net-snmp-includes.h>
        #include <net-snmp/config_api.h>
        #include <net-snmp/mib_api.h>
        int main(void) {
            struct snmp_session s;
            snmp_sess_init(&s);
            s.localname = \"test\";
            return 0;
        }
    " HAVE_SNMP_LOCALNAME)
    unset(CMAKE_REQUIRED_INCLUDES)

    if(HAVE_SNMP_LOCALNAME)
        set(SNMP_LOCALNAME 1 PARENT_SCOPE)
    else()
        set(SNMP_LOCALNAME 0 PARENT_SCOPE)
    endif()
endfunction()

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
    target_compile_definitions(spine_platform PUBLIC _POSIX_C_SOURCE=200809L _DEFAULT_SOURCE=1)
    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_compile_definitions(spine_platform PUBLIC _DARWIN_C_SOURCE=1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
        target_compile_definitions(spine_platform PUBLIC _POSIX_PTHREAD_SEMANTICS=1 _XOPEN_SOURCE=700 __EXTENSIONS__=1)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
        target_compile_definitions(spine_platform PUBLIC _ALL_SOURCE=1 _XOPEN_SOURCE=700)
    endif()
    target_link_libraries(spine_platform PUBLIC m ${CMAKE_DL_LIBS})
    if(CAP_LIBRARY)
        target_link_libraries(spine_platform PUBLIC ${CAP_LIBRARY})
    endif()
endif()

function(spine_add_platform_test test_name)
    add_executable(test_platform_${test_name}
        tests/unit/test_platform_${test_name}.c
        $<TARGET_OBJECTS:spine_platform>
    )
    target_include_directories(test_platform_${test_name} PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/platform
        ${CMAKE_SOURCE_DIR}/third_party
    )
    target_link_libraries(test_platform_${test_name} PRIVATE Threads::Threads)
    if(TARGET spine_build_options)
        target_link_libraries(test_platform_${test_name} PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_platform_${test_name} PRIVATE spine_hardening)
    if(WIN32)
        target_link_libraries(test_platform_${test_name} PRIVATE ws2_32 iphlpapi advapi32)
    else()
        target_link_libraries(test_platform_${test_name} PRIVATE m ${CMAKE_DL_LIBS})
    endif()
    add_test(NAME platform_${test_name} COMMAND test_platform_${test_name})
endfunction()

if(SPINE_BUILD_MAIN)
    spine_require_mysql()
    spine_require_netsnmp()

    add_executable(spine
        ${SPINE_CORE_SOURCES}
        ${SPINE_ICMP_SOURCES}
        $<TARGET_OBJECTS:spine_platform>
    )
    target_include_directories(spine PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/platform
        ${CMAKE_SOURCE_DIR}/third_party
    )
    target_link_libraries(spine PRIVATE
        spine_platform
        spine_mysql
        spine_netsnmp
        Threads::Threads
    )
    if(TARGET spine_build_options)
        target_link_libraries(spine PRIVATE spine_build_options)
    endif()
    target_link_libraries(spine PRIVATE spine_hardening)
    if(HAVE_LIBCAP)
        target_compile_definitions(spine PRIVATE HAVE_LIBCAP=1)
    endif()
    if(OpenSSL_FOUND)
        target_link_libraries(spine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()

    install(TARGETS spine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES etc/spine.conf.dist DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
endif()

if(BUILD_TESTING)
    foreach(test_name IN LISTS SPINE_TEST_NAMES)
        spine_add_platform_test(${test_name})
    endforeach()

    # Ping validation: links against the standalone validator TU only.
    add_executable(test_ping_reply_validation
        tests/unit/test_ping_reply_validation.c
        src/ping_validate.c
    )
    target_include_directories(test_ping_reply_validation PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    if(TARGET spine_build_options)
        target_link_libraries(test_ping_reply_validation PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_ping_reply_validation PRIVATE spine_hardening)
    add_test(NAME ping_reply_validation COMMAND test_ping_reply_validation)

    # IPv6 scope resolver: POSIX only (Windows build compiles a no-op main).
    add_executable(test_ping_ipv6_scope
        tests/unit/test_ping_ipv6_scope.c
        src/ping_ipv6_scope.c
    )
    target_include_directories(test_ping_ipv6_scope PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests/unit
    )
    if(TARGET spine_build_options)
        target_link_libraries(test_ping_ipv6_scope PRIVATE spine_build_options)
    endif()
    target_link_libraries(test_ping_ipv6_scope PRIVATE spine_hardening)
    add_test(NAME ping_ipv6_scope COMMAND test_ping_ipv6_scope)
endif()

configure_file(
    ${CMAKE_SOURCE_DIR}/config/config.h.cmake.in
    ${CMAKE_BINARY_DIR}/config/config.h
    @ONLY
)
