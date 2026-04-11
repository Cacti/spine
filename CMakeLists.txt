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
project(spine VERSION 1.3.0 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(SPINE_BUILD_MAIN "Build the spine executable" ON)

include(CheckIncludeFile)
include(CheckFunctionExists)
include(CheckTypeSize)
include(CTest)
include(GNUInstallDirs)

# --------------------------------------------------------------------------
# Configurable buffer / limit sizes (mirror autotools --with-* options)
# --------------------------------------------------------------------------
set(RESULTS_BUFFER 2048 CACHE STRING "Size of the spine results buffer")
set(MAX_SIMULTANEOUS_SCRIPTS 20 CACHE STRING "Maximum simultaneous spine scripts")
set(MAX_MYSQL_BUF_SIZE 131072 CACHE STRING "Maximum MySQL insert buffer size")

# --------------------------------------------------------------------------
# Optional build flags
# --------------------------------------------------------------------------
option(ENABLE_WARNINGS "Enable -Wall compiler warnings" ON)

if(ENABLE_WARNINGS)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(-Wall)
    elseif(MSVC)
        add_compile_options(/W3)
    endif()
endif()

# --------------------------------------------------------------------------
# Header checks
# --------------------------------------------------------------------------
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

# --------------------------------------------------------------------------
# Function checks
# --------------------------------------------------------------------------
check_function_exists(malloc        HAVE_MALLOC)
check_function_exists(calloc        HAVE_CALLOC)
check_function_exists(gettimeofday  HAVE_GETTIMEOFDAY)
check_function_exists(strerror      HAVE_STRERROR)
check_function_exists(strtoll       HAVE_STRTOLL)

# --------------------------------------------------------------------------
# Type checks
# --------------------------------------------------------------------------
check_type_size("unsigned long long" UNSIGNED_LONG_LONG)
check_type_size("long long"          LONG_LONG)
check_type_size("size_t"             SIZE_T)

if(HAVE_UNSIGNED_LONG_LONG)
    set(HAVE_UNSIGNED_LONG_LONG 1)
endif()
if(HAVE_LONG_LONG)
    set(HAVE_LONG_LONG 1)
endif()

# Assume standard C headers and time+sys/time coexistence on modern systems
set(STDC_HEADERS 1)
if(HAVE_SYS_TIME_H)
    set(TIME_WITH_SYS_TIME 1)
endif()

if(SPINE_BUILD_MAIN)
    # ----------------------------------------------------------------------
    # Dependencies: MySQL / MariaDB
    # ----------------------------------------------------------------------
    find_package(PkgConfig QUIET)

    set(MYSQL_FOUND FALSE)

    if(PkgConfig_FOUND)
        pkg_check_modules(MYSQL QUIET mysqlclient)
        if(NOT MYSQL_FOUND)
            pkg_check_modules(MYSQL QUIET mariadb)
        endif()
    endif()

    if(NOT MYSQL_FOUND)
        find_path(MYSQL_INCLUDE_DIR mysql.h
            PATHS
                /usr/include/mysql
                /usr/include/mariadb
                /usr/local/include/mysql
                /usr/local/include/mariadb
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
                /opt/mysql/lib
                /usr/pkg/lib
                ${MINGW_PREFIX}/lib
        )

        if(MYSQL_INCLUDE_DIR AND MYSQL_LIBRARY)
            set(MYSQL_FOUND TRUE)
            set(MYSQL_INCLUDE_DIRS ${MYSQL_INCLUDE_DIR})
            set(MYSQL_LIBRARIES ${MYSQL_LIBRARY})
        endif()
    endif()

    if(NOT MYSQL_FOUND)
        message(FATAL_ERROR
            "Cannot find MySQL/MariaDB client library. "
            "Install libmysqlclient-dev or libmariadb-dev, "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    set(HAVE_MYSQL 1)

    # ----------------------------------------------------------------------
    # Dependencies: Net-SNMP
    # ----------------------------------------------------------------------
    set(NETSNMP_FOUND FALSE)

    if(PkgConfig_FOUND)
        pkg_check_modules(NETSNMP QUIET netsnmp)
    endif()

    if(NOT NETSNMP_FOUND)
        find_program(NETSNMP_CONFIG net-snmp-config)
        if(NETSNMP_CONFIG)
            execute_process(
                COMMAND ${NETSNMP_CONFIG} --cflags
                OUTPUT_VARIABLE NETSNMP_CFLAGS_RAW
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            execute_process(
                COMMAND ${NETSNMP_CONFIG} --libs
                OUTPUT_VARIABLE NETSNMP_LIBS_RAW
                OUTPUT_STRIP_TRAILING_WHITESPACE
            )
            set(NETSNMP_FOUND TRUE)
            string(REPLACE " " ";" _snmp_cflags_list "${NETSNMP_CFLAGS_RAW}")
            set(NETSNMP_INCLUDE_DIRS "")
            foreach(_flag ${_snmp_cflags_list})
                if(_flag MATCHES "^-I(.*)")
                    list(APPEND NETSNMP_INCLUDE_DIRS "${CMAKE_MATCH_1}")
                endif()
            endforeach()
            separate_arguments(_snmp_libs_list UNIX_COMMAND "${NETSNMP_LIBS_RAW}")
            set(NETSNMP_LIBRARIES "")
            set(NETSNMP_LDFLAGS "")
            foreach(_flag ${_snmp_libs_list})
                if(_flag MATCHES "^-l(.*)")
                    list(APPEND NETSNMP_LIBRARIES "${CMAKE_MATCH_1}")
                elseif(_flag MATCHES "^-L(.*)")
                    list(APPEND NETSNMP_LDFLAGS "${_flag}")
                else()
                    list(APPEND NETSNMP_LDFLAGS "${_flag}")
                endif()
            endforeach()
        else()
            find_path(NETSNMP_INCLUDE_DIR net-snmp/net-snmp-config.h
                PATHS
                    /usr/include
                    /usr/local/include
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
                    /usr/pkg/lib
                    /opt/net-snmp/lib
                    ${MINGW_PREFIX}/lib
            )
            if(NETSNMP_INCLUDE_DIR AND NETSNMP_LIBRARY)
                set(NETSNMP_FOUND TRUE)
                set(NETSNMP_INCLUDE_DIRS ${NETSNMP_INCLUDE_DIR})
                set(NETSNMP_LIBRARIES ${NETSNMP_LIBRARY})
            endif()
        endif()
    endif()

    if(NOT NETSNMP_FOUND)
        message(FATAL_ERROR
            "Cannot find Net-SNMP library. "
            "Install libsnmp-dev or net-snmp-devel, "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        set(HAVE_OPENSSL 1)
    endif()

    find_package(Threads REQUIRED)
    if(CMAKE_USE_PTHREADS_INIT)
        set(HAVE_LIBPTHREAD 1)
    endif()

    if(NETSNMP_FOUND)
        include(CheckCSourceCompiles)
        set(CMAKE_REQUIRED_INCLUDES ${NETSNMP_INCLUDE_DIRS})
        check_c_source_compiles("
            #include <net-snmp/net-snmp-config.h>
            #include <net-snmp/utilities.h>
            #include <net-snmp/net-snmp-includes.h>
            #include <net-snmp/config_api.h>
            #include <net-snmp/mib_api.h>
            int main() {
                struct snmp_session s;
                snmp_sess_init(&s);
                s.localname = \"test\";
                return 0;
            }
        " HAVE_SNMP_LOCALNAME)
        if(HAVE_SNMP_LOCALNAME)
            set(SNMP_LOCALNAME 1)
        else()
            set(SNMP_LOCALNAME 0)
        endif()
    endif()
endif()

# --------------------------------------------------------------------------
# Generate config/config.h
# --------------------------------------------------------------------------
configure_file(
    ${CMAKE_SOURCE_DIR}/config/config.h.cmake.in
    ${CMAKE_BINARY_DIR}/config/config.h
    @ONLY
)

# --------------------------------------------------------------------------
# Build target
# --------------------------------------------------------------------------
if(SPINE_BUILD_MAIN)
    set(SPINE_SOURCES
        sql.c
        spine.c
        util.c
        snmp.c
        locks.c
        poller.c
        nft_popen.c
        php.c
        ping.c
        keywords.c
        error.c
        platform_common.c
        platform_posix.c
        platform_win.c
        platform_socket_posix.c
        platform_socket_win.c
        platform_error_posix.c
        platform_error_win.c
        platform_process_posix.c
        platform_process_win.c
        platform_fd_posix.c
        platform_fd_win.c
    )

    add_executable(spine ${SPINE_SOURCES})

    target_include_directories(spine PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
        ${MYSQL_INCLUDE_DIRS}
        ${NETSNMP_INCLUDE_DIRS}
    )

    target_link_libraries(spine PRIVATE
        ${MYSQL_LIBRARIES}
        ${NETSNMP_LIBRARIES}
        Threads::Threads
    )

    if(MYSQL_LDFLAGS)
        target_link_options(spine PRIVATE ${MYSQL_LDFLAGS})
    endif()
    if(NETSNMP_LDFLAGS)
        separate_arguments(_snmp_link_flags UNIX_COMMAND "${NETSNMP_LDFLAGS}")
        target_link_options(spine PRIVATE ${_snmp_link_flags})
    endif()

    if(OpenSSL_FOUND)
        target_link_libraries(spine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()

    if(WIN32)
        target_link_libraries(spine PRIVATE ws2_32 iphlpapi advapi32)
    else()
        target_link_libraries(spine PRIVATE m ${CMAKE_DL_LIBS})
    endif()

    install(TARGETS spine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES spine.conf.dist DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
endif()

if(BUILD_TESTING)
    set(PLATFORM_TEST_SOURCES
        platform_common.c
        platform_posix.c
        platform_win.c
        platform_socket_posix.c
        platform_socket_win.c
        platform_error_posix.c
        platform_error_win.c
        platform_process_posix.c
        platform_process_win.c
        platform_fd_posix.c
        platform_fd_win.c
    )

    foreach(test_name IN ITEMS env time process socket error fd)
        add_executable(test_platform_${test_name}
            tests/unit/test_platform_${test_name}.c
            ${PLATFORM_TEST_SOURCES}
        )
        target_include_directories(test_platform_${test_name} PRIVATE
            ${CMAKE_SOURCE_DIR}
        )
        if(WIN32)
            target_link_libraries(test_platform_${test_name} PRIVATE ws2_32)
        endif()
        add_test(NAME platform_${test_name} COMMAND test_platform_${test_name})
    endforeach()
endif()
