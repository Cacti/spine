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

include(CTest)
include(GNUInstallDirs)
include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(SPINE_BUILD_MAIN "Build the spine executable" ON)
option(ENABLE_WARNINGS "Enable compiler warnings" ON)
option(ENABLE_LCAP "Enable Linux capability checks" ON)

set(RESULTS_BUFFER 2048 CACHE STRING "Size of the spine results buffer")
set(MAX_SIMULTANEOUS_SCRIPTS 20 CACHE STRING "Maximum simultaneous spine scripts")
set(MAX_MYSQL_BUF_SIZE 131072 CACHE STRING "Maximum MySQL insert buffer size")

set(SPINE_PLATFORM_SOURCES
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

set(SPINE_CORE_SOURCES
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
)

set(SPINE_TEST_NAMES env time process socket error fd)

if(ENABLE_WARNINGS)
    add_library(spine_build_options INTERFACE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(spine_build_options INTERFACE -Wall)
    elseif(MSVC)
        target_compile_options(spine_build_options INTERFACE /W3)
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
            set(_mysql_found TRUE)
            set(_mysql_include_dirs "${MYSQL_INCLUDE_DIR}")
            set(_mysql_libraries "${MYSQL_LIBRARY}")
        endif()
    endif()

    if(NOT _mysql_found)
        message(FATAL_ERROR
            "Cannot find MySQL/MariaDB client library. "
            "Install libmysqlclient-dev or libmariadb-dev, "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    add_library(spine_mysql INTERFACE)
    target_include_directories(spine_mysql INTERFACE ${_mysql_include_dirs})
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
            set(_netsnmp_link_options "${NETSNMP_LDFLAGS}")
        endif()
    endif()

    if(NOT _netsnmp_found)
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

            set(_netsnmp_found TRUE)
            string(REPLACE " " ";" _snmp_cflags_list "${NETSNMP_CFLAGS_RAW}")
            foreach(_flag ${_snmp_cflags_list})
                if(_flag MATCHES "^-I(.*)")
                    list(APPEND _netsnmp_include_dirs "${CMAKE_MATCH_1}")
                endif()
            endforeach()

            separate_arguments(_snmp_libs_list UNIX_COMMAND "${NETSNMP_LIBS_RAW}")
            foreach(_flag ${_snmp_libs_list})
                if(_flag MATCHES "^-l(.*)")
                    list(APPEND _netsnmp_libraries "${CMAKE_MATCH_1}")
                elseif(_flag MATCHES "^-L(.*)")
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
                set(_netsnmp_found TRUE)
                set(_netsnmp_include_dirs "${NETSNMP_INCLUDE_DIR}")
                set(_netsnmp_libraries "${NETSNMP_LIBRARY}")
            endif()
        endif()
    endif()

    if(NOT _netsnmp_found)
        message(FATAL_ERROR
            "Cannot find Net-SNMP library. "
            "Install libsnmp-dev or net-snmp-devel, "
            "or set CMAKE_PREFIX_PATH to the install location.")
    endif()

    add_library(spine_netsnmp INTERFACE)
    target_include_directories(spine_netsnmp INTERFACE ${_netsnmp_include_dirs})
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
)
target_link_libraries(spine_platform PUBLIC Threads::Threads)
if(TARGET spine_build_options)
    target_link_libraries(spine_platform PUBLIC spine_build_options)
endif()
if(WIN32)
    target_link_libraries(spine_platform PUBLIC ws2_32 iphlpapi advapi32)
else()
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
    )
    target_link_libraries(test_platform_${test_name} PRIVATE Threads::Threads)
    if(TARGET spine_build_options)
        target_link_libraries(test_platform_${test_name} PRIVATE spine_build_options)
    endif()
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
        $<TARGET_OBJECTS:spine_platform>
    )
    target_include_directories(spine PRIVATE
        ${CMAKE_BINARY_DIR}
        ${CMAKE_SOURCE_DIR}
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
    if(OpenSSL_FOUND)
        target_link_libraries(spine PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    endif()

    install(TARGETS spine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES spine.conf.dist DESTINATION ${CMAKE_INSTALL_SYSCONFDIR})
endif()

if(BUILD_TESTING)
    foreach(test_name IN LISTS SPINE_TEST_NAMES)
        spine_add_platform_test(${test_name})
    endforeach()
endif()

configure_file(
    ${CMAKE_SOURCE_DIR}/config/config.h.cmake.in
    ${CMAKE_BINARY_DIR}/config/config.h
    @ONLY
)
