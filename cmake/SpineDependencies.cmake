include_guard(GLOBAL)

find_package(PkgConfig QUIET)

# libsystemd: Linux only, opt-in via WITH_SYSTEMD (default ON). Missing lib is
# not an error; spine falls back to no-op sd_notify stubs so macOS, Windows,
# and minimal Linux images build unchanged.
set(SPINE_HAVE_LIBSYSTEMD FALSE)
set(SPINE_SYSTEMD_UNIT_DIR "")
if(WITH_SYSTEMD AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if(PkgConfig_FOUND)
    pkg_check_modules(SYSTEMD QUIET libsystemd)
    if(SYSTEMD_FOUND)
      set(SPINE_HAVE_LIBSYSTEMD TRUE)
      pkg_get_variable(SPINE_SYSTEMD_UNIT_DIR systemd systemdsystemunitdir)
      message(STATUS "libsystemd: ${SYSTEMD_VERSION} (unit dir: ${SPINE_SYSTEMD_UNIT_DIR})")
    else()
      message(STATUS "libsystemd not found; spine will build without sd_notify")
    endif()
  else()
    message(STATUS "pkg-config not found; skipping libsystemd detection")
  endif()
endif()

# libseccomp: Linux only. Enables a real syscall allowlist inside
# spine_sandbox_restrict(). Missing header/library is not an error; the
# sandbox falls back to PR_SET_NO_NEW_PRIVS alone.
set(SPINE_HAVE_LIBSECCOMP FALSE)
if(WITH_SECCOMP AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_path(SECCOMP_INCLUDE_DIR seccomp.h)
  find_library(SECCOMP_LIB NAMES seccomp)
  if(SECCOMP_INCLUDE_DIR AND SECCOMP_LIB)
    set(SPINE_HAVE_LIBSECCOMP TRUE)
    message(STATUS "libseccomp: ${SECCOMP_LIB}")
  else()
    message(STATUS "libseccomp not found; seccomp allowlist disabled")
  endif()
endif()

# Linux Landlock (kernel >= 5.13). Header-only detection; the syscall is
# invoked via syscall(SYS_landlock_*). ENOSYS is handled at runtime.
set(SPINE_HAVE_LANDLOCK FALSE)
if(WITH_LANDLOCK AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  check_include_file("linux/landlock.h" SPINE_HAS_LANDLOCK_H)
  if(SPINE_HAS_LANDLOCK_H)
    set(SPINE_HAVE_LANDLOCK TRUE)
    message(STATUS "linux/landlock.h found; Landlock confinement enabled")
  else()
    message(STATUS "linux/landlock.h not found; Landlock disabled")
  endif()
endif()

# libaudit: emit AUDIT_USER events for lifecycle transitions (reload/term/
# circuit-breaker trip). Soft dependency.
set(SPINE_HAVE_LIBAUDIT FALSE)
if(WITH_AUDIT AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_path(AUDIT_INCLUDE_DIR libaudit.h)
  find_library(AUDIT_LIB NAMES audit)
  if(AUDIT_INCLUDE_DIR AND AUDIT_LIB)
    set(SPINE_HAVE_LIBAUDIT TRUE)
    message(STATUS "libaudit: ${AUDIT_LIB}")
  else()
    message(STATUS "libaudit not found; AUDIT_USER events disabled")
  endif()
endif()

# libuv: Mandatory dependency for the asynchronous event loop.
set(SPINE_HAVE_LIBUV FALSE)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBUV REQUIRED libuv>=1.40.0)
  if(LIBUV_FOUND)
    set(SPINE_HAVE_LIBUV TRUE)
    message(STATUS "libuv: ${LIBUV_VERSION}")
    # pkg-config might return '-luv' in LIBRARIES, but on macOS we want the absolute path
    # to avoid 'library not found' if it's in a non-standard Homebrew prefix.
    find_library(LIBUV_REAL_LIB NAMES ${LIBUV_LIBRARIES} PATHS ${LIBUV_LIBRARY_DIRS})
    if(LIBUV_REAL_LIB)
        set(LIBUV_LIBRARIES ${LIBUV_REAL_LIB})
    endif()
  endif()
else()
  find_path(LIBUV_INCLUDE_DIR uv.h)
  find_library(LIBUV_LIBRARY NAMES uv)
  if(LIBUV_INCLUDE_DIR AND LIBUV_LIBRARY)
    set(SPINE_HAVE_LIBUV TRUE)
    set(LIBUV_LIBRARIES ${LIBUV_LIBRARY})
    set(LIBUV_INCLUDE_DIRS ${LIBUV_INCLUDE_DIR})
    message(STATUS "libuv: ${LIBUV_LIBRARY}")
  endif()
endif()

if(NOT SPINE_HAVE_LIBUV)
  message(FATAL_ERROR "libuv 1.40+ is required for the event loop. "
                      "Install libuv1-dev or set CMAKE_PREFIX_PATH.")
endif()

# c-ares: optional async DNS backend used by src/async_dns.c. When present,
# Spine wires c-ares socket-state callbacks into libuv uv_poll_t handles plus
# a uv_timer_t timeout bridge.
set(SPINE_HAVE_CARES FALSE)
if(PkgConfig_FOUND)
  pkg_check_modules(CARES QUIET libcares)
  if(NOT CARES_FOUND)
    pkg_check_modules(CARES QUIET c-ares)
  endif()
endif()

if(CARES_FOUND)
  set(SPINE_HAVE_CARES TRUE)
  if(CARES_LIBRARY_DIRS)
    find_library(CARES_REAL_LIB NAMES ${CARES_LIBRARIES} PATHS ${CARES_LIBRARY_DIRS})
    if(CARES_REAL_LIB)
      set(CARES_LIBRARIES ${CARES_REAL_LIB})
    endif()
  endif()
  message(STATUS "c-ares: ${CARES_VERSION}")
else()
  find_path(CARES_INCLUDE_DIR ares.h)
  find_library(CARES_LIBRARY NAMES cares c-ares)
  if(CARES_INCLUDE_DIR AND CARES_LIBRARY)
    set(SPINE_HAVE_CARES TRUE)
    set(CARES_INCLUDE_DIRS "${CARES_INCLUDE_DIR}")
    set(CARES_LIBRARIES "${CARES_LIBRARY}")
    message(STATUS "c-ares: ${CARES_LIBRARY}")
  endif()
endif()

# jemalloc: High-performance multi-threaded allocator.
find_package(PkgConfig QUIET)
pkg_check_modules(JEMALLOC QUIET jemalloc)
if(JEMALLOC_FOUND)
  message(STATUS "jemalloc: ${JEMALLOC_LIBRARIES}")
endif()

# mimalloc: Compact high-performance allocator from Microsoft.
pkg_check_modules(MIMALLOC QUIET mimalloc)
if(MIMALLOC_FOUND)
  message(STATUS "mimalloc: ${MIMALLOC_LIBRARIES}")
endif()

function(spine_require_mysql)
  if(TARGET spine_mysql)
    return()
  endif()

  set(_mysql_found FALSE)
  set(_mysql_include_dirs "")
  set(_mysql_libraries "")
  set(_mysql_link_options "")

  if(PkgConfig_FOUND)
    # Prioritize MariaDB for non-blocking (async) API support.
    pkg_check_modules(MYSQL QUIET mariadb)
    if(NOT MYSQL_FOUND)
      pkg_check_modules(MYSQL QUIET mysqlclient)
    endif()

    if(MYSQL_FOUND)
      set(_mysql_found TRUE)
      set(_mysql_include_dirs "${MYSQL_INCLUDE_DIRS}")
      set(_mysql_libraries "${MYSQL_LIBRARIES}")
      set(_mysql_link_options "${MYSQL_LDFLAGS}")
    endif()
  endif()

  if(NOT _mysql_found)
    find_path(
      MYSQL_INCLUDE_DIR mysql.h
      PATHS
        /usr/include/mariadb
        /usr/include/mysql
        /usr/local/include/mariadb
        /usr/local/include/mysql
        /usr/local/mysql/include
        /opt/local/include/mariadb
        /opt/local/include/mysql
        /opt/homebrew/include/mariadb
        /opt/homebrew/include/mysql
        /usr/local/opt/mariadb-connector-c/include/mariadb
        /opt/homebrew/opt/mariadb-connector-c/include/mariadb
        /usr/local/opt/mysql-client/include/mysql
        /opt/homebrew/opt/mysql-client/include/mysql
        /opt/csw/include/mariadb
        /opt/csw/include/mysql
        /opt/freeware/include/mariadb
        /opt/freeware/include/mysql
        /opt/mysql/include
        /usr/pkg/include/mysql
        ${MINGW_PREFIX}/include/mariadb
        ${MINGW_PREFIX}/include/mysql)
    find_library(
      MYSQL_LIBRARY
      # Prefer 'mariadb' and 'mariadbclient' over 'mysqlclient'
      NAMES mariadb mariadbclient mysqlclient
      PATHS
        /usr/lib
        /usr/lib64
        /usr/lib/x86_64-linux-gnu
        /usr/local/lib
        /usr/local/lib/mysql
        /usr/local/mysql/lib
        /opt/local/lib
        /opt/homebrew/lib
        /usr/local/opt/mariadb-connector-c/lib
        /opt/homebrew/opt/mariadb-connector-c/lib
        /usr/local/opt/mysql-client/lib
        /opt/homebrew/opt/mysql-client/lib
        /opt/csw/lib
        /opt/freeware/lib
        /opt/mysql/lib
        /usr/pkg/lib
        ${MINGW_PREFIX}/lib)

    if(MYSQL_INCLUDE_DIR AND MYSQL_LIBRARY)
      set(_mysql_found TRUE)
      set(_mysql_include_dirs "${MYSQL_INCLUDE_DIR}")
      set(_mysql_libraries "${MYSQL_LIBRARY}")
    endif()
  endif()

  if(NOT _mysql_found)
    message(FATAL_ERROR "Cannot find MySQL/MariaDB client library. "
                        "Install libmariadb-dev or libmysqlclient-dev "
                        "(FreeBSD: mariadb-connector-c or mysql80-client), "
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

  # Check for MariaDB-specific non-blocking (async) API support.
  set(CMAKE_REQUIRED_INCLUDES "${_mysql_include_dirs}")
  set(CMAKE_REQUIRED_LIBRARIES "${_mysql_libraries}")
  check_c_source_compiles(
    "
        #include <mysql.h>
        int main(void) {
            MYSQL mysql;
            mysql_init(&mysql);
            mysql_real_query_start(NULL, &mysql, \"SELECT 1\", 7);
            return 0;
        }
    "
    SPINE_HAVE_MYSQL_ASYNC)
  unset(CMAKE_REQUIRED_INCLUDES)
  unset(CMAKE_REQUIRED_LIBRARIES)

  if(SPINE_HAVE_MYSQL_ASYNC)
    message(STATUS "libmariadb: non-blocking (async) API support enabled")
    set(HAVE_MYSQL_ASYNC 1 PARENT_SCOPE)
  else()
    message(STATUS "libmariadb: non-blocking (async) API support NOT found (standard MySQL library?)")
    set(HAVE_MYSQL_ASYNC 0 PARENT_SCOPE)
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
    find_program(
      NETSNMP_CONFIG net-snmp-config
      HINTS /opt/homebrew/opt/net-snmp/bin /usr/local/opt/net-snmp/bin
      NO_DEFAULT_PATH)
    if(NOT NETSNMP_CONFIG)
      find_program(NETSNMP_CONFIG net-snmp-config)
    endif()
    if(NETSNMP_CONFIG)
      execute_process(
        COMMAND ${NETSNMP_CONFIG} --cflags
        OUTPUT_VARIABLE NETSNMP_CFLAGS_RAW
        RESULT_VARIABLE _netsnmp_cflags_rc
        OUTPUT_STRIP_TRAILING_WHITESPACE)
      if(NOT _netsnmp_cflags_rc EQUAL 0)
        message(FATAL_ERROR "net-snmp-config --cflags failed with code ${_netsnmp_cflags_rc}")
      endif()
      execute_process(
        COMMAND ${NETSNMP_CONFIG} --libs
        OUTPUT_VARIABLE NETSNMP_LIBS_RAW
        RESULT_VARIABLE _netsnmp_libs_rc
        OUTPUT_STRIP_TRAILING_WHITESPACE)
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
          # Translate "-framework Foo" pairs into the absolute path of the
          # Foo.framework. target_link_options deduplicates repeated
          # "-framework" tokens when passed through an INTERFACE target, so a
          # resolved path is the most reliable form for linking frameworks.
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
      find_path(
        NETSNMP_INCLUDE_DIR net-snmp/net-snmp-config.h
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
          ${MINGW_PREFIX}/include)
      find_library(
        NETSNMP_LIBRARY
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
          ${MINGW_PREFIX}/lib)
      if(NETSNMP_INCLUDE_DIR AND NETSNMP_LIBRARY)
        set(_netsnmp_found TRUE)
        set(_netsnmp_include_dirs "${NETSNMP_INCLUDE_DIR}")
        set(_netsnmp_libraries "${NETSNMP_LIBRARY}")
      endif()
    endif()
  endif()

  if(NOT _netsnmp_found)
    message(FATAL_ERROR "Cannot find Net-SNMP library. "
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
  check_c_source_compiles(
    "
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
    "
    HAVE_SNMP_LOCALNAME)
  unset(CMAKE_REQUIRED_INCLUDES)

  if(HAVE_SNMP_LOCALNAME)
    set(SNMP_LOCALNAME 1 PARENT_SCOPE)
  else()
    set(SNMP_LOCALNAME 0 PARENT_SCOPE)
  endif()
endfunction()
