#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2026 The Cacti Group                                 |
# +-------------------------------------------------------------------------+

AC_PREREQ([2.71])
AC_INIT([Spine Poller], [1.3.0], [https://github.com/Cacti/spine/issues])

AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config/config.h])
AC_CONFIG_SRCDIR([spine.c])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.15 foreign subdir-objects -Wall])
AM_SILENT_RULES([yes])

AC_CANONICAL_HOST
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
LT_INIT

# Check for pkg-config
PKG_PROG_PKG_CONFIG

# Initialize variables
SPINE_CFLAGS=""
SPINE_LIBS=""

# --- System Library Checks ---
AC_SEARCH_LIBS([floor], [m])
AC_SEARCH_LIBS([dlclose], [dl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([clock_gettime], [rt pthread])

# --- Pthreads ---
# Modern systems have pthreads.
AC_CHECK_HEADERS([pthread.h], [], [AC_MSG_ERROR([pthread.h not found.])])
AC_CHECK_LIB([pthread], [pthread_create], [
    AC_DEFINE([HAVE_LIBPTHREAD], [1], [Define if you have pthreads library])
    SPINE_LIBS="$SPINE_LIBS -lpthread"
], [
    AC_MSG_ERROR([pthreads library not found.])
])

# --- OpenSSL / Crypto ---
PKG_CHECK_MODULES([OPENSSL], [openssl], [
    SPINE_CFLAGS="$SPINE_CFLAGS $OPENSSL_CFLAGS"
    SPINE_LIBS="$SPINE_LIBS $OPENSSL_LIBS"
], [
    AC_MSG_ERROR([OpenSSL (libssl/libcrypto) not found. Required for non-EOL systems.])
])

# --- MySQL / MariaDB ---
PKG_CHECK_MODULES([MYSQL], [mariadb], [
    MYSQL_FOUND=yes
], [
    PKG_CHECK_MODULES([MYSQL], [libmariadb], [
        MYSQL_FOUND=yes
    ], [
        PKG_CHECK_MODULES([MYSQL], [mysqlclient], [
            MYSQL_FOUND=yes
        ], [
            AC_MSG_ERROR([MySQL/MariaDB client libraries not found via pkg-config.])
        ])
    ])
])
SPINE_CFLAGS="$SPINE_CFLAGS $MYSQL_CFLAGS"
SPINE_LIBS="$SPINE_LIBS $MYSQL_LIBS"
AC_DEFINE([HAVE_MYSQL], [1], [MySQL Client API])

# --- Net-SNMP ---
PKG_CHECK_MODULES([NETSNMP], [netsnmp], [
    SPINE_CFLAGS="$SPINE_CFLAGS $NETSNMP_CFLAGS"
    SPINE_LIBS="$SPINE_LIBS $NETSNMP_LIBS"
], [
    AC_PATH_PROG([NETSNMP_CONFIG], [net-snmp-config])
    if test -z "$NETSNMP_CONFIG"; then
        AC_MSG_ERROR([Net-SNMP not found. Please install net-snmp-dev.])
    else
        SNMP_CFLAGS=`$NETSNMP_CONFIG --base-cflags`
        SNMP_LIBS=`$NETSNMP_CONFIG --libs`
        
        # Filter out mangled Apple internal flags and invalid paths
        SNMP_CFLAGS=`echo $SNMP_CFLAGS | sed 's/-i[[^ ]]*withsysroot [[^ ]]*//g' | sed 's/[[^ ]]*~[[^ ]]*//g' | sed 's/[[^ ]]*Internal.sdk[[^ ]]*//g'`
        
        SPINE_CFLAGS="$SPINE_CFLAGS $SNMP_CFLAGS"
        SPINE_LIBS="$SPINE_LIBS $SNMP_LIBS"
    fi
])

# Feature checks for Net-SNMP
# We need to temporarily add SPINE_CFLAGS to CFLAGS for compilation tests
SAVE_CFLAGS="$CFLAGS"
SAVE_LIBS="$LIBS"
CFLAGS="$SPINE_CFLAGS $CFLAGS"
LIBS="$SPINE_LIBS $LIBS"

AC_MSG_CHECKING([if Net-SNMP has localname support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-includes.h>
]], [[
    struct snmp_session session;
    snmp_sess_init(&session);
    session.localname = strdup("hello");
]])], [
    havelocalname=1
    AC_MSG_RESULT([yes])
], [
    havelocalname=0
    AC_MSG_RESULT([no])
])
AC_DEFINE_UNQUOTED([SNMP_LOCALNAME], [$havelocalname], [If snmp localname session structure member exists])

AC_MSG_CHECKING([for SNMPv3 USM error constants])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
    #include <net-snmp/net-snmp-config.h>
    #include <net-snmp/net-snmp-includes.h>
]], [[
    int x;
    #if defined(SNMPERR_NOT_IN_TIME_WINDOW)
    x = SNMPERR_NOT_IN_TIME_WINDOW;
    #elif defined(SNMPERR_USM_NOTINTIMEWINDOW)
    x = SNMPERR_USM_NOTINTIMEWINDOW;
    #else
    #error no USM error constants
    #endif
    (void)x;
]])], [
    AC_MSG_RESULT([yes])
], [
    AC_MSG_RESULT([no (USM error decoding disabled)])
])

# Restore CFLAGS/LIBS
CFLAGS="$SAVE_CFLAGS"
LIBS="$SAVE_LIBS"

# --- Platform Specifics ---
case $host_os in
    *darwin*)
        # Required for struct icmp and other networking structures on macOS
        AC_DEFINE([_DARWIN_C_SOURCE], [1], [Expose Darwin extensions])
        ;;
    *solaris*)
        SPINE_CFLAGS="$SPINE_CFLAGS -D_POSIX_PTHREAD_SEMANTICS"
        AC_DEFINE([SOLAR_THREAD], [1], [Modern Solaris threading])
        ;;
    *freebsd*)
        SPINE_LIBS="$SPINE_LIBS -lexecinfo"
        ;;
esac

# --- Header Checks ---
AC_CHECK_HEADERS([sys/socket.h sys/select.h sys/wait.h sys/time.h syslog.h])
AC_CHECK_HEADERS([assert.h ctype.h errno.h signal.h math.h malloc.h netdb.h])
AC_CHECK_HEADERS([netinet/in.h netinet/in_systm.h netinet/ip.h netinet/ip_icmp.h netinet/ip6.h netinet/icmp6.h])

# --- Library Functions ---
AC_CHECK_FUNCS([gettimeofday strerror strtoll malloc calloc])

# --- Linux Capabilities ---
AC_ARG_ENABLE([lcap],
    [AS_HELP_STRING([--enable-lcap], [Enable Linux Capabilities support (default: disabled)])])
if test "x$enable_lcap" = "xyes"; then
    AC_CHECK_LIB([cap], [cap_init], [
        SPINE_LIBS="$SPINE_LIBS -lcap"
        AC_DEFINE([HAVE_LCAP], [1], [Linux Capabilities])
    ], [
        AC_MSG_ERROR([libcap not found but --enable-lcap was specified.])
    ])
fi

# --- Spine specific options ---
AC_ARG_WITH([results-buffer],
    [AS_HELP_STRING([--with-results-buffer=N], [Size of spine results buffer (default=2048)])],
    [results_buffer=$withval], [results_buffer=2048])
AC_DEFINE_UNQUOTED([RESULTS_BUFFER], [$results_buffer], [Result buffer size])

AC_ARG_WITH([max-scripts],
    [AS_HELP_STRING([--with-max-scripts=N], [Max simultaneous scripts (default=20)])],
    [max_scripts=$withval], [max_scripts=20])
AC_DEFINE_UNQUOTED([MAX_SIMULTANEOUS_SCRIPTS], [$max_scripts], [Max scripts])

AC_ARG_WITH([max-mysql-buffer],
    [AS_HELP_STRING([--with-max-mysql-buffer=N], [Max SQL insert size (default=131072)])],
    [max_mysql_buffer=$withval], [max_mysql_buffer=131072])
AC_DEFINE_UNQUOTED([MAX_MYSQL_BUF_SIZE], [$max_mysql_buffer], [Max MySQL buffer])

# Optional warnings
AC_ARG_ENABLE([warnings],
    [AS_HELP_STRING([--enable-warnings], [Enable -Wall if using gcc])])
if test "x$enable_warnings" = "xyes" && test "x$GCC" = "xyes"; then
    SPINE_CFLAGS="$SPINE_CFLAGS -Wall"
fi

AC_PATH_PROG([HELP2MAN], [help2man])
AM_CONDITIONAL([HAVE_HELP2MAN], [test -n "$HELP2MAN"])

# Export variables to Makefile
AC_SUBST([SPINE_CFLAGS])
AC_SUBST([SPINE_LIBS])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
