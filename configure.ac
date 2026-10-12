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

AC_PREREQ([2.69])
AC_INIT([Spine Poller],[1.3.0],[http://www.cacti.net/issues.php])

AC_CONFIG_AUX_DIR(config)
AC_SUBST(ac_aux_dir)

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR(spine.c)
AC_PREFIX_DEFAULT(/usr/local/spine)
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS(config/config.h)

# These generic package macros belong to the generated configuration header.
# Leave them available for Net-SNMP to define; snmp_spine_init uses its
# PACKAGE_VERSION when header/library version verification is enabled.
# Continue each directive so config.status preserves the literal cleanup
# instead of substituting another package definition into the header footer.
AH_BOTTOM([#undef \
PACKAGE_NAME
#undef \
PACKAGE_VERSION
#undef \
PACKAGE_BUGREPORT
#undef \
PACKAGE_STRING
#undef \
PACKAGE_TARNAME])

# static libraries
AC_ARG_WITH(static,
  AS_HELP_STRING([--with-static],[Build using static libraries
  ]),
  [CFLAGS="-static $CFLAGS"]
)

AC_CONFIG_MACRO_DIR([m4])

# mysql
AC_ARG_WITH(mysql,
  AS_HELP_STRING([--with-mysql],[MySQL base directory [[/usr/local/mysql]]
  ]),
  [MYSQL_DIR=$withval]
)

# snmp
AC_ARG_WITH(snmp,
  AS_HELP_STRING([--with-snmp],[SNMP base directory [[/usr/(local/)include]]
  ]),
  [SNMP_DIR=$withval]
)

# Platform-specific tweaks
ShLib="so"

case $host in
*sparc-sun-solaris2.8)
  CPPFLAGS="$CPPFLAGS -D_POSIX_PTHREAD_SEMANTICS"
  AC_DEFINE(SOLAR_THREAD, 1, [Correct issue around Solaris threading model]);;
*solaris*)
  CPPFLAGS="$CPPFLAGS -D_POSIX_PTHREAD_SEMANTICS";;
*freebsd*)
  LIBS="$LIBS -pthread -lexecinfo"
  AC_DEFINE(HAVE_LIBPTHREAD, 1);;
*darwin*)
  ShLib="dylib";;
*)
  LIBS="-lpthread -lssl $LIBS"
esac

# Checks for programs.
AC_PROG_AWK
spine_user_cc=$CC
AC_PROG_CC

# ****************** C language standard ***********************
dnl Spine is written to C17 with GNU extensions (docs/adr/0001). Name it
dnl explicitly: the compiler default drifts, and GCC 15 moved it to gnu23.
dnl Autoconf 2.70 and later append their own -std to CC, overriding one the
dnl caller put there, so drop it. A -std in the caller's CC or CFLAGS wins.
if test -n "$spine_user_cc"; then
  CC=$spine_user_cc
else
  CC=`echo "$CC" | sed 's/ -std=[[^ ]]*//g'`
fi
spine_user_std=
for spine_flag in $spine_user_cc $CFLAGS; do
  case $spine_flag in
    -std=*) spine_user_std=$spine_flag ;;
  esac
done

if test -z "$spine_user_std"; then
  AC_MSG_CHECKING([whether $CC accepts -std=gnu17])
  CFLAGS="$CFLAGS -std=gnu17"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [])],
    [AC_MSG_RESULT([yes])],
    [AC_MSG_RESULT([no])
     AC_MSG_ERROR([$CC does not accept -std=gnu17. Spine needs a C17 compiler: GCC 8, Clang 6 or newer.])])
fi

AC_MSG_CHECKING([whether the compiler is in C17 mode or later])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201710L
#error older than C17
#endif
]], [])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no])
   if test -n "$spine_user_std"; then
     AC_MSG_WARN([$spine_user_std selects a standard older than C17; Spine is developed and tested as gnu17])
   else
     AC_MSG_ERROR([__STDC_VERSION__ is below 201710L under -std=gnu17])
   fi])

AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
LT_INIT

AC_MSG_CHECKING([whether to enable -Wall])
AC_ARG_ENABLE(warnings,
  [  --enable-warnings       Enable -Wall if using gcc.],
  [if test -n "$GCC"; then
    AC_MSG_RESULT(adding -Wall to CFLAGS.)
    CFLAGS="$CFLAGS -Wall"
   fi
  ],
  AC_MSG_RESULT(no)
)

AC_ARG_ENABLE(sanitizers,
  [  --enable-sanitizers     Build with AddressSanitizer and UndefinedBehaviorSanitizer.],
  [if test "x$enableval" = "xyes"; then
    AC_MSG_RESULT(adding -fsanitize=address,undefined to CFLAGS.)
    CFLAGS="$CFLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -g"
    LDFLAGS="$LDFLAGS -fsanitize=address,undefined"
   fi
  ],
  AC_MSG_RESULT(no)
)

AC_PATH_PROG(HELP2MAN, help2man, false // No help2man //)
AC_CHECK_PROG([HELP2MAN], [help2man], [help2man])
AM_CONDITIONAL([HAVE_HELP2MAN], [test x$HELP2MAN = xhelp2man])

# Checks for libraries.
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, floor)
AC_CHECK_LIB(dl, dlclose)
AC_CHECK_LIB(pthread, pthread_exit)

# Some builds of MySQL require libz - try to detect
AC_CHECK_LIB(z, deflate)
AC_CHECK_LIB(kstat, kstat_close)
AC_CHECK_LIB(crypto, CRYPTO_realloc)

# minor adjustments for debian
AC_SEARCH_LIBS([clock_gettime], [rt pthread])

# Checks for header files.
AC_CHECK_HEADERS(sys/socket.h sys/select.h sys/wait.h sys/time.h)
AC_CHECK_HEADERS(assert.h ctype.h errno.h signal.h math.h malloc.h netdb.h)
AC_CHECK_HEADERS(signal.h stdarg.h stdio.h syslog.h)
AC_CHECK_HEADERS(ifaddrs.h net/if.h)
AC_CHECK_HEADERS(
  netinet/in_systm.h netinet/in.h netinet/ip.h netinet/ip_icmp.h,
  [],
  [],
  [#ifdef HAVE_SYS_TYPES_H
  #include <sys/types.h>
  #endif
  #ifdef HAVE_NETINET_IN_H
  #include <netinet/in.h>
  #endif
  #ifdef HAVE_NETINET_IN_SYSTM_H
  #include <netinet/in_systm.h>
  #endif
  #ifdef HAVE_NETINET_IP_H
  #include <netinet/ip.h>
  #endif]
)

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPES([unsigned long long, long long])
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNCS(malloc calloc gettimeofday strerror strtoll getifaddrs if_nametoindex)

# ****************** Solaris Privileges Check ***********************

# Check if usage of Solaris privileges support is possible
AC_CHECK_HEADER(priv.h, [FOUND_PRIV_H=yes], [FOUND_PRIV_H=no])

# If we should use the Solaris privileges support
AC_MSG_CHECKING(whether we are using Solaris privileges)
AC_ARG_ENABLE(solaris-priv,
  [  --enable-solaris-priv   Enable support for the Solaris process privilege model (default: disabled)],
  [ ENABLED_SOL_PRIV=$enableval ],
  [ ENABLED_SOL_PRIV=no ]
  )
if test x$ENABLED_SOL_PRIV != xno; then
  if test x$FOUND_PRIV_H != xno; then
    AC_MSG_RESULT([yes])
    AC_DEFINE([SOLAR_PRIV], [1],
      [If Support for Solaris privileges should be enabled]
    )
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([no])
fi

# ****************** Linux Capabilities Check ***********************
CAPLOC="sys/capability.h"
for file in sys/capability.h;do
    test -f /usr/include/$file && CAPLOC=$file && break
done

AC_CHECK_HEADER($CAPLOC, [FOUND_SYS_CAPABILITY_H=yes],
	[FOUND_SYS_CAPABILITY_H=no])

# If we should use the Linux Capabilities support
AC_MSG_CHECKING(whether we are using Linux Capabilities)
AC_ARG_ENABLE(lcap,
  [  --enable-lcap   Enable support for the Linux Capabilities (default: disabled)],
  [ ENABLED_LCAP=$enableval ],
  [ ENABLED_LCAP=no ]
  )

HAVE_LCAP=no
if test x$ENABLED_LCAP != xno; then
  AC_MSG_RESULT([yes])
  if test x$FOUND_SYS_CAPABILITY_H != xno; then
    AC_CHECK_LIB(cap, cap_init,
      [ LIBS="-lcap $LIBS"
        AC_DEFINE(HAVE_LCAP, 1, Linux Capabilities)
        HAVE_LCAP=yes ])
  fi
  # An explicit request must not quietly produce a build without it.
  if test x$HAVE_LCAP != xyes; then
    AC_MSG_ERROR([--enable-lcap was given but libcap (sys/capability.h and -lcap) was not found])
  fi
else
  AC_MSG_RESULT([no])
  if test x$FOUND_SYS_CAPABILITY_H != xno; then
    AC_MSG_NOTICE([libcap headers were found but are not used; pass --enable-lcap to use them])
  else
    AC_MSG_NOTICE([libcap was not found; building without Linux capabilities support])
  fi
  AC_MSG_NOTICE([without it a setuid root spine opens its raw ICMP sockets at startup, then drops root for good])
fi

# ****************** MySQL-compatible client checks ***********************
AC_ARG_VAR([MYSQL_CONFIG], [path to mariadb_config or mysql_config])

if test -n "$MYSQL_DIR" && test -z "$MYSQL_CONFIG"; then
  for mysql_config_candidate in mariadb_config mysql_config; do
    if test -x "$MYSQL_DIR/bin/$mysql_config_candidate"; then
      MYSQL_CONFIG="$MYSQL_DIR/bin/$mysql_config_candidate"
      break
    fi
  done
fi

if test -z "$MYSQL_CONFIG"; then
  AC_PATH_PROGS([MYSQL_CONFIG], [mariadb_config mysql_config])
fi

if test -n "$MYSQL_CONFIG"; then
  AC_MSG_NOTICE([using $MYSQL_CONFIG for database client flags])
  if ! MYSQL_CFLAGS=`"$MYSQL_CONFIG" --cflags`; then
    AC_MSG_ERROR([$MYSQL_CONFIG --cflags failed])
  fi
  if ! MYSQL_LIBS=`"$MYSQL_CONFIG" --libs`; then
    AC_MSG_ERROR([$MYSQL_CONFIG --libs failed])
  fi
  CFLAGS="$MYSQL_CFLAGS $CFLAGS"
  LIBS="$MYSQL_LIBS $LIBS"
else
  AC_MSG_NOTICE([no client config tool found; using header and library discovery])

  mysql_header_prefix=

  for mysql_prefix in $MYSQL_DIR /usr /usr/local /opt /opt/mysql /usr/pkg /usr/local/mysql; do
    for mysql_include_dir in include include/mysql include/mariadb mysql; do
      if test -f "$mysql_prefix/$mysql_include_dir/mysql.h"; then
        CFLAGS="-I$mysql_prefix/$mysql_include_dir $CFLAGS"
        mysql_header_prefix=$mysql_prefix
        break 2
      fi
    done
  done

  dnl The header can turn up under a prefix the caller never named, so search
  dnl for the library under that same prefix. Adding only the MYSQL_DIR paths
  dnl leaves mysql_init unlinkable when the client lives anywhere else.
  mysql_library_prefixes="$MYSQL_DIR"

  if test -n "$mysql_header_prefix" && test "x$mysql_header_prefix" != "x$MYSQL_DIR"; then
    mysql_library_prefixes="$mysql_library_prefixes $mysql_header_prefix"
  fi

  for mysql_prefix in $mysql_library_prefixes; do
    for mysql_library_dir in lib64 lib64/mysql lib lib/mysql; do
      if test -d "$mysql_prefix/$mysql_library_dir"; then
        LDFLAGS="-L$mysql_prefix/$mysql_library_dir $LDFLAGS"
      fi
    done
  done
fi

AC_CHECK_HEADER([mysql.h], [],
  [AC_MSG_ERROR([Cannot find mysql.h. Install MariaDB Connector/C or MySQL Connector/C development files.])])

AC_SEARCH_LIBS([mysql_init], [mariadb mysqlclient perconaserverclient],
  [AC_DEFINE([HAVE_MYSQL], [1], [MySQL-compatible Client API])
   HAVE_MYSQL=yes],
  [AC_MSG_ERROR([Cannot link a MySQL-compatible client library.])])

# ****************** Net-SNMP Checks ***********************
if test "x$SNMP_DIR" != "x"; then
  for i in / /net-snmp /include/net-snmp; do
    test -f $SNMP_DIR/$i/net-snmp-config.h  && SNMP_INCDIR=$SNMP_DIR$i && break
  done

  # Accommodate 64-Bit Libraries
  test -f $SNMP_DIR/lib64/libnetsnmp.a -o -f $SNMP_DIR/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$SNMP_DIR/lib64

  if test -z "$SNMP_LIBDIR"; then
    # Accommodate 32-Bit Libraries
    test -f $SNMP_DIR/lib/libnetsnmp.a -o -f $SNMP_DIR/lib/libnetsnmp.$ShLib && SNMP_LIBDIR=$SNMP_DIR/lib
  fi
else
  for i in /usr /usr/local /usr/include /usr/pkg/include /usr/local/include /opt /opt/net-snmp /opt/snmp; do
    test -f $i/snmp.h                                  && SNMP_INCDIR=$i                       && break
    test -f $i/include/net-snmp/net-snmp-config.h      && SNMP_INCDIR=$i/include/net-snmp      && break
    test -f $i/net-snmp/net-snmp-config.h              && SNMP_INCDIR=$i/net-snmp              && break
    test -f $i/net-snmp/include/net-snmp-config.h      && SNMP_INCDIR=$i/net-snmp/include      && break
    test -f $i/snmp/snmp.h                             && SNMP_INCDIR=$i/snmp                  && break
    test -f $i/snmp/include/net-snmp/net-snmp-config.h && SNMP_INCDIR=$i/snmp/include/net-snmp && break
  done

  # Accommodate 64-Bit Libraries
  for i in /usr /usr/local /usr/pkg /usr/snmp /opt /opt/net-snmp /opt/snmp /usr/local/snmp; do
    test -f $i/lib64/libnetsnmp.a -o -f $i/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$i/lib64 && break
  done

  # Only check for 32 Bit libraries if the 64 bit are not found
  if test -z "$SNMP_LIBDIR"; then
    # Accommodate 32-Bit Libraries
    for i in /usr /usr/local /usr/pkg /usr/snmp /opt /opt/net-snmp /opt/snmp /usr/local/snmp; do
      test -f $i/lib/libnetsnmp.a -o -f $i/lib/libnetsnmp.$ShLib && SNMP_LIBDIR=$i/lib && break
    done
  fi
fi

if test -z "$SNMP_INCDIR"; then
  if test "x$SNMP_DIR" != "x";then
    AC_MSG_ERROR(Cannot find SNMP header files under $SNMP_DIR)
  else
    AC_MSG_ERROR(Cannot find SNMP headers.  Use --with-snmp= to specify non-default path.)
  fi
fi

if test -n "$SNMP_LIBDIR" ; then
  LDFLAGS="-L$SNMP_LIBDIR $LDFLAGS"
fi

if test -n "$SNMP_INCDIR" ; then
  CFLAGS="-I$SNMP_INCDIR -I$SNMP_INCDIR/.. $CFLAGS"
fi

# Net-SNMP includes v3 support and insists on crypto unless compiled --without-openssl
AC_MSG_CHECKING([if Net-SNMP needs crypto support])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <net-snmp-config.h>]], [[return NETSNMP_USE_OPENSSL != 1;]])],
  [  AC_MSG_RESULT(yes)
     SNMP_SSL=yes
  ],[AC_MSG_RESULT(no)
])

AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ #include <net-snmp-config.h>
  #include <net-snmp/utilities.h>
  #include <net-snmp/net-snmp-includes.h>
  #include <net-snmp/config_api.h>
  #include <net-snmp/mib_api.h> ]], [[struct snmp_session session; snmp_sess_init(&session); session.localname = strdup("hello")]])],[havelocalname=1],[havelocalname=0
])
AC_DEFINE_UNQUOTED(SNMP_LOCALNAME, $havelocalname, If snmp localname session structure member exists)

AC_CHECK_LIB(netsnmp, snmp_timeout)

# ****************** Linker --wrap support (tests only) *********************
dnl The PHP runtime suite interposes on process and descriptor operations so
dnl destructive failure paths are deterministic. GNU ld and lld provide the
dnl required --wrap option; probe it so other supported linkers skip cleanly.
AC_MSG_CHECKING([whether the linker supports --wrap])
spine_save_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -Wl,--wrap=spine_ld_wrap_probe"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  int spine_ld_wrap_probe(void);
  int __wrap_spine_ld_wrap_probe(void);
  int __wrap_spine_ld_wrap_probe(void) { return 0; }
]], [[
  return spine_ld_wrap_probe();
]])],
  [spine_ld_wrap=yes],
  [spine_ld_wrap=no])
LDFLAGS="$spine_save_LDFLAGS"
AC_MSG_RESULT($spine_ld_wrap)
AM_CONDITIONAL([HAVE_LD_WRAP], [test "x$spine_ld_wrap" = "xyes"])

# ****************** SNMPv3 USM Error Constants Check ***********************
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
]])],
  [AC_MSG_RESULT([yes])],
  [AC_MSG_RESULT([no (USM error decoding disabled)])]
)

# ****************** USM DES Privacy Protocol Symbol Check ***********************
# Some distributions (e.g. Fedora) ship a net-snmp-config.h that advertises DES
# as the default privacy protocol (SNMP_DEFAULT_PRIV_PROTO expands to
# usmDESPrivProtocol) while the shipped libnetsnmp does not export that symbol,
# so referencing the header's own default fails to link. Probe for the actual
# symbol rather than trusting the header.
AC_MSG_CHECKING([for usmDESPrivProtocol in libnetsnmp])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
  #include <net-snmp/net-snmp-config.h>
  #include <net-snmp/net-snmp-includes.h>
]], [[
  return usmDESPrivProtocol[0];
]])],
  [AC_MSG_RESULT([yes])
   AC_DEFINE(HAVE_USM_DES_PRIV_PROTOCOL, 1, [Define if libnetsnmp exports usmDESPrivProtocol])],
  [AC_MSG_RESULT([no])]
)

# ****************** Spine Result Buffer Check ***********************
# Check for the default spine output buffer size
results_buffer=2048
AC_ARG_WITH(results-buffer,
  AS_HELP_STRING([--with-results-buffer=N],[The size of the spine results buffer (default=2048)]),
  [results_buffer=$withval]
)
AC_DEFINE_UNQUOTED(RESULTS_BUFFER, $results_buffer, The size of the spine result buffer)
AC_MSG_RESULT(checking for the spine results buffer size... $results_buffer bytes)

# ****************** Maximum Simultaneous Scripts ***********************
# Check for the most scripts that can be active at one time per spine process
max_scripts=20
AC_ARG_WITH(max-scripts,
  AS_HELP_STRING([--with-max-scripts=N],[The maximum simultaneous spine scripts that can run (default=20)]),
  [max_scripts=$withval]
)
AC_DEFINE_UNQUOTED(MAX_SIMULTANEOUS_SCRIPTS, $max_scripts, The maximum number of simultaneous running scripts)
AC_MSG_RESULT(checking for the maximum simultaneous spine scripts... $max_scripts)

# ****************** Maximum MySQL Buffer Size ***********************
# Check for the most scripts that can be active at one time per spine process
max_mysql_buffer=131072
AC_ARG_WITH(max-mysql-buffer,
  AS_HELP_STRING([--with-max-mysql-buffer=N],[The maximum SQL insert size allowed (default=131072)]),
  [max_mysql_buffer=$withval]
)
AC_DEFINE_UNQUOTED(MAX_MYSQL_BUF_SIZE, $max_mysql_buffer, The maximum MySQL buffer size to insert)
AC_MSG_RESULT(checking for the maximum MySQL buffer size... $max_mysql_buffer)

# ****************** Force Net-SNMP Version Checks ***********************
# If we should use the system popen or nifty popen
AC_MSG_CHECKING(whether to verify net-snmp library vs header versions)
AC_ARG_ENABLE(strict-snmp,
    [  --enable-strict-snmp    Enable checking of Net-SNMP library vs header versions  (default: disabled)],
    [ ENABLED_SNMP_VERSION=$enableval ],
    [ ENABLED_SNMP_VERSION=no ]
    )
if test "$ENABLED_SNMP_VERSION" = "yes"; then
  AC_MSG_RESULT([yes])
  AC_DEFINE(VERIFY_PACKAGE_VERSION, 1, If we are going to force Net-SNMP library and header versions to be the same)
else
  AC_MSG_RESULT([no])
fi

AC_MSG_CHECKING([if we can support mysql/mariadb retry count])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include <mysql.h>
  ]], [[
    if (MYSQL_OPT_RETRY_COUNT) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAS_MYSQL_OPT_RETRY_COUNT,1,[Do we have mysql/mariadb retry count capabilities?])
  ],[AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([if we mysql/mariadb supports verify certificates])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include <mysql.h>
  ]], [[
    if (MYSQL_OPT_SSL_VERIFY_SERVER_CERT) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAS_MYSQL_OPT_SSL_VERIFY_SERVER_CERT,1,[Do we have mysql/mariadb verify certificate support?])
  ],[AC_MSG_RESULT(no)
])

# See if we can support backtracing
AC_MSG_CHECKING([if we can support mysql/mariadb ssl keys])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include <mysql.h>
  ]], [[
    if (MYSQL_OPT_SSL_KEY) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAS_MYSQL_OPT_SSL_KEY,1,[Do we have mysql/mariadb ssl keys capabilities?])
  ],[AC_MSG_RESULT(no)
])

spine_saved_ldflags=$LDFLAGS
spine_linker_wrap=no
case "$host_os" in
  linux*)
    LDFLAGS="$LDFLAGS -Wl,--wrap=strftime"
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <time.h>
extern size_t __real_strftime(char *, size_t, const char *, const struct tm *);
size_t __wrap_strftime(char *out, size_t size, const char *format, const struct tm *time) {
  return __real_strftime(out, size, format, time);
}
]], [[return 0;]])], [spine_linker_wrap=yes], [])
    ;;
  *) ;;
esac
LDFLAGS=$spine_saved_ldflags
AM_CONDITIONAL([HAVE_LINKER_WRAP], [test "$spine_linker_wrap" = yes])

# ****************** Compiler and Linker Hardening ***********************
dnl Probe each flag with -Werror: clang only warns about options it ignores
dnl (-fstack-clash-protection and -pie on Darwin), and a warning would let the
dnl flag through without the protection. The accepted flags go in front of
dnl CPPFLAGS, CFLAGS and LDFLAGS so an explicit -fno-..., -no-pie or
dnl -U_FORTIFY_SOURCE from a packager or user still wins.
AC_ARG_ENABLE([hardening],
  AS_HELP_STRING([--disable-hardening],[Do not add compiler and linker hardening flags (default: enabled)]),
  [enable_hardening=$enableval],
  [enable_hardening=yes])

AC_DEFUN([SPINE_HARDEN_CFLAG],
[AS_VAR_PUSHDEF([spine_cv], [spine_cv_harden_cflag_$1])dnl
AC_CACHE_CHECK([whether $CC accepts $1], [spine_cv],
  [spine_save_CFLAGS=$CFLAGS
   CFLAGS="$CFLAGS $1 -Werror"
   AC_COMPILE_IFELSE([AC_LANG_PROGRAM()],
     [AS_VAR_SET([spine_cv], [yes])],
     [AS_VAR_SET([spine_cv], [no])])
   CFLAGS=$spine_save_CFLAGS])
AS_VAR_IF([spine_cv], [yes], [spine_hardening_cflags="$spine_hardening_cflags $1"])
AS_VAR_POPDEF([spine_cv])])

dnl Link probes run without LIBS: on Linux LIBS already names -lssl, and a
dnl missing library must not be mistaken for an unsupported linker flag.
AC_DEFUN([SPINE_HARDEN_LDFLAG],
[AS_VAR_PUSHDEF([spine_cv], [spine_cv_harden_ldflag_$1])dnl
AC_CACHE_CHECK([whether the linker accepts $1], [spine_cv],
  [spine_save_CFLAGS=$CFLAGS
   spine_save_LDFLAGS=$LDFLAGS
   spine_save_LIBS=$LIBS
   CFLAGS="$CFLAGS $spine_hardening_cflags -Werror"
   LDFLAGS="$LDFLAGS $spine_hardening_ldflags $1"
   LIBS=
   AC_LINK_IFELSE([AC_LANG_PROGRAM()],
     [AS_VAR_SET([spine_cv], [yes])],
     [AS_VAR_SET([spine_cv], [no])])
   CFLAGS=$spine_save_CFLAGS
   LDFLAGS=$spine_save_LDFLAGS
   LIBS=$spine_save_LIBS])
AS_VAR_IF([spine_cv], [yes], [spine_hardening_ldflags="$spine_hardening_ldflags $1"])
AS_VAR_POPDEF([spine_cv])])

spine_hardening_cppflags=
spine_hardening_cflags=
spine_hardening_ldflags=

if test "x$enable_hardening" != xno; then
  SPINE_HARDEN_CFLAG([-fstack-protector-strong])
  SPINE_HARDEN_CFLAG([-fstack-clash-protection])
  SPINE_HARDEN_CFLAG([-fcf-protection])
  SPINE_HARDEN_CFLAG([-Wformat -Wformat-security])

  dnl -static and -pie produce different, conflicting link modes.
  if test "x$with_static" != xyes; then
    SPINE_HARDEN_CFLAG([-fPIE])
    case " $spine_hardening_cflags " in
    *" -fPIE "*)
      SPINE_HARDEN_LDFLAG([-pie])
      case " $spine_hardening_ldflags " in
      *" -pie "*) ;;
      *) spine_hardening_cflags=`echo "$spine_hardening_cflags" | sed 's/ -fPIE//'` ;;
      esac
      ;;
    esac
  fi

  SPINE_HARDEN_LDFLAG([-Wl,-z,relro,-z,now])
  SPINE_HARDEN_LDFLAG([-Wl,-z,noexecstack])

  dnl Leave _FORTIFY_SOURCE alone when the compiler, a distro spec file or
  dnl the caller already set it, so a level 3 default is never lowered and
  dnl the macro is never redefined. glibc ignores it, with a warning, below
  dnl -O1, and it hides overflows from the ASan interceptors.
  AC_CACHE_CHECK([whether _FORTIFY_SOURCE is already defined],
    [spine_cv_fortify_preset],
    [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#include <stdio.h>
#ifndef _FORTIFY_SOURCE
#error not defined
#endif
]])],
      [spine_cv_fortify_preset=yes],
      [spine_cv_fortify_preset=no])])

  AC_CACHE_CHECK([whether optimization is enabled],
    [spine_cv_optimizing],
    [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#ifndef __OPTIMIZE__
#error not optimizing
#endif
]])],
      [spine_cv_optimizing=yes],
      [spine_cv_optimizing=no])])

  if test "x$spine_cv_fortify_preset" = xno &&
     test "x$spine_cv_optimizing" = xyes &&
     test "x$enable_sanitizers" != xyes; then
    dnl Level 3 needs __builtin_dynamic_object_size (GCC 12, Clang 9).
    AC_CACHE_CHECK([for the highest supported _FORTIFY_SOURCE level],
      [spine_cv_fortify_level],
      [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#if !defined(__has_builtin)
#error no __has_builtin
#elif !__has_builtin(__builtin_dynamic_object_size)
#error no __builtin_dynamic_object_size
#endif
]])],
        [spine_cv_fortify_level=3],
        [spine_cv_fortify_level=2])])
    spine_hardening_cppflags="-D_FORTIFY_SOURCE=$spine_cv_fortify_level"
  fi

  CPPFLAGS="$spine_hardening_cppflags $CPPFLAGS"
  CFLAGS="$spine_hardening_cflags $CFLAGS"
  LDFLAGS="$spine_hardening_ldflags $LDFLAGS"
fi

AC_MSG_NOTICE([hardening CPPFLAGS:${spine_hardening_cppflags:+ $spine_hardening_cppflags}])
AC_MSG_NOTICE([hardening CFLAGS:$spine_hardening_cflags])
AC_MSG_NOTICE([hardening LDFLAGS:$spine_hardening_ldflags])

# cmocka is only used by the unit tests under "make check".  Absence is not
# fatal; the tests are dropped from check_PROGRAMS instead.
have_cmocka=no
AC_CHECK_LIB([cmocka], [_cmocka_run_group_tests], [have_cmocka=yes])
if test "x$have_cmocka" = xyes; then
  AC_CHECK_HEADER([cmocka.h], [], [have_cmocka=no], [[
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
  ]])
fi

CMOCKA_LIBS=
if test "x$have_cmocka" = xyes; then
  CMOCKA_LIBS=-lcmocka
fi
AC_SUBST(CMOCKA_LIBS)
AM_CONDITIONAL([HAVE_CMOCKA], [test "x$have_cmocka" = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
