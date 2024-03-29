# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2023 The Cacti Group                                 |
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

AC_PREREQ([2.63])
AC_INIT([Spine Poller],[1.3.0],[http://www.cacti.net/issues.php])

AC_CONFIG_AUX_DIR(config)
AC_SUBST(ac_aux_dir)

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR(spine.c)
AC_PREFIX_DEFAULT(/usr/local/spine)
AC_LANG(C)
AC_PROG_CC

AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_HEADERS(config/config.h)

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

# reentrant
MYSQL_REENTRANT=0
AC_ARG_WITH(reentrant,
  AS_HELP_STRING([--with-reentrant],[If using MySQL versions less than 5.5 you must choose this option
  ]),
  [MYSQL_REENTRANT=1]
)

# if host_alias is empty, ac_cv_host_alias may still have the info
if test -z "$host_alias"; then
  host_alias=$ac_cv_host_alias
fi

# Platform-specific tweaks
ShLib="so"

case $host_alias in
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
AC_PROG_CC
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
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_DIAGNOSE([obsolete],[your code may safely assume C89 semantics that RETSIGTYPE is void.
Remove this warning and the `AC_CACHE_CHECK' when you adjust the code.])dnl
AC_CACHE_CHECK([return type of signal handlers],[ac_cv_type_signal],[AC_COMPILE_IFELSE(
[AC_LANG_PROGRAM([#include <sys/types.h>
#include <signal.h>
],
		 [return *(signal (0, 0)) (0) == 1;])],
		   [ac_cv_type_signal=int],
		   [ac_cv_type_signal=void])])
AC_DEFINE_UNQUOTED([RETSIGTYPE],[$ac_cv_type_signal],[Define as the return type of signal handlers
		    (`int' or `void').])

AC_CHECK_FUNCS(malloc calloc gettimeofday strerror strtoll)

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

if test x$ENABLED_LCAP != xno; then
  if test x$FOUND_SYS_CAPABILITY_H != xno; then
    AC_MSG_RESULT([yes])
    AC_CHECK_LIB(cap, cap_init,
      [ LIBS="-lcap $LIBS"
        AC_DEFINE(HAVE_LCAP, 1, Linux Capabilities)
        HAVE_LCAP=yes ],
      [ AC_MSG_RESULT(Cannot find Linux Capabilities library(cap)...)
        HAVE_LCAP=no ]
    )
  else
    AC_MSG_RESULT([no])
  fi
else
  AC_MSG_RESULT([no])
fi

# ****************** MySQL Checks ***********************
AC_DEFUN([MYSQL_LIB_CHK],
  [ str="$1/libmysqlclient.*"
    for j in `echo $str`; do
      if test -r $j; then
        MYSQL_LIB_DIR=$1
        break 2
      fi
    done
  ]
)

# Determine MySQL installation paths
MYSQL_SUB_DIR="include include/mysql include/mariadb mysql";
for i in $MYSQL_DIR /usr /usr/local /opt /opt/mysql /usr/pkg /usr/local/mysql; do
  for d in $MYSQL_SUB_DIR; do
    if [[ -f $i/$d/mysql.h ]]; then
      MYSQL_INC_DIR=$i/$d
      break;
    fi
  done

  if [[ ! -z $MYSQL_INC_DIR ]]; then
    break;
  fi
#  test -f $i/include/mysql.h          && MYSQL_INC_DIR=$i/include          && break
#  test -f $i/include/mysql/mysql.h    && MYSQL_INC_DIR=$i/include/mysql    && break
#  test -f $i/include/mariadb/mysql.h  && MYSQL_INC_DIR=$i/include/mariadb  && break
#  test -f $i/mysql/include/mysql.h    && MYSQL_INC_DIR=$i/mysql/include    && break
done

if test -z "$MYSQL_INC_DIR"; then
  if test "x$MYSQL_DIR" != "x"; then
    AC_MSG_ERROR(Cannot find MySQL header files under $MYSQL_DIR)
  else
    AC_MSG_ERROR(Cannot find MySQL headers.  Use --with-mysql= to specify non-default path.)
  fi
fi

for i in $MYSQL_DIR /usr /usr/local /opt /opt/mysql /usr/pkg /usr/local/mysql; do
  MYSQL_LIB_CHK($i/lib64)
  MYSQL_LIB_CHK($i/lib64/mysql)
  MYSQL_LIB_CHK($i/lib/x86_64-linux-gnu)
  MYSQL_LIB_CHK($i/lib/x86_64-linux-gnu/mysql)
  MYSQL_LIB_CHK($i/lib)
  MYSQL_LIB_CHK($i/lib/mysql)
done

if test -n "$MYSQL_LIB_DIR" ; then
  LDFLAGS="-L$MYSQL_LIB_DIR $LDFLAGS"
fi
  CFLAGS="-I$MYSQL_INC_DIR $CFLAGS"

unamestr=$(uname)
if test $unamestr = 'OpenBSD'; then
  AC_CHECK_LIB(mysqlclient, mysql_init,
    [ LIBS="-lmysqlclient -lexecinfo -lm $LIBS"
      AC_DEFINE(HAVE_MYSQL, 1, MySQL Client API)
      HAVE_MYSQL=yes ],
    [ HAVE_MYSQL=no ]
  )
else
  AC_CHECK_LIB(mysqlclient, mysql_init,
    [ LIBS="-lmysqlclient -lm -ldl $LIBS"
      AC_DEFINE(HAVE_MYSQL, 1, MySQL Client API)
      HAVE_MYSQL=yes ],
    [ HAVE_MYSQL=no ]
  )
fi

if test $MYSQL_REENTRANT = 1 ; then
  LIBS="-lmysqlclient_r -lm -ldl $LIBS"
else
  if test -f $MYSQL_LIB_DIR/libmysqlclient_r.a -o -f $MYSQL_LIB_DIR/libmysqlclient_r.$ShLib; then
    LIBS="-lmysqlclient_r -lm -ldl $LIBS"
  else
    if test -f $MYSQL_LIB_DIR/libmysqlclient_r.a -o -f $MYSQL_LIB_DIR/libmysqlclient_r.$ShLib ; then
      LIBS="-lmysqlclient_r -lm -ldl $LIBS"
    else
      if test "$HAVE_MYSQL" = "yes"; then
        if test $unamestr = 'OpenBSD'; then
          LIBS="-lmysqlclient -lm $LIBS"
        else
          LIBS="-lmysqlclient -lm -ldl $LIBS"
        fi
      else
        if test -f $MYSQL_LIB_DIR/libperconaserverclient.a -o -f $MYSQL_LIB_DIR/libperconaserverclient.$ShLib; then
          LIBS="-lperconaserverclient -lm -ldl $LIBS"
        else
          LIBS="-lmariadbclient -lm -ldl $LIBS"
        fi
      fi
    fi
  fi
fi

# ****************** Net-SNMP Checks ***********************
if test "x$SNMP_DIR" != "x"; then
  for i in / /net-snmp /include/net-snmp; do
    test -f $SNMP_DIR/$i/net-snmp-config.h  && SNMP_INCDIR=$SNMP_DIR$i && break
  done

  # Accomodate 64-Bit Libraries
  test -f $SNMP_DIR/lib64/libnetsnmp.a -o -f $SNMP_DIR/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$SNMP_DIR/lib64

  if test -z "$SNMP_LIBDIR"; then
    # Accomodate 32-Bit Libraries
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

  # Accomodate 64-Bit Libraries
  for i in /usr /usr/local /usr/pkg /usr/snmp /opt /opt/net-snmp /opt/snmp /usr/local/snmp; do
    test -f $i/lib64/libnetsnmp.a -o -f $i/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$i/lib64 && break
  done

  # Only check for 32 Bit libraries if the 64 bit are not found
  if test -z "$SNMP_LIBDIR"; then
    # Accomodate 32-Bit Libraries
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
AC_TRY_COMPILE([#include <net-snmp-config.h>], [return NETSNMP_USE_OPENSSL != 1;],
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

# ****************** Traditional Popen Check ***********************
# If we should use the system popen or nifty popen
AC_MSG_CHECKING(whether we are using traditional popen)
AC_ARG_ENABLE(popen,
    [  --enable-popen          Enable the traditional popen implementation of nifty popen (default: disabled)],
    [ ENABLED_TPOPEN=$enableval ],
    [ ENABLED_TPOPEN=no ]
    )
if test "$ENABLED_TPOPEN" = "yes"; then
  AC_MSG_RESULT([yes])
  AC_DEFINE(USING_TPOPEN, 1, If traditional popen should be enabled by default)
else
  AC_MSG_RESULT([no])
fi

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
  AC_DEFINE(VERIFY_PACKAGE_VERSION, 1, If we are going to force Net-SNMP library and header versons to be the same)
else
  AC_MSG_RESULT([no])
fi

# See if we can support backtracing
AC_MSG_CHECKING([if we can support backtracing])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include <execinfo.h>
  ]], [[
    void *array[10];
    size_t size;

    // get void*'s for all entries on the stack
    size = backtrace(array, 10);
    if (size) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_EXECINFO_H,1,[Do we have backtracing capabilities?])
  ],[AC_MSG_RESULT(no)
])

# See if we can support backtracing
AC_MSG_CHECKING([if we can support mysql/mariadb retry count])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include "$MYSQL_INC_DIR/mysql.h"
  ]], [[
    if (MYSQL_OPT_RETRY_COUNT) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAS_MYSQL_OPT_RETRY_COUNT,1,[Do we have mysql/maraidb retry count capabilities?])
  ],[AC_MSG_RESULT(no)
])

# See if we can support backtracing
AC_MSG_CHECKING([if we can support mysql/mariadb ssl keys])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <stdlib.h>
    #include "$MYSQL_INC_DIR/mysql.h"
  ]], [[
    if (MYSQL_OPT_SSL_KEY) {
      exit(0);
    } else {
      exit(1);
    }
  ]])],[  AC_MSG_RESULT(yes)
     AC_DEFINE(HAS_MYSQL_OPT_SSL_KEY,1,[Do we have mysql/maraidb ssl keys capabilities?])
  ],[AC_MSG_RESULT(no)
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
