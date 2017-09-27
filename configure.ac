AC_PREREQ(2.53)
AC_INIT(Spine Poller, 1.1.25, http://www.cacti.net/issues.php)

AC_CONFIG_AUX_DIR(config)
AC_SUBST(ac_aux_dir)

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR(spine.c)
AC_PREFIX_DEFAULT(/usr/local/spine)
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign])
AM_CONFIG_HEADER(config/config.h)

# static libraries
AC_ARG_WITH(static,
  AC_HELP_STRING(
    [--with-static],
    [Build using static libraries]
  ),
  [CFLAGS="-static $CFLAGS"]
)

AC_CONFIG_MACRO_DIR([m4])

# mysql
AC_ARG_WITH(mysql,
  AC_HELP_STRING(
    [--with-mysql],
    [MySQL base directory [[/usr/local/mysql]]]
  ),
  [MYSQL_DIR=$withval]
)

# snmp
AC_ARG_WITH(snmp,
  AC_HELP_STRING(
    [--with-snmp],
    [SNMP base directory [[/usr/(local/)include]]]
  ),
  [SNMP_DIR=$withval]
)

# reentrant
MYSQL_REENTRANT=0
AC_ARG_WITH(reentrant,
  AC_HELP_STRING(
    [--with-reentrant],
    [If using MySQL versions less than 5.5 you must choose this option]
  ),
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
  LIBS="$LIBS -pthread"
  AC_DEFINE(HAVE_LIBPTHREAD, 1);;
*darwin*)
  ShLib="dylib";;
*)
  LDFLAGS="-lpthread -lssl -lm $LDFLAGS";;
esac

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL

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

# On some systems, gethostbyname() is thread-safe
AC_ARG_ENABLE(threadsafe_gethostbyname,
  AC_HELP_STRING(
    [--enable-threadsafe-gethostbyname],
	  [Assume gethostbyname() is threadsafe]
	)
)

# Check if the user told use gethostbyname() is thread-safe.
AC_MSG_CHECKING([for threadsafe gethostbyname()])
if test "x$enable_threadsafe_gethostbyname" = "xyes" ; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_GETHOSTBYNAME_THREADSAFE, 1, 
	[Define if gethostbyname is threadsafe])
  HAVE_GETHOSTBYNAME_THREADSAFE=yes
else
  AC_MSG_RESULT(no)
fi

# Checks for libraries.
AC_CHECK_LIB(nls, gethostbyname_r)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, floor)
AC_CHECK_LIB(pthread, pthread_exit)

# Some builds of MySQL require libz - try to detect
AC_CHECK_LIB(z, deflate)
AC_CHECK_LIB(kstat, kstat_close)
AC_CHECK_LIB(crypto, CRYPTO_realloc)

# Checks for header files.
AC_HEADER_STDC
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
AC_TYPE_SIGNAL
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
      [If upport for Solaris privileges should be enabled]
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
for i in $MYSQL_DIR /usr /usr/local /opt /opt/mysql /usr/pkg /usr/local/mysql; do
  test -f $i/include/mysql.h        && MYSQL_INC_DIR=$i/include        && break
  test -f $i/include/mysql/mysql.h  && MYSQL_INC_DIR=$i/include/mysql  && break
  test -f $i/mysql/include/mysql.h  && MYSQL_INC_DIR=$i/mysql/include  && break
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
  MYSQL_LIB_CHK($i/lib)
  MYSQL_LIB_CHK($i/lib/mysql)
done

if test -n "$MYSQL_LIB_DIR" ; then
  LDFLAGS="-L$MYSQL_LIB_DIR $LDFLAGS"
fi
CFLAGS="-I$MYSQL_INC_DIR $CFLAGS"

if test $MYSQL_REENTRANT = 0 ; then
  LIBS="-lmysqlclient $LIBS"
else
  LIBS="-lmysqlclient_r $LIBS"
fi

# Net-SNMP includes v3 support and insists on crypto unless compiled --without-openssl
AC_MSG_CHECKING([if Net-SNMP needs crypto support])
AC_TRY_COMPILE([#include <net-snmp-config.h>], [exit(NETSNMP_USE_OPENSSL != 1);],
  [  AC_MSG_RESULT(yes)
     SNMP_SSL=yes
  ],
  AC_MSG_RESULT(no)
)

AC_TRY_COMPILE([ #include <net-snmp-config.h> 
  #include <net-snmp/utilities.h>
  #include <net-snmp/net-snmp-includes.h>
  #include <net-snmp/config_api.h>
  #include <net-snmp/mib_api.h> ], 
  [struct snmp_session session; snmp_sess_init(&session); session.localname = strdup("hello")],
  havelocalname=1,
  havelocalname=0
)
AC_DEFINE_UNQUOTED(SNMP_LOCALNAME, $havelocalname, If snmp localname session structure member exists)

AC_CHECK_LIB(netsnmp, snmp_timeout)

# ****************** Spine Result Buffer Check ***********************
# Check for the default spine output buffer size
results_buffer=1024
AC_ARG_WITH(results-buffer,
  AC_HELP_STRING([--with-results-buffer=N], [The size of the spine results buffer (default=1024)]),
  [results_buffer=$withval]
)
AC_DEFINE_UNQUOTED(RESULTS_BUFFER, $results_buffer, The size of the spine result buffer)
AC_MSG_RESULT(checking for the spine results buffer size... $results_buffer bytes)

# ****************** Maximum Simultaneous Scripts ***********************
# Check for the most scripts that can be active at one time per spine process
max_scripts=20
AC_ARG_WITH(max-scripts,
  AC_HELP_STRING([--with-max-scripts=N], [The maximum simultaneous spine scripts that can run (default=20)]),
  [max_scripts=$withval]
)
AC_DEFINE_UNQUOTED(MAX_SIMULTANEOUS_SCRIPTS, $max_scripts, The maximum number of simultaneous running scripts)
AC_MSG_RESULT(checking for the maximum simultaneous spine scripts... $max_scripts)

# ****************** Maximum MySQL Buffer Size ***********************
# Check for the most scripts that can be active at one time per spine process
max_mysql_buffer=65536
AC_ARG_WITH(max-mysql-buffer,
  AC_HELP_STRING([--with-max-mysql-buffer=N], [The maximum SQL insert size allowed (default=65536)]),
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

# ****************** gethostbyname_r Check ***********************
# Linux Variant
AC_MSG_CHECKING([for glibc gethostbyname_r])
AC_TRY_LINK([#include <netdb.h>],
  [struct hostent result_buf;
    char buf[1024];
    struct hostent *result;
    int h_erropp;
    gethostbyname_r("localhost",
      &result_buf,
      buf,
      sizeof(buf),
      &result,
      &h_erropp);
  ],
  [AC_MSG_RESULT([yes])
   AC_DEFINE(HAVE_GETHOSTBYNAME_R_GLIBC, 1, [Using glibc versionf of gethostbyname_r()])
   HAVE_GETHOSTBYNAME_R=yes
  ],
  [AC_MSG_RESULT([no])]
)

# Solaris or Irix Check
AC_MSG_CHECKING([for Solaris/Irix gethostbyname_r])
AC_TRY_LINK([#include <netdb.h>],
  [struct hostent result;
   char buf[1024];
   int h_errnop;
   gethostbyname_r("localhost",
     &result,
     buf,
     sizeof(buf),
     &h_errnop);
  ],
  [AC_MSG_RESULT([yes])
   AC_DEFINE(HAVE_GETHOSTBYNAME_R_SOLARIS, 1, [Using Solaris gethostbyname_r()])
   HAVE_GETHOSTBYNAME_R=yes
  ],
  [AC_MSG_RESULT([no])]
)

# HP-UX Check
AC_MSG_CHECKING([for HP-UX gethostbyname_r])
AC_TRY_LINK([#include <netdb.h>],
  [struct hostent result;
   char buf[1024];
   gethostbyname_r("localhost",
     &result,
     buf);
  ],
  [AC_MSG_RESULT([yes])
   AC_DEFINE(HAVE_GETHOSTBYNAME_R_HPUX, 1, [Using HPUX gethostbyname_r()])
   HAVE_GETHOSTBYNAME_R=yes],
  [AC_MSG_RESULT([no])]
)

# Not Found, Use Mutex Locking
if test -z "$HAVE_GETHOSTBYNAME_R"; then
	AC_DEFINE(HAVE_GETHOSTBYNAME_R_MUTEX_LOCK, 1, [Using traditional of gethostbyname_r()])
	HAVE_GETHOSTBYNAME_R=yes
fi

AC_OUTPUT(Makefile)
