AC_PREREQ(2.53)
AC_INIT(Spine Poller, 0.8.7c-beta2, http://www.cacti.net/bugs.php)

AC_CONFIG_AUX_DIR(config)
AC_SUBST(ac_aux_dir)

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR(spine.c)
AC_PREFIX_DEFAULT(/usr/local/spine)
AC_LANG(C)

AM_INIT_AUTOMAKE(spine, 0.8.7c-beta2)
AM_CONFIG_HEADER(config/config.h)

# static libraries
AC_ARG_WITH(static,
  AC_HELP_STRING(
    [--with-static],
    [Build using static libraries]
  ),
  [CFLAGS="-static $CFLAGS"]
)

# mysql
AC_ARG_WITH(mysql,
  AC_HELP_STRING(
    [--with-mysql],
    [MySQL include directory [[/usr/include/mysql]]]
  ),
  [MYSQL_DIR=$withval]
)

# snmp
AC_ARG_WITH(snmp,
  AC_HELP_STRING(
    [--with-snmp],
    [SNMP include base directory [[/usr/(local/)include]]]
  ),
  [SNMP_DIR=$withval]
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

# ****************** MySQL Checks ***********************

AC_DEFUN([MYSQL_LIB_CHK],
  [ str="$1/libmysqlclient_r.*"
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

LDFLAGS="-L$MYSQL_LIB_DIR $LDFLAGS"
CFLAGS="-I$MYSQL_INC_DIR $CFLAGS"

AC_CHECK_LIB(mysqlclient_r,mysql_init, LIBS="-lmysqlclient_r $LIBS",
  AC_MSG_ERROR([MySQL libraries not found])
)

AC_CHECK_LIB(mysqlclient_r,mysql_thread_init,[],
  AC_DEFINE(OLD_MYSQL, 1, [Old MySQL version])
)

# ****************** Net-SNMP/UCD-SNMP Checks ***********************

# Determine UCD or Net-SNMP installation paths
if test "x$SNMP_DIR" != "x"; then
  for i in / /ucd-snmp /include/ucd-snmp; do
    test -f $SNMP_DIR/$i/snmp.h             && SNMP_INCDIR=$SNMP_DIR$i && break
  done

  for i in / /net-snmp /include/net-snmp; do
    test -f $SNMP_DIR/$i/net-snmp-config.h  && SNMP_INCDIR=$SNMP_DIR$i && break
  done

  # Accomodate 64-Bit Libraries
  test -f $SNMP_DIR/lib64/libsnmp.a -o -f $SNMP_DIR/lib64/libsnmp.$ShLib       && SNMP_LIBDIR=$SNMP_DIR/lib64
  test -f $SNMP_DIR/lib64/libnetsnmp.a -o -f $SNMP_DIR/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$SNMP_DIR/lib64

  if test -z "$SNMP_LIBDIR"; then
    # Accomodate 32-Bit Libraries
    test -f $SNMP_DIR/lib/libsnmp.a -o -f $SNMP_DIR/lib/libsnmp.$ShLib       && SNMP_LIBDIR=$SNMP_DIR/lib
    test -f $SNMP_DIR/lib/libnetsnmp.a -o -f $SNMP_DIR/lib/libnetsnmp.$ShLib && SNMP_LIBDIR=$SNMP_DIR/lib
  fi
else
  for i in /usr /usr/local /usr/include /usr/pkg/include /usr/local/include /opt /opt/ucd-snmp /opt/net-snmp /opt/snmp; do
    test -f $i/snmp.h                                  && SNMP_INCDIR=$i                       && break
    test -f $i/ucd-snmp/snmp.h                         && SNMP_INCDIR=$i/ucd-snmp              && break
    test -f $i/include/net-snmp/net-snmp-config.h      && SNMP_INCDIR=$i/include/net-snmp      && break
    test -f $i/net-snmp/net-snmp-config.h              && SNMP_INCDIR=$i/net-snmp              && break
    test -f $i/net-snmp/include/net-snmp-config.h      && SNMP_INCDIR=$i/net-snmp/include      && break
    test -f $i/snmp/snmp.h                             && SNMP_INCDIR=$i/snmp                  && break
    test -f $i/snmp/include/ucd-snmp/snmp.h            && SNMP_INCDIR=$i/snmp/include/ucd-snmp && break
    test -f $i/snmp/include/net-snmp/net-snmp-config.h && SNMP_INCDIR=$i/snmp/include/net-snmp && break
  done

  # Accomodate 64-Bit Libraries
  for i in /usr /usr/local /usr/pkg /usr/snmp /opt /opt/net-snmp /opt/ucd-snmp /opt/snmp /usr/local/snmp; do
    test -f $i/lib64/libsnmp.a -o -f $i/lib64/libsnmp.$ShLib       && SNMP_LIBDIR=$i/lib64 && break
    test -f $i/lib64/libnetsnmp.a -o -f $i/lib64/libnetsnmp.$ShLib && SNMP_LIBDIR=$i/lib64 && break
  done

  # Only check for 32 Bit libraries if the 64 bit are not found
  if test -z "$SNMP_LIBDIR"; then
    # Accomodate 32-Bit Libraries
    for i in /usr /usr/local /usr/pkg /usr/snmp /opt /opt/net-snmp /opt/ucd-snmp /opt/snmp /usr/local/snmp; do
      test -f $i/lib/libsnmp.a -o -f $i/lib/libsnmp.$ShLib       && SNMP_LIBDIR=$i/lib && break
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

LDFLAGS="-L$SNMP_LIBDIR $LDFLAGS"
CFLAGS="-I$SNMP_INCDIR -I$SNMP_INCDIR/.. $CFLAGS"

# Net/UCD-SNMP includes v3 support and insists on crypto unless compiled --without-openssl
AC_MSG_CHECKING([if UCD-SNMP needs crypto support])
SNMP_SSL=no
AC_TRY_COMPILE([#include <ucd-snmp-config.h>], [exit(USE_OPENSSL != 1);],
  [  AC_MSG_RESULT(yes)
     SNMP_SSL=yes
  ],
  AC_MSG_RESULT(no)
)

AC_MSG_CHECKING([if Net-SNMP needs crypto support])
AC_TRY_COMPILE([#include <net-snmp-config.h>], [exit(USE_OPENSSL != 1);],
  [  AC_MSG_RESULT(yes)
     SNMP_SSL=yes
  ],
  AC_MSG_RESULT(no)
)

AC_CHECK_LIB(netsnmp, snmp_timeout,
  [ LIBS="-lnetsnmp $LIBS"
    AC_DEFINE(USE_NET_SNMP, 1, New Net SNMP Version)
    USE_NET_SNMP=yes ],
    [ AC_MSG_RESULT(Cannot find NET-SNMP libraries(snmp)... checking UCD-SNMP)
    USE_NET_SNMP=no ])

if test "$USE_NET_SNMP" = "no"; then
  AC_CHECK_LIB(snmp, snmp_timeout,
    LIBS="-lsnmp $LIBS",
    AC_MSG_ERROR(Cannot find UCD-SNMP libraries(snmp)))
fi

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
AC_DEFINE_UNQUOTED(MAX_SIMULTANEOUS_SCRIPTS, $results_buffer, The maximum number of simultaneous running scripts)
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

# ****************** Nifty Popen Check ***********************
# If we should use the system popen or nifty popen
AC_MSG_CHECKING(whether we are using nifty popen)
AC_ARG_ENABLE(nifty-popen,
    [  --enable-nifty-popen    Enable the nifty popen implementation of popen (default: disabled)],
    [ ENABLED_NIFTY=$enableval ],
    [ ENABLED_NIFTY=no ]
    )
if test "$ENABLED_NIFTY" = "yes"; then
  AC_MSG_RESULT([yes])
  AC_DEFINE(USING_NIFTY, 1, If nifty popen should be enabled by default)
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
