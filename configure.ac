AC_PREREQ(2.53)
AC_INIT(cactid.h)

AC_CONFIG_AUX_DIR(config)
AC_SUBST(ac_aux_dir)

AC_CANONICAL_HOST
AC_CONFIG_SRCDIR(cactid.c)
AC_PREFIX_DEFAULT(/usr/local/cactid)
AC_LANG(C)

AM_INIT_AUTOMAKE(cactid, 0.8.5)
AM_CONFIG_HEADER(config/config.h)

# mysql
AC_ARG_WITH(mysql,
	AC_HELP_STRING(
		[--with-mysql],
		[MySQL include directory [[/usr/include/mysql]]]),
	[MYSQL_DIR=$withval],
	[MYSQL_DIR="/usr"])

# snmp
AC_ARG_WITH(snmp,
	AC_HELP_STRING(
		[--with-snmp],
		[SNMP include base directory [[/usr/(local/)include]]]),
	[SNMP_DIR=$withval])


# if host_alias is empty, ac_cv_host_alias may still have the info
if test -z "$host_alias"; then
    host_alias=$ac_cv_host_alias
fi

# Platform-specific tweaks
case $host_alias in
*solaris*)
    CPPFLAGS="$CPPFLAGS -D_POSIX_PTHREAD_SEMANTICS";;
*freebsd*)
    LIBS="$LIBS -pthread"
    AC_DEFINE(HAVE_LIBPTHREAD, 1);;
esac

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AC_MSG_CHECKING([whether to enable -Wall])
AC_ARG_ENABLE(warnings,
  [  --enable-warnings       Enable -Wall if using gcc.],
  [ if test -n "$GCC"; then
    AC_MSG_RESULT(adding -Wall to CFLAGS.)
        CFLAGS="$CFLAGS -Wall"	
   fi],AC_MSG_RESULT(no))

# Checks for libraries.
AC_CHECK_LIB(kstat, kstat_lookup)
AC_CHECK_LIB(nsl, gethostbyname)
AC_CHECK_LIB(socket, socket)
AC_CHECK_LIB(m, floor)
AC_CHECK_LIB(pthread, pthread_exit)
# Some builds of MySQL require libz - try to detect
AC_CHECK_LIB(z, deflate)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS(malloc.h ctype.h sys/time.h netinet/in.h)

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_TYPES([unsigned long long, long long])
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_TYPE_SIGNAL
AC_CHECK_FUNCS(gettimeofday strerror strtoll)

# ****************** MySQL Checks ***********************

AC_DEFUN(MYSQL_LIB_CHK,[
	str="$1/libmysqlclient.*"
	for j in `echo $str`; do
		if test -r $j; then
		MYSQL_LIB_DIR=$1
		break 2
	fi
	done
])

# Determine MySQL installation paths
for i in $MYSQL_DIR /usr/local /usr/local/mysql; do
   test -f $i/include/mysql.h                    && MYSQL_INC_DIR=$i/include
   test -f $i/include/mysql/mysql.h              && MYSQL_INC_DIR=$i/include/mysql
   test -f $i/mysql/include/mysql.h              && MYSQL_INC_DIR=$i/mysql/include
done

if test -z "$MYSQL_INC_DIR"; then
  if test "x$MYSQL_DIR" != "x"; then
    AC_MSG_ERROR(Cannot find MySQL header files under $MYSQL_DIR)
  else
    AC_MSG_ERROR(Cannot find MySQL headers.  Use --with-mysql= to specify non-default path.)
  fi
fi

for i in $MYSQL_DIR /usr/local /usr/local/mysql; do
   MYSQL_LIB_CHK($i/lib)
   MYSQL_LIB_CHK($i/lib/mysql)
done

LDFLAGS="-L$MYSQL_LIB_DIR $LDFLAGS"
CFLAGS="-I$MYSQL_INC_DIR $CFLAGS"

AC_CHECK_LIB(mysqlclient, mysql_init, LIBS="-lmysqlclient $LIBS",
	AC_MSG_ERROR([MySQL libraries not found.]))
AC_CHECK_LIB(mysqlclient, mysql_thread_init, [],
	AC_DEFINE(OLD_MYSQL, 1, [Old MySQL version]))

# ****************** Net-SNMP/UCD-SNMP Checks ***********************
	
# Determine UCD or Net-SNMP installation paths
if test "x$SNMP_DIR" != "x"; then
    for i in / /ucd-snmp /include/ucd-snmp; do
       test -f $SNMP_DIR/$i/snmp.h             && SNMP_INCDIR=$SNMP_DIR$i
    done
    for i in / /net-snmp /include/net-snmp; do
       test -f $SNMP_DIR/$i/net-snmp-config.h  && SNMP_INCDIR=$SNMP_DIR$i
    done
    
    test -f $SNMP_DIR/lib/libsnmp.a -o -f $SNMP_DIR/lib/libsnmp.so && SNMP_LIBDIR=$SNMP_DIR/lib
    test -f $SNMP_DIR/lib/libnetsnmp.a -o -f $SNMP_DIR/lib/libnetsnmp.so && SNMP_LIBDIR=$SNMP_DIR/lib
else
    for i in /usr/include /usr/local/include; do
      test -f $i/snmp.h                       && SNMP_INCDIR=$i
      test -f $i/ucd-snmp/snmp.h              && SNMP_INCDIR=$i/ucd-snmp
      test -f $i/net-snmp/net-snmp-config.h   && SNMP_INCDIR=$i/net-snmp
      test -f $i/snmp/snmp.h                  && SNMP_INCDIR=$i/snmp
      test -f $i/snmp/include/ucd-snmp/snmp.h && SNMP_INCDIR=$i/snmp/include/ucd-snmp
      test -f $i/snmp/include/net-snmp/net-snmp-config.h && SNMP_INCDIR=$i/snmp/include/net-snmp
    done
    for i in /usr /usr/snmp /usr/local /usr/local/snmp; do
      test -f $i/lib/libsnmp.a -o -f $i/lib/libsnmp.so && SNMP_LIBDIR=$i/lib
      test -f $i/lib/libnetsnmp.a -o -f $i/lib/libnetsnmp.so && SNMP_LIBDIR=$i/lib
    done
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
     SNMP_SSL=yes ],
  AC_MSG_RESULT(no))
AC_MSG_CHECKING([if Net-SNMP needs crypto support])
AC_TRY_COMPILE([#include <net-snmp-config.h>], [exit(USE_OPENSSL != 1);],
  [  AC_MSG_RESULT(yes)
     SNMP_SSL=yes ],
  AC_MSG_RESULT(no))

if test "$SNMP_SSL" = "yes"; then
  LDFLAGS="-L/usr/local/ssl/lib $LDFLAGS"
  AC_CHECK_LIB(crypto, CRYPTO_free,[],[AC_MSG_ERROR(libcrypto not found!)])
fi

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

AC_OUTPUT(Makefile)
