#ifndef RTG_COMMON_H
#define RTG_COMMON_H 1

#if HAVE_CONFIG_H
#  include "config.h"
#endif

#include <stdio.h>

#if STDC_HEADERS
#  include <stdlib.h>
#  include <string.h>
#elif HAVE_STRINGS_H
#  include <strings.h>
#endif /*STDC_HEADERS*/

#if HAVE_UNISTD_H
#  include <sys/types.h>
#  include <unistd.h>
#endif

#if HAVE_STDINT_H
#  include <stdint.h>
#endif

#if HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifndef HAVE_LIBPTHREAD
# define HAVE_LIBPTHREAD 0
#else
# include <pthread.h>
#endif

#include <signal.h>

#if HAVE_MYSQL
# include <mysql.h>
#endif

#if HAVE_RRDTOOL
# include <rrd.h>
#endif

#endif /* RTG_COMMON_H */
