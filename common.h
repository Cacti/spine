/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004 Ian Berry                                            |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU General Public License             |
 | as published by the Free Software Foundation; either version 2          |
 | of the License, or (at your option) any later version.                  |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU General Public License for more details.                            |
 +-------------------------------------------------------------------------+
 | cactid: a backend data gatherer for cacti                               |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - raXnet - http://www.raxnet.net/                                       |
 +-------------------------------------------------------------------------+
*/

#ifndef CACTID_COMMON_H
#define CACTID_COMMON_H 1

#ifdef __CYGWIN__
/* We use a Unix API, so pretend it's not Windows */
#undef WIN
#undef WIN32
#undef _WIN
#undef _WIN32
#undef _WIN64
#undef __WIN__
#undef __WIN32__
#define HAVE_ERRNO_AS_DEFINE
#endif /* __CYGWIN__ */

#define _THREAD_SAFE
#define _PTHREADS
#define _P __P

#ifndef _REENTRANT 
#define _REENTRANT 
#endif 

#define PTHREAD_MUTEXATTR_DEFAULT ((pthread_mutexattr_t *) 0)

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

#endif /* CACTID_COMMON_H */
