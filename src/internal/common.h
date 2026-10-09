/*
 * SPDX-FileCopyrightText: 2004-2026 The Cacti Group
 * SPDX-License-Identifier: LGPL-2.1-or-later
 *
 * Fork maintenance: Thomas Vincent.
 * Project contributor history: CONTRIBUTORS.md.
 *
 * Original credits:
 * - Larry Adams (current development and enhancements)
 * - Rivo Nurges (rrd support, mysql poller cache, misc functions)
 * - RTG (core poller code, pthreads, snmp, autoconf examples)
 * - Brady Alleman/Doug Warner (threading ideas, implementation details)
 * - Cacti - http://www.cacti.net/
 */

#ifndef SPINE_COMMON_H
#define SPINE_COMMON_H 1

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

/* Cygwin supports only 64 open file descriptors, let's increase it a bit. */
#define FD_SETSIZE 512
#endif /* __CYGWIN__ */

#define _THREAD_SAFE
#define _PTHREADS
#define _P __P

#ifndef _REENTRANT
#define _REENTRANT
#endif

#ifndef _LIBC_REENTRANT
#define _LIBC_REENTRANT
#endif

#define PTHREAD_MUTEXATTR_DEFAULT ((pthread_mutexattr_t *) 0)

#ifndef SPINE_BUILD_CONFIG_H_INCLUDED
#define SPINE_BUILD_CONFIG_H_INCLUDED
#include "config/config.h"
#endif

#if STDC_HEADERS
#include <stdlib.h>
#include <string.h>
#elif HAVE_STRINGS_H
#include <strings.h>
#endif /*STDC_HEADERS*/

#if HAVE_UNISTD_H
#include <sys/types.h>
#include <unistd.h>
#endif

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <mysql.h>
#include <netdb.h>
#include "platform/spine_sem.h"
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <arpa/inet.h>

#if HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#ifndef __CYGWIN__
#include <netinet/icmp6.h>
#endif
#include <netinet/ip_icmp.h>
#endif

#if HAVE_NET_IF_H
#include <net/if.h>
#endif

#if HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <time.h>

#ifndef HAVE_LIBPTHREAD
#define HAVE_LIBPTHREAD 0
#else
#include <pthread.h>
#endif

#ifdef SOLAR_PRIV
#include <priv.h>
#endif

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/library/snmpv3.h>
#include <net-snmp/library/snmp_parse_args.h>
#include <net-snmp/utilities.h>

#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_client.h>
#include <net-snmp/library/mib.h>
#include <net-snmp/library/scapi.h>
#include <net-snmp/library/keytools.h>
#include <net-snmp/library/transform_oids.h>

#ifdef HAVE_LCAP
#include <sys/capability.h>
#include <sys/prctl.h>
#include <grp.h>
#endif

#include "uthash.h"

#endif /* SPINE_COMMON_H */
