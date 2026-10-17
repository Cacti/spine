/*
 ex: set tabstop=4 shiftwidth=4 autoindent:
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version.      |
 |                                                                         |
 | This program is distributed in the hope that it will be useful,         |
 | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 | GNU Lesser General Public License for more details.                     |
 |                                                                         |
 | You should have received a copy of the GNU Lesser General Public        |
 | License along with this library; if not, write to the Free Software     |
 | Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA           |
 | 02110-1301, USA                                                         |
 |                                                                         |
 +-------------------------------------------------------------------------+
 | spine: a backend data gatherer for cacti                                |
 +-------------------------------------------------------------------------+
 | This poller would not have been possible without:                       |
 |   - Larry Adams (current development and enhancements)                  |
 |   - Rivo Nurges (rrd support, mysql poller cache, misc functions)       |
 |   - RTG (core poller code, pthreads, snmp, autoconf examples)           |
 |   - Brady Alleman/Doug Warner (threading ideas, implementation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

#ifndef SPINE_CONSTANTS_H
#define SPINE_CONSTANTS_H

#include <stddef.h>
#ifndef SPINE_BUILD_CONFIG_H_INCLUDED
#define SPINE_BUILD_CONFIG_H_INCLUDED
#include "config/config.h"
#endif

/* Defines */
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define LOCAL 0
#define REMOTE 1

#define SPINE_NONE 0
#define SPINE_IPV4 1
#define SPINE_IPV6 2

#ifndef __GNUC__
#define __attribute__(x) /* NOTHING */
#endif

/* Windows does not support stderr.  Therefore, don't use it. */
#ifdef __CYGWIN__
#define DISABLE_STDERR
#endif

#ifdef HAS_EXECINFO_H
#include <execinfo.h>
#endif

/* if a host is legal, return TRUE */
#define HOSTID_DEFINED(x) ((x) >= 0)

/* warning-suppression macros
 *
 * There are times when we cannot avoid using a parameter or variable which
 * is not used, and these correctly generate compiler warnings. But when we
 * *know* that the variable is actually intended to be unused, we can use one
 * of these macros inside the function to suppress it. This has the effect
 * of suppressing the warning (a good thing), plus documenting to the reader
 * that this is intentional.
 *
 * Both do the same thing - they're just for different semantics.
 */

#define UNUSED_VARIABLE(p) (void) (p)
#define UNUSED_PARAMETER(p) (void) (p)

/* logging macros
 *
 * These all perform conditional logging based on the current runtime logging
 * level, and it relies on a bit of tricky (but entirely portable) preprocessor
 * techniques.
 *
 * Standard C does not support variadic macros (macros with a variable number
 * of parameters), and though GNU C does, it's not at all portable. So we instead
 * rely on the fact that putting parens around something turn multiple params
 * into one:
 *
 *	SPINE_LOG_DEBUG(("n=%d string=%s foo=%f", n, string, foo));
 *
 * This macros has *one* parameter:
 *
 *		("n=%d string=%s foo=%f", n, string, foo)
 *
 * and the parentheses are part of it. When we call this macro, we pass the
 * "single" parameter unadorned, so that
 *
 *		spine_log args
 *
 * expands to
 *
 *		spine_log ("n=%d string=%s foo=%f", n, string, foo)
 *
 * Voila: it's a normal printf-like call.
 *
 * The second part of this is the conditional test, and the obvious approach
 * of using an "if" statement is exceptionally bad form: there are all kinds
 * of pitfalls which arise in this case. Instead, we should try to use an
 * *expression*, which has none of these problems.
 *
 * The conditional tests are modelled after the assert() mechanism, which
 * checks the first parameter, and if it's true, it evaluates the second
 * parameter. If the test is not true, then the second part is *guaranteed*
 * not to be evaluated.
 *
 * The (void) prefix is to forestall compiler warnings about expressions
 * not being used.
 */
#define SPINE_LOG(format_and_args) (spine_log format_and_args)
#define SPINE_LOG_LOW(format_and_args) (void) (set.logging.log_level >= POLLER_VERBOSITY_LOW && spine_log format_and_args)
#define SPINE_LOG_MEDIUM(format_and_args) (void) (set.logging.log_level >= POLLER_VERBOSITY_MEDIUM && spine_log format_and_args)
#define SPINE_LOG_HIGH(format_and_args) (void) (set.logging.log_level >= POLLER_VERBOSITY_HIGH && spine_log format_and_args)
#define SPINE_LOG_DEBUG(format_and_args) (void) (set.logging.log_level >= POLLER_VERBOSITY_DEBUG && spine_log format_and_args)
#define SPINE_LOG_DEVDBG(format_and_args) (void) (set.logging.log_level >= POLLER_VERBOSITY_DEVDBG && spine_log format_and_args)
#define SPINE_LOG_DEVICE(host_id, verbosity, format_and_args) \
	(void) (spine_should_log_device(host_id, verbosity) && spine_log format_and_args)

/* general constants */
#define MAX_THREADS 100
#define MAX_DEBUG_DEVICES 100
#define TINY_BUFSIZE 16
#define SMALL_BUFSIZE 256
#define MEDIUM_BUFSIZE 512
#define BUFSIZE 1024
#define DBL_BUFSIZE 2048
#define LRG_BUFSIZE 8096
#define BIG_BUFSIZE 65535
#define MEGA_BUFSIZE 1024000
#define HUGE_BUFSIZE 2048000
#define LOGSIZE 65535
#define LRG_LOGSIZE 1024000
#define BITSINBYTE 8
#define THIRTYTWO 4294967295ul
#define SIXTYFOUR 18446744073709551615ul
#define STAT_DESCRIP_ERROR 99
#define SPINE_PARENT 1
#define SPINE_FORK 0

/* locations to search for the config file */
#define CONFIG_PATHS 4
#define CONFIG_PATH_1 ""
#define CONFIG_PATH_2 "/etc/"
#define CONFIG_PATH_3 "/etc/cacti/"
#define CONFIG_PATH_4 "../etc/"

/* config file defaults */
#define DEFAULT_CONF_FILE "spine.conf"
#define DEFAULT_THREADS 5
#define DEFAULT_DB_HOST "localhost"
#define DEFAULT_DB_DB "cacti"
#define DEFAULT_DB_USER "cactiuser"
#define DEFAULT_DB_PASS "cactiuser"
#define DEFAULT_DB_PORT 3306
#define DEFAULT_DB_PREG 0
#define DEFAULT_LOGFILE "/var/www/html/cacti/log/cacti.log"
#define DEFAULT_TIMEOUT 294000000

/* threads constants */
#define LOCK_SNMP 0
#define LOCK_ICMP 2
#define LOCK_GHBN 3
#define LOCK_POOL 4
#define LOCK_PHP 6
#define LOCK_PHP_PROC_0 7
#define LOCK_PHP_PROC_1 8
#define LOCK_PHP_PROC_2 9
#define LOCK_PHP_PROC_3 10
#define LOCK_PHP_PROC_4 11
#define LOCK_PHP_PROC_5 12
#define LOCK_PHP_PROC_6 13
#define LOCK_PHP_PROC_7 14
#define LOCK_PHP_PROC_8 15
#define LOCK_PHP_PROC_9 16
#define LOCK_PHP_PROC_10 17
#define LOCK_PHP_PROC_11 18
#define LOCK_PHP_PROC_12 19
#define LOCK_PHP_PROC_13 20
#define LOCK_PHP_PROC_14 21
#define LOCK_THDET 40
#define LOCK_HOST_TIME 41

#define LOCK_SNMP_O 0
#define LOCK_ICMP_O 2
#define LOCK_GHBN_O 3
#define LOCK_POOL_O 4
#define LOCK_PHP_O 6
#define LOCK_PHP_PROC_0_O 7
#define LOCK_PHP_PROC_1_O 8
#define LOCK_PHP_PROC_2_O 9
#define LOCK_PHP_PROC_3_O 10
#define LOCK_PHP_PROC_4_O 11
#define LOCK_PHP_PROC_5_O 12
#define LOCK_PHP_PROC_6_O 13
#define LOCK_PHP_PROC_7_O 14
#define LOCK_PHP_PROC_8_O 15
#define LOCK_PHP_PROC_9_O 16
#define LOCK_PHP_PROC_10_O 17
#define LOCK_PHP_PROC_11_O 18
#define LOCK_PHP_PROC_12_O 19
#define LOCK_PHP_PROC_13_O 20
#define LOCK_PHP_PROC_14_O 21
#define LOCK_THDET_O 40
#define LOCK_HOST_TIME_O 41

/* poller actions */
#define POLLER_ACTION_SNMP 0
#define POLLER_ACTION_SCRIPT 1
#define POLLER_ACTION_PHP_SCRIPT_SERVER 2
#define POLLER_ACTION_SNMP_COUNT 10
#define POLLER_ACTION_SCRIPT_COUNT 11
#define POLLER_ACTION_PHP_SCRIPT_SERVER_COUNT 12

/* reindex constants */
#define POLLER_COMMAND_REINDEX 1

/* log destinations */
#define LOGDEST_FILE 1
#define LOGDEST_BOTH 2
#define LOGDEST_SYSLOG 3
#define LOGDEST_STDOUT 4

#define IS_LOGGING_TO_FILE() ((set.logging.log_destination) == LOGDEST_FILE || (set.logging.log_destination) == LOGDEST_BOTH)
#define IS_LOGGING_TO_SYSLOG() ((set.logging.log_destination) == LOGDEST_SYSLOG || (set.logging.log_destination) == LOGDEST_BOTH)
#define IS_LOGGING_TO_STDOUT() ((set.logging.log_destination) == LOGDEST_STDOUT)

#define SPINE_FREE(s) \
	do { \
		if (s) { \
			free((void *) s); \
			s = NULL; \
		} \
	} while (0)

/* logging levels */
#define POLLER_VERBOSITY_NONE 1
#define POLLER_VERBOSITY_LOW 2
#define POLLER_VERBOSITY_MEDIUM 3
#define POLLER_VERBOSITY_HIGH 4
#define POLLER_VERBOSITY_DEBUG 5
#define POLLER_VERBOSITY_DEVDBG 6

/* logging separator constants */
#define GDC_MIN 0
#define GDC_HYPHEN 0
#define GDC_SLASH 1
#define GDC_DOT 2
#define GDC_MAX 2
#define GDC_DEFAULT 1

/* logging format constants */
#define GD_FMT_SIZE 21
#define GD_MIN 0
#define GD_MO_D_Y 0
#define GD_MN_D_Y 1
#define GD_D_MO_Y 2
#define GD_D_MN_Y 3
#define GD_Y_MO_D 4
#define GD_Y_MN_D 5
#define GD_MAX 5
#define GD_DEFAULT 5

/* host availability statistics */
#define AVAIL_NONE 0
#define AVAIL_SNMP_AND_PING 1
#define AVAIL_SNMP 2
#define AVAIL_PING 3
#define AVAIL_SNMP_OR_PING 4
#define AVAIL_SNMP_GET_SYSDESC 5
#define AVAIL_SNMP_GET_NEXT 6
#define AVAIL_STREAM 7

#define PING_ICMP 1
#define PING_UDP 2
#define PING_TCP 3
#define PING_SNMP 4
#define PING_TCP_CLOSED 5

#define HOST_UNKNOWN 0
#define HOST_DOWN 1
#define HOST_RECOVERING 2
#define HOST_UP 3

/* required for ICMP and UDP ping */
#define ICMP_ECHO 8
#define ICMP_HDR_SIZE 8

/* required for PHP Script Server */
#define MAX_PHP_SERVERS 15
#define PHP_READY 0
#define PHP_BUSY 1
#define PHP_INIT 999
#define PHP_ERROR 99

/* required for validation of script results */
#define RESULT_INIT 0
#define RESULT_ARGX 1
#define RESULT_VALX 2
#define RESULT_SEPARATOR 3
#define RESULT_SPACE 4
#define RESULT_ALPHA 5
#define RESULT_DIGIT 6

/* snmp session status */
#define SNMP_1 0
#define SNMP_2c 1
#define SNMP_3 3
#define SNMP_NONE 4

/* Constants for remote polling */
#define REMOTE_ONLINE 0
#define REMOTE_OFFLINE 1
#define REMOTE_RECOVERY 2

/* These are used to perform string matches, returning TRUE/VALUE values.
 * For strcmp() this is not really that useful, but the case-insensitive
 * one has slight portability issues. Better to abstract them here.
 */
#define STRMATCH(a, b) (strcmp((a), (b)) == 0)
#define STRIMATCH(a, b) (strcasecmp((a), (b)) == 0)

/* When any kind of poller wants to set an undefined value; this particular
 * value used ('U') springs from the requirements of rrdupdate. We also
 * include the corresponding test macro which looks for the literal string
 * "U". This *could* use strcmp(), but this is more efficient.
 */
#define SET_UNDEFINED(buf) ((buf)[0] = 'U', (buf)[1] = '\0')
#define IS_UNDEFINED(buf) ((buf)[0] == 'U' && (buf)[1] == '\0')

#endif
