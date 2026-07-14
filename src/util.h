/*
 ex: set tabstop=4 shiftwidth=4 autoindent:*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 |                                                                         |
 | This program is free software; you can redistribute it and/or           |
 | modify it under the terms of the GNU Lesser General Public              |
 | License as published by the Free Software Foundation; either            |
 | version 2.1 of the License, or (at your option) any later version. 	   |
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

/* cacti config reading functions */
extern void read_config_options(void);
extern int read_spine_config(const char *file);
extern void config_defaults(void);

/* Zero secret fields in the global `set` struct (DB / RDB passwords and
 * user names). Called on every non-signal exit path so a core dump or
 * late-stage memory-scan attack cannot recover DB credentials. Signal
 * handlers must stay AS-safe and therefore do NOT invoke this. */
extern void spine_scrub_secrets(void);

/* Range-safe int parser for DB/config-setting values. Safer atoi:
 *
 * - NULL input returns 0 (atoi is UB).
 * - Non-numeric input returns 0 (matches atoi's 'use default' contract).
 * - Positive overflow clamps to INT_MAX; negative overflow clamps to
 *   INT_MIN (a bare cast would produce undefined behaviour).
 * - Trailing garbage is tolerated and ignored, matching atoi; callers
 *   that need strictness should use strtol directly.
 *
 * Exposed for reuse across TUs (config_repository, future config
 * parsers) so the safety contract is not duplicated. */
extern int spine_parse_int(const char *s);

/* Zero SNMP credential fields (community, v3 username/password,
 * auth/priv passphrases) in a target_t array before free. Each poll
 * cycle populates these buffers from DB rows; scrubbing them as the
 * cycle unwinds narrows the window in which a core dump or cross-
 * process memory scan can recover per-device credentials. */
struct target_struct;
extern void spine_scrub_target_secrets(struct target_struct *items, int count);

/* Zero SNMP credential fields on a single host row. */
struct host_struct;
extern void spine_scrub_host_secrets(struct host_struct *host);

/* Capture the effective uid at process startup before any privilege drop.
 * Used by the spine.conf owner check so a root-owned config stays valid
 * once spine drops to its service account. */
extern void spine_capture_startup_euid(void);

/* cacti logging function */
extern int spine_log(const char *format, ...)
	__attribute__((format(printf, 1, 2)));

extern void die(const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 1, 2)));

/* option processing function */
extern void set_option(const char *setting, const char *value);

/* number validation functions */
extern int is_numeric(char *string);
extern int is_ipaddress(const char *string);
extern int all_digits(const char *str);
extern int is_hexadecimal(const char * str, const short ignore_special);

/* determine if a device is a debug device */
extern int is_debug_device(int device_id);

/* string and file functions */
extern int file_exists(const char *filename);
extern char *strip_alpha(char *string);
extern char *strncopy(char *dst, const char *src, size_t n);
extern char *trim(char *str);
extern char *rtrim(char *str);
extern char *ltrim(char *str);
extern char *reverse(char *str);
extern int strpos(const char *haystack, const char *needle);
extern int char_count(const char *str, int chr);

/* custom hex2dec that returns a string instead of a number */
unsigned long long hex2dec(char *str);

/* custom regex replace to return a value if matches */
#define MAX_MATCHES 5
#define REGEX_NUMBER "([-+]*)([0-9]*)([.][0-9]+)"
const char *regex_replace(const char *exp, const char *value);

/* macro to copy string to string with an ending null */
#define STRNCOPY(dst, src)  strncopy((dst), (src), sizeof(dst))
#define USTRNCOPY(dst, src) ustrncopy((dst), (src), sizeof(dst))

/* macro to duplicate string and die if fails */
#define STRDUP_OR_DIE(dst, src, reason)	\
	if ((dst = strdup(src)) == NULL) {\
		die("FATAL: malloc() failed during strdup() for %s", reason);\
	}\


/* Keep this public header self-contained for focused unit tests that include
 * it without common.h (which normally provides the MySQL client typedef). */
typedef struct st_mysql MYSQL;

/* get highres time as double */
extern double get_time_as_double(void);

/* function to check to see if program has capability to use raw socket with
   out uid = 0 */
extern int hasCaps(void);

/* see if we can do things as root */
extern void checkAsRoot(void);

/* log format */
extern char *get_date_format(void);

/* remote/main server synchronization */
extern void poller_push_data_to_main(void);

/* start time for spine */
extern double start_time;

/* the version of Cacti as a decimal */
int get_cacti_version(MYSQL *psql, int mode);

/* Operational CLI helpers. */
extern int spine_health_check(void);
extern void spine_dump_config(void);

/* Redact credential-bearing flag values from a shell-style command string so
 * the result is safe to write to logs. Recognized short flags: -c, -u, -a,
 * -x, -p, -A, -X, -E, -Z (case-sensitive so -A / -X are distinct from
 * -a / -x). Recognized long flags: --community, --password, --secret,
 * --authPassphrase, --privPassphrase, plus =VAL variants. VAL becomes
 * three asterisks in the output. Unrecognized input is copied verbatim.
 * Always NUL-terminates out even on truncation. */
extern void spine_redact_args(const char *cmd, char *out, size_t outsz);
