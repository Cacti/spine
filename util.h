/*
 ex: set tabstop=4 shiftwidth=4 autoindent:*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2021 The Cacti Group                                 |
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
 |   - Brady Alleman/Doug Warner (threading ideas, implimentation details) |
 +-------------------------------------------------------------------------+
 | - Cacti - http://www.cacti.net/                                         |
 +-------------------------------------------------------------------------+
*/

/* cacti config reading functions */
extern void read_config_options(void);
extern int read_spine_config(char *file);
extern void config_defaults(void);

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
extern char *add_slashes(char *string);
extern int file_exists(const char *filename);
extern char *strip_alpha(char *string);
extern char *strncopy(char *dst, const char *src, size_t n);
extern char *trim(char *str);
extern char *rtrim(char *str);
extern char *ltrim(char *str);
extern char *reverse(char *str);
extern int strpos(char *haystack, char *needle) ;
extern int char_count(const char *str, int chr);

/* custom hex2dec that returns a string instead of a number */
unsigned long long hex2dec(char *str);

/* custom regex replace to return a value if matches */
#define MAX_MATCHES 5
#define REGEX_NUMBER "([-+]*)([0-9]*)([.][0-9]+)"
char *regex_replace(const char *exp, const char *value);

/* macro to copy string to string with an ending null */
#define STRNCOPY(dst, src)	strncopy((dst), (src), sizeof(dst))

/* macro to duplicate string and die if fails */
#define STRDUP_OR_DIE(dst, src, reason)	\
	if ((dst = strdup(src)) == NULL) {\
		die("FATAL: malloc() failed during strdup() for %s", reason);\
	}\


/* get highres time as double */
extern double get_time_as_double(void);

/* function to check to see if program has capability to use raw socket with
   out uid = 0 */
extern int hasCaps();

/* see if we can do things as root */
extern void checkAsRoot();

/* log format */
extern char *get_date_format();

/* start time for spine */
extern double start_time;
