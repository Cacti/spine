/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 | cactid: a backend data gatherer for cacti                               |
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
void read_config_options(config_t *set);
int read_cactid_config(char *file, config_t * set);
void config_defaults(config_t *);

/* cacti logging function */
void cacti_log(const char *format, ...);
void die(const char *format, ...)
	__attribute__((noreturn))
	__attribute__((format(printf, 1, 2)));

/* option processing function */
void set_option(const char *setting, const char *value);

/* number validation functions */
int is_numeric(const char *string);
int all_digits(const char *str);

/* string and file functions */
char *add_slashes(char *string, int arguments_2_strip);
int file_exists(const char *filename);
char *strip_string_crlf(char *string);
char *strip_quotes(char *string);
char *strip_alpha(char *string);
char *strncopy(char *dst, const char *src, size_t n);

/* macro to copy string to string with an ending null */
#define STRNCOPY(dst, src)	strncopy((dst), (src), sizeof(dst))
