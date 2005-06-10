/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2002-2005 The Cacti Group                                 |
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
 |                                                                         | 
 | In addition, as a special exception, the copyright holders give         |
 | permission to link the code of portions of this program with the        |
 | OpenSSL library under certain conditions as described in each           |
 | individual source file, and distribute linked combinations              |
 | including the two.                                                      |
 |                                                                         |
 | You must obey the GNU General Public License in all respects            |
 | for all of the code used other than OpenSSL.  If you modify             |
 | file(s) with this exception, you may extend this exception to your      |
 | version of the file(s), but you are not obligated to do so.  If you     |
 | do not wish to do so, delete this exception statement from your         |
 | version.  If you delete this exception statement from all source        |
 | files in the program, then also delete it here.                         |
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

/* Cacti config reading utilities */
int read_config_options(config_t *set);
int read_cactid_config(char *file, config_t * set);
void config_defaults(config_t *);

/* Cacti premature shutdown utility */
void exit_cactid();

/* Cacti logging utilities */
void cacti_log(char *logmessage);

/* Number validation tools */
int is_numeric(char *string);

/* String and file utilities */
char *add_slashes(char *string, int arguments_2_strip);
int file_exists(char *filename);
char *strip_quotes(char *string);
char *strip_alpha(char *string);
