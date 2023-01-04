## Makefile.am -- Process this file with automake to produce Makefile.in
#
# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2023 The Cacti Group                                 |
# |                                                                         |
# | This program is free software; you can redistribute it and/or           |
# | modify it under the terms of the GNU General Public License             |
# | as published by the Free Software Foundation; either version 2          |
# | of the License, or (at your option) any later version.                  |
# |                                                                         |
# | This program is distributed in the hope that it will be useful,         |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
# | GNU General Public License for more details.                            |
# +-------------------------------------------------------------------------+
# | Cacti: The Complete RRDtool-based Graphing Solution                     |
# +-------------------------------------------------------------------------+
# | This code is designed, written, and maintained by the Cacti Group. See  |
# | about.php and/or the AUTHORS file for specific developer information.   |
# +-------------------------------------------------------------------------+
# | http://www.cacti.net/                                                   |
# +-------------------------------------------------------------------------+

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

spine_SOURCES = sql.c spine.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

bin_PROGRAMS = spine

man_MANS = spine.1

spine.1: $(bin_PROGRAMS)
	$(HELP2MAN) --output=$@ --name='Data Collector for Cacti' --no-info --version-option='--version' ./spine
