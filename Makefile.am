# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2026 The Cacti Group                                 |
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

AUTOMAKE_OPTIONS = foreign 1.15
ACLOCAL_AMFLAGS = -I m4

# --- Compilation Flags ---
AM_CPPFLAGS = -I$(srcdir)
AM_CFLAGS = $(SPINE_CFLAGS)

# --- Primary Binary ---
bin_PROGRAMS = spine

spine_SOURCES = \
	sql.c \
	spine.c \
	util.c \
	snmp.c \
	locks.c \
	poller.c \
	nft_popen.c \
	php.c \
	ping.c \
	keywords.c \
	error.c

spine_LDADD = $(SPINE_LIBS)

# --- Configuration & Data ---
configdir = $(sysconfdir)
dist_config_DATA = spine.conf.dist

# --- Documentation ---
if HAVE_HELP2MAN
man_MANS = spine.1
CLEANFILES = spine.1
spine.1: spine$(EXEEXT)
	$(HELP2MAN) --output=$@ --name='Data Collector for Cacti' --no-info --version-option='--version' ./spine$(EXEEXT)
endif

EXTRA_DIST = spine.conf.dist bootstrap copyright_year.sh

# --- Maintenance & Tooling ---
.PHONY: docker docker-dev verify cppcheck

docker:
	docker build -t spine .

docker-dev:
	docker build -f Dockerfile.dev -t spine-dev .

verify: docker-dev
	docker run --rm spine-dev

cppcheck: docker-dev
	docker run --rm spine-dev bash -c \
		"cppcheck --enable=all --std=c11 --error-exitcode=1 \
		--suppress=missingIncludeSystem --suppress=unusedFunction \
		--suppress=checkersReport --suppress=toomanyconfigs $(spine_SOURCES)"
