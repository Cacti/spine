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
# | Cacti: The Complete RRDtool-based Graphing Solution                     |
# +-------------------------------------------------------------------------+
# | This code is designed, written, and maintained by the Cacti Group. See  |
# | about.php and/or the AUTHORS file for specific developer information.   |
# +-------------------------------------------------------------------------+
# | http://www.cacti.net/                                                   |
# +-------------------------------------------------------------------------+

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

spine_SOURCES = sql.c spine.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c platform_common.c platform_posix.c platform_win.c platform_socket_posix.c platform_socket_win.c platform_error_posix.c platform_error_win.c platform_process_posix.c platform_process_win.c

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

bin_PROGRAMS = spine

man_MANS = spine.1

EXTRA_DIST = spine.1 uthash.h spine_sem.h platform.h platform_socket.h platform_error.h platform_process.h platform_common.c platform_posix.c platform_win.c platform_socket_posix.c platform_socket_win.c platform_error_posix.c platform_error_win.c platform_process_posix.c platform_process_win.c tests/unit/Makefile tests/unit/test_platform_helpers.h tests/unit/test_platform_env.c tests/unit/test_platform_time.c tests/unit/test_platform_process.c tests/unit/test_platform_socket.c tests/unit/test_platform_error.c

# Docker targets — require Dockerfile and Dockerfile.dev (from PR #401)
.PHONY: docker docker-dev verify cppcheck check-unit

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

check-unit:
	$(MAKE) -C tests/unit run
