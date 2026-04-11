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

bin_PROGRAMS = spine

spine_SOURCES = \
	sql.c spine.c util.c snmp.c locks.c poller.c \
	nft_popen.c php.c ping.c keywords.c error.c

noinst_HEADERS = \
	common.h spine.h sql.h util.h snmp.h poller.h \
	nft_popen.h locks.h error.h

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

man_MANS = spine.1

EXTRA_DIST = \
	spine.1 \
	uthash.h \
	spine.conf.dist \
	bootstrap \
	Dockerfile \
	Dockerfile.dev \
	tests/integration/smoke_test.sh \
	tests/integration/test_output_regex.sh \
	tests/integration/test_db_column_detect.sh \
	tests/unit/Makefile \
	tests/unit/test_build_fixes.c \
	tests/snmpv3/docker-compose.yml \
	tests/snmpv3/db/init.sql \
	tests/snmpv3/snmpd/Dockerfile \
	tests/snmpv3/snmpd/snmpd.conf \
	tests/snmpv3/snmpd/snmpv3.conf \
	tests/snmpv3/spine/spine.conf \
	tests/snmpv3/scripts/run_test.sh

CLEANFILES = *~

# Docker targets
.PHONY: docker docker-dev verify cppcheck check-unit

docker:
	docker build -t spine .

docker-dev:
	docker build -f Dockerfile.dev -t spine-dev .

verify: docker-dev
	docker run --rm spine-dev

cppcheck: docker-dev
	docker run --rm spine-dev bash -c \
		"cppcheck --enable=warning,style,performance \
		--std=c11 --error-exitcode=1 \
		--suppress=missingIncludeSystem --suppress=unusedFunction \
		--suppress=checkersReport --suppress=toomanyconfigs \
		$(spine_SOURCES)"

check-unit:
	cd tests/unit && $(MAKE)
