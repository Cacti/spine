## Makefile.am -- Process this file with automake to produce Makefile.in

spine_SOURCES = sql.c spine.c util.c snmp.c locks.c poller.c nft_popen.c php.c ping.c keywords.c error.c

configdir = $(sysconfdir)
config_DATA = spine.conf.dist

bin_PROGRAMS = spine

man_MANS = spine.1

spine.1: spine.c 
	$(HELP2MAN) --output=$@ --name='Data Collector for Cacti' --no-info --version-string='$(VERSION)' ./spine
