# Unit test Makefile for spine/tests/unit
#
# The test binaries are self-contained: each one carries a copy of the routine
# under test so it links without MySQL, Net-SNMP or the spine globals.  Keep
# those copies byte-identical to the shipped source, or the tests stop being
# regression guards.
#
# Usage:
#   make          -- build and run
#   make build    -- build only
#   make clean    -- remove build artefacts

CC      ?= cc
PKG_CONFIG ?= pkg-config
BINDIR  := bin

SPINE_ROOT := ../..

# cmocka via pkg-config, with a plain -lcmocka fallback for platforms that
# ship the library without a .pc file.
# test_util_strings.c pulls in common.h, which needs the MySQL and Net-SNMP
# headers.  Discover them the same way configure does rather than hardcoding
# a prefix.
MYSQL_CFLAGS   := $(shell mysql_config --include 2>/dev/null)
NETSNMP_CFLAGS := $(shell net-snmp-config --base-cflags 2>/dev/null)

CMOCKA_CFLAGS := $(shell $(PKG_CONFIG) --cflags cmocka 2>/dev/null)
CMOCKA_LIBS   := $(shell $(PKG_CONFIG) --libs cmocka 2>/dev/null)
ifeq ($(strip $(CMOCKA_LIBS)),)
CMOCKA_LIBS := -lcmocka
endif

CFLAGS ?= -O0 -g
CFLAGS += \
	-std=c99 \
	-D_DEFAULT_SOURCE \
	-I$(SPINE_ROOT) \
	-I$(SPINE_ROOT)/config \
	$(CMOCKA_CFLAGS) \
	$(MYSQL_CFLAGS) \
	$(NETSNMP_CFLAGS) \
	-Wall \
	-Wextra \
	-Wno-unused-parameter

LDLIBS := $(CMOCKA_LIBS)

BUILD_FIXES   := $(BINDIR)/test_build_fixes
SAFETY_FIXES  := $(BINDIR)/test_safety_fixes
STRINGS       := $(BINDIR)/test_util_strings
TARGETS       := $(BUILD_FIXES) $(SAFETY_FIXES) $(STRINGS)

.PHONY: all build run clean

all: run

build: $(TARGETS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/%: %.c | $(BINDIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

run: $(TARGETS)
	@rc=0; for t in $(TARGETS); do \
		echo "== $$t"; \
		$$t || rc=1; \
	done; exit $$rc

clean:
	rm -rf $(BINDIR)
