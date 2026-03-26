# Unit test Makefile for spine/tests/unit
#
# Compiles test_build_fixes.c as a fully self-contained binary.  No MySQL or
# SNMP daemon required; the test file inlines the two functions under test to
# avoid link dependencies on util.o.
#
# Usage:
#   make          -- build and run
#   make build    -- build only
#   make clean    -- remove build artefacts

CC      := cc
BINDIR  := build

CMOCKA_INC := /opt/homebrew/Cellar/cmocka/2.0.2/include
CMOCKA_LIB := /opt/homebrew/Cellar/cmocka/2.0.2/lib

SPINE_ROOT := ../..

OPENSSL_INC  := /opt/homebrew/opt/openssl@3/include
MYSQL_INC    := /opt/homebrew/opt/mysql-client/include/mysql
NETSNMP_INC  := /opt/homebrew/opt/net-snmp/include/net-snmp
NETSNMP_INC2 := /opt/homebrew/opt/net-snmp/include/net-snmp/..

CFLAGS := \
	-std=gnu23 \
	-DHAVE_CONFIG_H \
	-I$(CMOCKA_INC) \
	-I$(SPINE_ROOT) \
	-I$(SPINE_ROOT)/config \
	-I$(OPENSSL_INC) \
	-I$(MYSQL_INC) \
	-I$(NETSNMP_INC) \
	-I$(NETSNMP_INC2) \
	-Wall \
	-Wextra \
	-Wno-unused-parameter

LDFLAGS := \
	-L$(CMOCKA_LIB) \
	-lcmocka \
	-Wl,-rpath,$(CMOCKA_LIB)

TARGET := $(BINDIR)/test_build_fixes

.PHONY: all build run clean

all: run

build: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): test_build_fixes.c | $(BINDIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

run: $(TARGET)
	$(TARGET)

clean:
	rm -rf $(BINDIR)
