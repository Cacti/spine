# Lightweight unit/platform smoke test Makefile.
#
# Usage:
#   make        - build and run the portable smoke test
#   make compile - build only
#   make clean  - remove build artefacts

CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

SPINE_ROOT := ../..
BINDIR := build
TARGET := $(BINDIR)/test_platform_smoke

.PHONY: all compile run clean

all: run

compile: $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

$(TARGET): test_platform_smoke.c $(SPINE_ROOT)/platform_common.c $(SPINE_ROOT)/platform_posix.c $(SPINE_ROOT)/platform_win.c $(SPINE_ROOT)/platform.h | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) test_platform_smoke.c $(SPINE_ROOT)/platform_common.c $(SPINE_ROOT)/platform_posix.c $(SPINE_ROOT)/platform_win.c -o $@

run: $(TARGET)
	$(TARGET)

clean:
	rm -rf $(BINDIR)
