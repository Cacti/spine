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
PLATFORM_SOURCES := $(SPINE_ROOT)/src/platform/platform_common.c \
	$(SPINE_ROOT)/src/platform/platform_posix.c \
	$(SPINE_ROOT)/src/platform/platform_win.c \
	$(SPINE_ROOT)/src/platform/platform_socket_posix.c \
	$(SPINE_ROOT)/src/platform/platform_socket_win.c \
	$(SPINE_ROOT)/src/platform/platform_error_posix.c \
	$(SPINE_ROOT)/src/platform/platform_error_win.c \
	$(SPINE_ROOT)/src/platform/platform_process_posix.c \
	$(SPINE_ROOT)/src/platform/platform_process_win.c \
	$(SPINE_ROOT)/src/platform/platform_fd_posix.c \
	$(SPINE_ROOT)/src/platform/platform_fd_win.c \
	$(SPINE_ROOT)/src/platform/platform_sandbox_posix.c \
	$(SPINE_ROOT)/src/platform/platform_sandbox_linux.c \
	$(SPINE_ROOT)/src/platform/platform_sandbox_openbsd.c \
	$(SPINE_ROOT)/src/platform/platform_sandbox_freebsd.c \
	$(SPINE_ROOT)/src/platform/platform_sandbox_win.c
TEST_SOURCES := test_platform_env.c test_platform_time.c test_platform_process.c test_platform_socket.c test_platform_error.c test_platform_fd.c test_platform_dns.c
TARGETS := $(patsubst %.c,$(BINDIR)/%,$(TEST_SOURCES))

.PHONY: all compile run clean

all: run

compile: $(TARGETS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/test_platform_env: test_platform_env.c $(SPINE_ROOT)/src/platform/platform.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_env.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_time: test_platform_time.c $(SPINE_ROOT)/src/platform/platform.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_time.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_process: test_platform_process.c $(SPINE_ROOT)/src/platform/platform.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_process.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_socket: test_platform_socket.c $(SPINE_ROOT)/src/platform/platform.h $(SPINE_ROOT)/src/platform/platform_socket.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_socket.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_error: test_platform_error.c $(SPINE_ROOT)/src/platform/platform_error.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_error.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_fd: test_platform_fd.c $(SPINE_ROOT)/src/platform/platform_fd.h $(SPINE_ROOT)/src/platform/platform_process.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_fd.c $(PLATFORM_SOURCES) -o $@

$(BINDIR)/test_platform_dns: test_platform_dns.c $(SPINE_ROOT)/src/platform/platform.h $(PLATFORM_SOURCES) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/src/platform -I$(SPINE_ROOT)/third_party test_platform_dns.c $(PLATFORM_SOURCES) -o $@

run: $(TARGETS)
	@for test_binary in $(TARGETS); do \
		$$test_binary; \
	done

clean:
	rm -rf $(BINDIR)
