# libFuzzer targets for spine.
#
# The sources are compiled directly rather than reusing the objects from the
# top-level build, so the instrumentation is consistent across every
# translation unit.  Without that libFuzzer has no coverage signal and the
# run is worthless.
#
#   make            -- build the targets
#   make run        -- build, then fuzz each target for $(FUZZ_SECONDS)
#   make clean

# CC is often exported by the parent build; use a dedicated variable so the
# fuzzer is always built with a clang that supports -fsanitize=fuzzer.
FUZZ_CC      ?= clang
FUZZ_SECONDS ?= 60
FUZZ_TIMEOUT ?= 5
FUZZ_RSS_MB  ?= 2048
SPINE_ROOT   := ../..
BINDIR       := bin

SANITIZERS := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-lto

# net-snmp-config reports the distro's own build flags, which include -flto and
# hardening options that clash with the sanitizer build. Keep only the includes.
NETSNMP_CFLAGS := $(filter -I% -D%, $(shell net-snmp-config --base-cflags 2>/dev/null))
NETSNMP_LIBS   := $(filter -l% -L%, $(shell net-snmp-config --libs 2>/dev/null))
DB_CONFIG      ?= $(shell command -v mariadb_config 2>/dev/null || command -v mysql_config 2>/dev/null)

SPINE_SRC := $(addprefix $(SPINE_ROOT)/, \
	src/poller/availability.c \
	src/ping/icmp_shared.c \
	src/ping/icmp4.c \
	src/ping/icmp6.c \
	src/ping/udp.c src/ping/tcp.c \
	src/ping/address.c src/app/buffer.c src/platform/clock.c src/platform/socket.c src/platform/thread.c src/platform/descriptor.c src/config/text.c src/config/validate.c src/log/debug.c src/log/sanitize.c src/script/escape.c \
	src/config/settings.c \
	src/config/options.c \
	src/config/file.c \
	src/database/transfer.c \
	src/log/log.c \
	src/poller/result.c \
	src/platform/privileges.c \
	src/poller/regex.c src/database/sql.c \
	src/database/connection.c \
	src/database/pool.c src/snmp/requests.c src/snmp/response.c \
	src/snmp/session.c src/platform/locks.c src/poller/poller.c \
	src/script/external.c src/database/cacti_query.c src/database/persistence.c src/poller/host.c src/poller/reindex.c src/poller/items.c src/poller/system.c src/process/nft_popen.c src/process/fd.c src/script/protocol.c src/script/read.c src/script/server.c \
	src/config/keywords.c src/app/signals.c)

FUZZ_CFLAGS := $(SANITIZERS) -g -O1 -DHAVE_CONFIG_H \
	-I$(SPINE_ROOT) -I$(SPINE_ROOT)/src -I$(SPINE_ROOT)/vendor/uthash \
	-I$(SPINE_ROOT)/config \
	$(NETSNMP_CFLAGS) \
	$(shell $(DB_CONFIG) --include 2>/dev/null)

FUZZ_LDLIBS := $(NETSNMP_LIBS) $(filter -l% -L%, $(shell $(DB_CONFIG) --libs 2>/dev/null))

TARGETS := $(BINDIR)/fuzz_namebyhost $(BINDIR)/fuzz_output_parser $(BINDIR)/fuzz_icmp_reply

.PHONY: all run clean

all: $(TARGETS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/fuzz_%: fuzz_%.c ../support/spine_runtime.c $(SPINE_SRC) | $(BINDIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDLIBS)

run: $(TARGETS)
	@rc=0; for t in $(TARGETS); do \
		name=$$(basename $$t); \
		echo "== $$name ($(FUZZ_SECONDS)s)"; \
		mkdir -p corpus/$$name; \
		$$t corpus/$$name -max_total_time=$(FUZZ_SECONDS) \
			-timeout=$(FUZZ_TIMEOUT) -rss_limit_mb=$(FUZZ_RSS_MB) \
			-print_final_stats=1 || rc=1; \
	done; exit $$rc

clean:
	rm -rf $(BINDIR)
