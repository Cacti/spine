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
SPINE_ROOT   := ../..
BINDIR       := bin

SANITIZERS := -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -fno-lto

# net-snmp-config reports the distro's own build flags, which include -flto and
# hardening options that clash with the sanitizer build. Keep only the includes.
NETSNMP_CFLAGS := $(filter -I% -D%, $(shell net-snmp-config --base-cflags 2>/dev/null))
NETSNMP_LIBS   := $(filter -l% -L%, $(shell net-snmp-config --libs 2>/dev/null))

SPINE_SRC := $(addprefix $(SPINE_ROOT)/, \
	ping.c util.c sql.c snmp.c locks.c poller.c nft_popen.c php.c keywords.c error.c)

FUZZ_CFLAGS := $(SANITIZERS) -g -O1 -DHAVE_CONFIG_H \
	-I$(SPINE_ROOT) -I$(SPINE_ROOT)/config \
	$(NETSNMP_CFLAGS) \
	$(shell mysql_config --include 2>/dev/null)

FUZZ_LDLIBS := $(NETSNMP_LIBS) $(filter -l% -L%, $(shell mysql_config --libs 2>/dev/null))

TARGETS := $(BINDIR)/fuzz_namebyhost $(BINDIR)/fuzz_icmp_reply

.PHONY: all run clean

all: $(TARGETS)

$(BINDIR):
	mkdir -p $(BINDIR)

$(BINDIR)/fuzz_%: fuzz_%.c stubs.c $(SPINE_SRC) | $(BINDIR)
	$(FUZZ_CC) $(FUZZ_CFLAGS) $^ -o $@ $(FUZZ_LDLIBS)

run: $(TARGETS)
	@rc=0; for t in $(TARGETS); do \
		name=$$(basename $$t); \
		echo "== $$name ($(FUZZ_SECONDS)s)"; \
		mkdir -p corpus/$$name; \
		$$t corpus/$$name -max_total_time=$(FUZZ_SECONDS) -print_final_stats=1 || rc=1; \
	done; exit $$rc

clean:
	rm -rf $(BINDIR)
