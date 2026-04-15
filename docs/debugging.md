# Debugging spine

Spine runs as a short-lived batch poller when invoked from cron or systemd
timers and as a long-lived daemon under `spine.service` on modern Cacti
deployments. The attach model differs in each case.

## Attach gdbserver to a running spine

On the production host:

    gdbserver --attach :1234 "$(pgrep spine)"

From a developer workstation with matching sources and debug symbols:

    gdb \
        -ex "target remote production-host:1234" \
        -ex "set sysroot /path/to/target-sysroot" \
        /path/to/spine

Spine must be built with `-g` (the default `CMAKE_BUILD_TYPE=Debug`) for the
session to carry line numbers. Release builds strip to `/usr/lib/debug` on
Debian and Fedora; `set debug-file-directory` in `~/.gdbinit` resolves that.

## systemd-confined gdbserver

The hardened unit blocks `ptrace(2)` via `SystemCallFilter=~@privileged`
and `CapabilityBoundingSet=`. Both must be relaxed before gdbserver can
attach. The safest path is an override, not an edit of the shipped unit:

    systemctl edit spine.service

Add:

    [Service]
    SystemCallFilter=
    CapabilityBoundingSet=CAP_SYS_PTRACE

Then:

    systemctl daemon-reload
    systemctl restart spine

Remove the override when the debugging session ends:

    systemctl revert spine.service

## Core dumps

Spine's default unit sets `LimitCORE=0`. To capture a core, override with:

    [Service]
    LimitCORE=infinity

Then wait for `systemd-coredump` to catch the next crash and inspect with
`coredumpctl gdb`.

## USDT tracing

Spine emits USDT probes when built on Linux with `sys/sdt.h` available
(`systemtap-sdt-devel` on Fedora, `systemtap-sdt-dev` on Debian). See
`src/spine_probes.h` for the probe set. Enumerate with:

    readelf -n /usr/bin/spine | grep -A3 'stapsdt'

Attach with `bpftrace`:

    bpftrace -e 'usdt:/usr/bin/spine:spine:poll_start { printf("host %d\n", arg0); }'
