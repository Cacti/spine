# Runtime hardening

Spine is built with the usual set of compile-time hardening flags enabled
by CMake's `spine_hardening` target (PIE, full RELRO, stack protector,
FORTIFY_SOURCE=2, `-D_GLIBCXX_ASSERTIONS`). The runtime additions below
are deployment-time choices that stack on top.

## GrapheneOS hardened_malloc

[hardened_malloc](https://github.com/GrapheneOS/hardened_malloc) is a
drop-in libc malloc replacement with out-of-line metadata, guard regions,
randomised slab layouts, and bounds-checked free lists. It is useful for
spine specifically because the poller dispatches short-lived allocations
from many threads, a workload that surfaces typical heap bugs quickly.

### Deployment

Build hardened_malloc on the target distribution (no binary tarballs are
published upstream; distros sometimes package it as `libhardened_malloc`).

Wire it into the systemd unit via a drop-in:

```
# /etc/systemd/system/spine.service.d/hardened-malloc.conf
[Service]
Environment=LD_PRELOAD=/usr/lib/libhardened_malloc.so
```

`systemctl daemon-reload && systemctl restart spine`.

### Caveats

* hardened_malloc raises RSS by 10-30%. Raise `LimitAS` in the systemd
  unit if it was tuned down for a constrained host.
* `SystemCallFilter=@system-service` in the spine unit already blocks
  most of the exotic syscalls hardened_malloc avoids calling, so the two
  hardening layers do not conflict.
* LD_PRELOAD is cleared when spine execs a PHP script server; the child
  runs with the stock allocator. That is fine: the attack surface that
  matters for the PHP children is in the script they execute, not in the
  malloc implementation.

## musl + mimalloc (alternative)

For distros built on musl libc (Alpine) mimalloc is the pragmatic choice
because musl's native allocator is already slab-based and hardened_malloc
expects glibc ABI details. The integration is identical (`LD_PRELOAD`);
see mimalloc's `docs/hardening.md` for the recommended environment
variable set.

## scudo (Bionic / LLVM)

Binaries built with `-fsanitize=scudo` get the Scudo allocator linked in
directly; no `LD_PRELOAD` is required. On Clang builds, adding
`-fsanitize=scudo` to `CFLAGS` at CMake configure time is sufficient. The
Scudo allocator is tuned for server workloads and is the default on
Android and on some Fuchsia configurations.

## AppArmor profile scope

`etc/apparmor.d/spine.apparmor.in` (rendered at install time to the
binary-attach-specific profile name) restricts spine's temp write
scope to `/tmp/spine.*`. A prior `/tmp/** rw` catch-all was removed
because it let spine read or replace any other service's temp files
(e.g. PostgreSQL's socket lockfile, sshd's auth temp spools). If a
Cacti script genuinely needs its own /tmp scratch path, grant the
narrower prefix it uses rather than widening the profile.

The profile also carries explicit `deny /root/** rwklx,` and
`deny /etc/shadow* rwklx,` rules. AppArmor deny-on-match wins over any
later permit, so a future edit that re-adds `/` or `/etc/**` cannot
silently expose those paths.

## Coordination with the sandbox

`spine_sandbox_restrict()` applies seccomp-bpf and Landlock after the
DB and SNMP sessions are open. hardened_malloc does its own `mprotect`,
`mmap`, and `madvise` calls for guard pages and slab rotation; all three
syscalls are on the spine seccomp allowlist. If the allowlist ever
narrows, keep those three entries regardless of whether hardened_malloc
is in use - they are hot in glibc's default allocator as well.
