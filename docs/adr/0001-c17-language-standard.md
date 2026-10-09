<!--
SPDX-FileCopyrightText: 2026 The Cacti Group
SPDX-License-Identifier: GPL-2.0-or-later
-->

# 0001: C17 language standard

## Status

Accepted

## Date

2026-10-07

## Context

Spine's guidance said C99, but `configure.ac` never passed `-std`, so each
compiler built Spine in its own default mode. GCC 8 to 14 and current Clang
default to `gnu17`. GCC 15 and later default to `gnu23`, so a distribution
that moves to GCC 15 would start building Spine as C23 with no change in the
tree. Under GCC 16 that already adds `-Wdiscarded-qualifiers` warnings in
`src/app/runtime.c` that `gnu17` builds do not show.

C17 is the C11 language with defect fixes. It gives Spine `_Static_assert`
for checking struct sizes and buffer limits at compile time, `_Noreturn` for
fatal paths, and `<stdatomic.h>` for counters that today need a mutex.

Spine also depends on POSIX and BSD interfaces such as pthreads,
`getaddrinfo`, `strtok_r`, `clock_gettime` and the `u_char` type in
Net-SNMP's API. It defines no feature-test macros. Strict `-std=c17` makes
glibc hide those declarations, and on Ubuntu 24.04 the build stops in
`src/snmp/requests.c` at the first `u_char`. Strict mode would need feature-test macros
in every file first.

## Decision

Spine is written to C17 with GNU extensions. `configure` adds `-std=gnu17`
to `CFLAGS` and stops with an error if the compiler rejects it. A second
check confirms that `__STDC_VERSION__` is at least `201710L`. A `-std`
the caller sets in `CC` or `CFLAGS` is kept; if it names an older
standard, `configure` warns and continues.

The supported compiler floor is:

- GCC 8, the system compiler on Rocky Linux 8 and AlmaLinux 8, which are
  supported until 2029-05-31;
- Clang 6 and Apple Clang;
- MSVC 2019 16.8 (`/std:c17`), for the planned Windows port.

These rules stay as they are:

- Declare variables at the top of each block in new code. About 90 older
  declarations follow statements; leave them until that code changes for
  another reason.
- No variable-length arrays.
- Threads use pthreads until libuv's thread API replaces them in Phase 4.
  Do not use `<threads.h>`.
- No C23 features until the oldest supported distribution's compiler builds
  C23.

## Consequences

The language mode no longer depends on which compiler a packager has. CI
builds with GCC 13 and Clang 18 on Ubuntu 24.04, Apple Clang on macOS, and
GCC 16 on Fedora 44, whose default is `gnu23`. The weekly Rocky Linux
workflow covers GCC 11. No CI job covers the GCC 8 floor yet; it was checked
by hand on Rocky Linux 8.

New code may use `_Static_assert` and `_Noreturn`. Check `<stdatomic.h>`
against the floor before relying on it: C17 makes atomics optional
(`__STDC_NO_ATOMICS__`), and MSVC 2019 does not ship the header.

cppcheck 2.13, the Ubuntu 24.04 package CI installs, accepts `--std=c17` but
still analyses the code as C11. CI keeps `--std=c11` until it uses a newer
cppcheck.

A compiler older than the floor now fails at `configure` time rather than
partway through the build.
