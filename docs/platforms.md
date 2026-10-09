<!--
SPDX-FileCopyrightText: 2026 The Cacti Group
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Platforms

`.github/workflows/distro-matrix.yml` builds Spine with Autotools and runs
`make check` on each platform below, on every pull request and push to
`develop` that touches the build or the sources.

## Support policy

A release is supported until its vendor end-of-life date. New releases are
added after general availability, and a lane is removed when its release
reaches end of life. Dates come from [endoflife.date](https://endoflife.date).
`.github/workflows/distro-eol.yml` runs `.github/scripts/check-distro-eol.py`
weekly and fails if any lane has passed end of life or is not listed. It
only reports; it opens no issue or pull request.

## Tested platforms

| Platform | Releases | How |
| --- | --- | --- |
| Rocky Linux | 8, 9, 10 | `rockylinux/rockylinux` container |
| AlmaLinux | 8, 9, 10 | `almalinux` container |
| Ubuntu | 22.04, 24.04, 26.04 | container |
| Debian | 12, 13 | container |
| Fedora | 44 | container |
| openSUSE Leap | 16.0 | container |
| Alpine Linux | 3.24 | container |
| FreeBSD | 14.5, 15.1 | VM via `cross-platform-actions/action` |
| NetBSD | 10.1, 11.0 | VM, best effort (Tier 3) |
| OpenBSD | 7.9 | VM, best effort (Tier 3) |

macOS is built and tested by the `macos` job in `.github/workflows/ci.yml`.

The dependencies are a C compiler, Autoconf, Automake, Libtool, Net-SNMP,
MariaDB Connector/C, OpenSSL, and cmocka for the unit tests. MySQL's
`libmysqlclient` still builds with `--with-mysql-client=mysql` but is
deprecated and will be removed in the next release
([ADR 0003](adr/0003-mariadb-connector.md)). Spine works with MariaDB and
MySQL servers through either library.
`scripts/test-distros.sh` holds the package list for each platform.

## Platform tiers

Tier 1 is Linux: the RHEL family, Debian, Ubuntu and SUSE, and the other
distributions in the table. It is fully tested. Every distribution runs
`make check`, and Ubuntu also runs the sanitizer, coverage, regression and
integration jobs against live MariaDB, MySQL and SNMP agents. Releases
block on Tier 1.

Tier 2 is FreeBSD and macOS. Both are built and tested with `make check` on
every pull request, and their lanes must pass. They do not run the
sanitizer, coverage or live-server jobs.

Tier 3 is NetBSD, OpenBSD and Windows, built and tested on a best-effort
basis. The NetBSD and OpenBSD lanes run with `continue-on-error`, so a
failure there does not block a merge. Portability failures are fixed rather
than skipped; existing platform prerequisites still govern integration checks.
Windows has no lane until the planned port lands.

A platform moves up a tier when its lane has been green for a full release.

Branch protection on `develop` requires only the `CI / required` check in
`.github/workflows/ci.yml`, which includes the Ubuntu and macOS jobs. The
`distro-matrix.yml` lanes are not part of it, so keeping the Tier 1 and
FreeBSD lanes green is a review rule, not an enforced check.

## 32-bit platforms

32-bit platforms are unsupported. Every CI lane is 64-bit: x86-64 for Linux
and the BSDs, arm64 for macOS.

A 32-bit `time_t` overflows on 19 January 2038, so `configure` stops when
`time_t` is narrower than 64 bits. On a 32-bit target with glibc 2.34 or
later it first adds `-D_TIME_BITS=64 -D_FILE_OFFSET_BITS=64`, which gives a
64-bit `time_t`. No CI lane covers that build. Every library Spine links,
including Net-SNMP and the database client, must be built with the same
`time_t` width, or values passed between them are misread.
`--disable-y2038-check` lets `configure` continue with a 32-bit `time_t`;
the result is unsupported.

## BSD portability

Child cleanup bounds elapsed monotonic time as well as syscall attempts.
This prevents coarse NetBSD/OpenBSD sleep ticks from turning the intended
20 ms grace period into roughly a second. Kernel scheduling can still
delay a wakeup beyond the deadline.

PHP signal-mask fault injection uses a test-only function rather than a
linker wrapper that NetBSD's libc aliases can bypass. Spawn tests distinguish
a parent-side failure from a child-side exec failure: OpenBSD can return
success from `posix_spawn()` while the child exits unsuccessfully. In that
case, `php_init()` retains its existing busy-slot behavior; tests verify that
the slot never becomes ready and that closing it releases its resources.

The packaging helper uses portable tar arguments and removes obsolete
metadata from the staged copy, supporting native OpenBSD tar.

[Native validation of commit 0514e936](https://github.com/somethingwithproof/spine/actions/runs/37860340116)
passed on both FreeBSD releases, both NetBSD releases and OpenBSD 7.9.
Each NetBSD/OpenBSD lane reported 16 passed, two skipped and zero failed
suites. The existing skips cover allocation-fault injection and setuid
testing; the previously failing process, PHP and helper suites all passed.

## Running the Linux lanes locally

With Docker installed:

```sh
scripts/test-distros.sh                 # every Linux lane
scripts/test-distros.sh debian:13       # one image
```

The checkout is mounted read-only and copied inside the container, and the
tests run as an unprivileged user. On an arm64 host Docker runs the arm64
images, while CI runs x86-64.
