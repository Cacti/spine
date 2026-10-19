<!--
SPDX-FileCopyrightText: 2026 The Cacti Group
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Spine agent instructions

## Project and architecture

Spine is Cacti's multithreaded C poller, not a PHP web application.
`src/app/main.c` is the entry point; `src/app/runtime.c` owns runtime initialization
and shutdown. Subsystem coordinators and implementation
modules live under `src/`; headers stay beside their implementations.
`include/spine/` is reserved for supported external interfaces, not internal
sharing. Legacy compatibility headers live under `src/internal/` while focused
interfaces replace them incrementally. See docs/architecture/source-modules.md. `etc/spine.conf.dist`
is a sample configuration, not permission to contact a live Cacti installation.

`configure.ac`, `Makefile.am`, `bootstrap` and tracked distribution inputs define
an Autotools build. Dependencies include a C compiler, Autoconf/Automake,
Libtool, Net-SNMP, MySQL/MariaDB client development libraries and OpenSSL.
Read `README.md` for platform-specific prerequisites. Select managed tool/runtime
versions through `mise`; report native libraries that must be installed separately.

Spine is written to C17 with GNU extensions; `configure` adds `-std=gnu17`.
Declare variables at the top of each block in new code, use no VLAs, keep
pthreads rather than `<threads.h>`, and use no C23 features. The reasons and
the compiler floor are in `docs/adr/0001-c17-language-standard.md`.

## Offline build validation

In an isolated source/build checkout with the native prerequisites installed:

```sh
mise exec -- ./bootstrap
mise exec -- ./configure
mise exec -- make
```

`bootstrap` regenerates files and can normalize source line endings; review the
diff and retain legitimate tracked release inputs such as `Makefile.in`.
Run make check for production-linked regression contracts and unit tests.
CI also exercises multiple compilers, platforms, sanitizers and local SNMPv3
fixtures. Report build validation separately from live polling acceptance.
Cacti/spine uses GitHub CodeQL default setup. Keep it enabled; do not add conflicting advanced CodeQL uploads.

## Poller safety and review

Preserve Cacti's poller/database protocol, data-source identifiers and numerical
semantics. Audit memory ownership, buffer bounds, thread synchronization,
connection cleanup, subprocess handling and timeout/error paths. Never print
SNMP community strings or database passwords. Avoid changing privileges or
concurrency defaults as a workaround for a test failure.

Do not run `make install`, enable setuid, change Cacti poller settings or execute
polling against live devices/databases during ordinary validation. Runtime tests
need an explicitly selected disposable Cacti database and test endpoints.
The tracked `scripts/debug.sh` file is a helper script, not disposable debug output.
Preserve GPL notices and distinguish Cacti's `develop` work from `1.2.x`.

## Working rules

Select required language runtimes through `mise`. Read the checked-out manifests,
lockfiles and GitHub Actions before choosing versions or commands; do not infer
support from an old README example. Keep changes focused and preserve public
interfaces, licenses and existing correctness/security checks.

Keep credentials, customer data, `.omc/`, `.worktrees/` and generated output out
of commits. Never disable checks or suppress findings just to obtain a passing
result. Report the commands run, results and untested environments. Publishing,
deploying, modifying live systems and merging require task authorization.
