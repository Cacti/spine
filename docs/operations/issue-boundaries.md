<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Remaining issue acceptance boundaries

This records requirements that cannot be established by changing Spine alone.
It does not mark the listed issues complete or claim untested platform support.

## Output regular expressions (#210)

Spine discovers an `output_regex` column on `poller_item` and applies configured
expressions before numeric validation in each SNMP batch flush. Regression
fixtures cover full batches, credential changes, final batches, units-bearing
strings and normalized hexadecimal strings. The tests add that column only to
the disposable fixture and remove it afterward.

The audited Cacti develop schema at
`cad6762d44cf71cd9980d03ff1c266ef90e6108e` does not define `output_regex`.
A deployable Cacti feature still needs a schema migration, configuration UI and
poller-cache population contract in the Cacti repository. Spine does not add
columns to a live Cacti database. Leave #210 open until that integration exists.

## SNMP Diffie-Hellman key changes (#295)

The request must distinguish provisioning/rekeying a device's USM user from
ordinary authenticated polling. Spine currently consumes configured USM keys;
changing a device key without atomically updating Cacti's stored credentials
would interrupt polling and can strand credentials after a partial failure.

Before implementing a protocol, obtain the target device/MIB specification,
required authentication/privacy combinations, administrator authorization,
credential persistence and rollback behavior, and a disposable device or
protocol fixture. Reuse Net-SNMP's supported implementation where applicable;
do not invent a key exchange. Cacti owns its credential schema and management
UI, including the related Cacti #5099 request. Spine-only unit tests cannot
establish provisioning interoperability. Leave #295 open pending that contract.

## AIX and Solaris (#536)

Linux/macOS builds cannot establish runtime support for AIX or Solaris. An
acceptance lane needs an owned runner or reproducible machine image, a C17 GNU
compiler/toolchain selection, Autotools, matching Net-SNMP and database client
headers/libraries, a documented TLS capability matrix, and disposable database
and SNMP endpoints. It must run build, production-linked tests, ownership tests,
polling, timeout/process cleanup and TLS trust/identity cases. Unsupported
explicit policies must remain failures, not become fallback behavior.

No AIX/Solaris platform execution was available for this change. Leave #536 open
until those environments are supplied and the acceptance runs are recorded.

## Nightly validation (#496)

The nightly workflow runs its declared unit suites and dynamic checks, with a
manifest gate rejecting omitted, duplicate or nonexecutable suites. Local
sanitizer runs do not substitute for a completed scheduled workflow after the
stack merges. Record that run and its artifacts before declaring #496 complete.

## Ownership audit (#609)

The bounded joinable worker registry and database lease module have mandatory
100% line and branch coverage gates. Parent shutdown joins workers before pool
destruction. Leases bind the slot, generation, destination and borrowing thread;
stale, duplicate or foreign releases fail. Script cancellation owns its output,
descriptor, child process group and acquired permit. Obsolete pool/host-time
global locks are removed, and connection-count updates are atomic.

These are concrete ownership fixes. They do not assert 100% coverage for every
legacy resource path: the remaining global-lock consumers and full lifetime
audit must be reviewed against #609's broader acceptance criteria. Keep that
broader audit open rather than treating helper coverage as whole-program proof.

## Poller-wide script aborts (#476)

The explicit script policy and per-call cancellation cleanup are implemented
and tested with real children. Parent/worker `die()` and SIGINT/SIGTERM/SIGQUIT
now stop external-script groups owned by other workers, with production-linked
child/descendant tests. Handlers notify an ordinary-context coordinator rather
than locking the registry. See [resource ownership](resource-ownership.md) for
the reviewed lock consumers and precise contract. Hardware-fault exits and
PHP's separate process-wide ownership remain outside that guarantee. Leave
#476 open for those remaining acceptance boundaries.
