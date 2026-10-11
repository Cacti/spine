<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Resource ownership review

This extends the worker-registry and database-lease audit to remaining global
lock consumers. Full coverage of those modules does not establish every legacy
lifetime or platform. The table records reviewed responsibilities and limits.

| Resource / lock | Owner and lifetime | Evidence / boundary |
| --- | --- | --- |
| Worker slots | `src/platform/worker_set.c` retains slots until successful join; completion is atomic and mutex-serialized. | Worker suite, TSan, Helgrind. |
| Database leases | `src/database/lease.c` binds slot, generation, destination and borrower; pool destruction rejects outstanding leases. | Lease suite and database fault contracts. |
| `LOCK_THDET` | `src/poller/workers.c`, `src/poller/poller.c`, `src/database/pool.c` protect details and completion accounting. Worker joins precede shared-state release; database writes occur outside this lock. | Mocked host contracts and concurrency soak. |
| `LOCK_SNMP` | `src/snmp/session.c`, `src/snmp/requests.c` serialize global session/packet-ID operations. Production host polling disables cancellation while owning sessions and leases. | SNMPv3 contracts; retain library serialization. |
| `LOCK_GHBN` | `src/ping/icmp4.c`, `src/ping/icmp6.c` copy resolver address data before unlocking. | ICMP contracts; resolver modernization is separate. |
| `LOCK_ICMP` | `src/ping/icmp_shared.c` protects socket/waiter publication; the designated reader unlocks during I/O, locks to dispatch, and hands reading ownership to a waiter. | Timing/ICMP suites. Direct cancellable callers would need cleanup beyond the production host's cancellation protection. |
| `LOCK_PHP` / per-server locks | `src/script/protocol.c` uses the global lock only for the cursor and per-server locks for command/recovery. Startup handshakes occur outside the cursor lock. | PHP runtime faults. Process-wide PHP shutdown still needs coordination with command/recovery owners. |
| External-script registry | `src/process/nft_popen.c` publishes under `ListMutex`, retains closing entries until cleanup, and parks unreaped children. Reaping clears the owned PID under that mutex before reuse; cancellation kills the group before releasing its entry. | Linked close-owner contracts and process-abort suite. |
| Permits | `src/platform/thread.c` owns mutex/condition state; script/worker cleanup returns acquired permits. | Thread fault and cancellation contracts. |
| Log stream | `src/log/log.c` serializes writes with cancellation disabled and restores cancellation after unlocking. | Log cancellation faults and JSON tests. |

## External-script fatal and termination policy

`die()` freezes external-script creation and kills every registered external
script group, including entries another worker is closing, before logging and
exiting. Existing owners retain their descriptors and allocations until cleanup.
Spawn, reap, cleanup and abort share the registry mutex, preventing an abort
from signalling a PID already reaped by this registry. The bounded close grace
period sleeps outside the mutex.
Once abort starts, result persistence rejects newly assembled batches and host
completion does not advance due-item scheduling. A killed script's EOF must
not publish an undefined result while the fatal thread prints its diagnostic.

SIGINT, SIGTERM and SIGQUIT notify a coordinator through a nonblocking,
close-on-exec pipe. The handler only writes a signal byte and returns, allowing
an interrupted worker to finish publication and release the registry mutex.
In ordinary thread context the coordinator aborts scripts, then restores and
raises the signal's default disposition to retain signalled termination status.
No registry lock, allocator or stdio call is added to the handler.

The production-linked process-abort suite creates four concurrent owners with
real shell children and descendants. It checks parent/worker fatal exits,
SIGINT/SIGTERM/SIGQUIT, no surviving fixtures, repeated abort, spawn rejection,
and coordinator installation/teardown. Linux fixtures adopt/reap descendants
instead of relying on container PID 1.

Synchronous hardware faults, SIGABRT/SIGSYS/SIGKILL, scripts that deliberately
escape their group, and PHP's separate process ownership are outside this
cooperative guarantee. Hardware-fault handlers retain emergency async-safe
exits. A crash-proof child supervisor needs a separate design. Do not claim
issue #476 or the broader lifetime audit #609 complete.
