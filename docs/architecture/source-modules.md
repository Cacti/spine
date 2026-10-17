# Source module boundaries

Spine uses ordinary C translation units grouped by responsibility. Public
headers at the repository root retain the existing Cacti-facing interfaces;
`*_internal.h` headers describe only collaboration inside the implementation.
There are no implementation-file includes in production. Include-based legacy
unit tests retain their syscall interception by including the moved sources.

| Directory | Responsibility |
| --- | --- |
| `src/config/` | Settings cache, database-backed options, configuration file parsing |
| `src/core/` | CLI, startup, worker scheduling, locks, logging, numerical result parsing, regex, privileges |
| `src/database/` | Connections, pool ownership, remote poller transfers |
| `src/ping/` | Address parsing, UDP/TCP probes, IPv4/IPv6 ICMP, shared raw-socket reply dispatch |
| `src/poller/` | Query construction, host metadata, reindexing, item batches, system information, scripts |
| `src/php/` | Script-server process lifecycle and response reading |
| `src/process/` | Close-on-exec descriptors, pipes, spawn attributes, bounded child reaping |
| `src/snmp/` | Session setup and security-protocol selection |

The root translation units remain the entry points and subsystem coordinators.
Automake source groups are shared by production and linked tests. The fuzz
build lists the same implementation modules. Autotools remains the build system.

The split keeps the original function bodies and public signatures. Private
helpers that collaborate across translation units have declarations in internal
headers; helpers used by only one translation unit retain static linkage.
Shared ICMP state remains protected by LOCK_ICMP, including registration,
reply dispatch and ownership handoff. Worker accounting, SQL retry budgets,
script framing, result ownership and shutdown sequencing are unchanged.

At extraction, all 308 original root-source function bodies matched a lexical
comparison with the new module set. Compiler/linker checks and existing runtime
contracts provide the behavior validation; a text comparison alone is not a
runtime acceptance test. Production files range up to approximately 680 lines,
with most below 500. Tests and historical fixtures are separate from that count.
