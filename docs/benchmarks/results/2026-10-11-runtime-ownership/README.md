<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Runtime ownership comparison, 2026-10-11

This is a completed local run of the implemented paired-build harness, not a
GitHub Actions run. The baseline is
`24e105fc1a4002c334b5cffd78d571fbb10388ce`; the candidate is
`dc423d4f9bc6f4bb6199a4136318fb8e73b136ae`. The candidate includes the
destination-specific upsert fix, explicit database TLS policy, checked database
leases, bounded joinable workers, common polling cleanup, optional script limits,
opt-in JSON logging and accompanying tests. JSON logging and script limits were
disabled. Subsequent coverage-script and documentation changes are excluded.

This historical candidate is preserved on
`refactor/c17-series-15-issue-resolution`. The active recovered implementation
in PRs #655 and #656 overlaps with it but differs in resource-policy interfaces
and other details. This record does not measure those PR heads; their separate
comparison is recorded in `../2026-10-11-recovered-runtime/`.

Both exact source archives were built with GCC 13.3.0, `-O2 -g0`, empty
`LDFLAGS` and `--with-mysql-client=mariadb`, using unchanged dependency versions.
The baseline binary was reused from the first comparison; its hash was verified
unchanged. Compiler, package, source-archive and binary hashes are recorded here.

Both builds ran in the same ARM64 Ubuntu 24.04 container under OrbStack, reporting
14 CPUs and an unlimited cgroup CPU quota (`max 100000`). The database was the
same unchanged MariaDB 10.11.14 server. The workload used one owned Net-SNMP
agent, four threads, 64 logical loopback devices and 16 SNMPv2c items per device.
Database TLS was disabled on both builds and the server. All 1,024 stored numeric
results were verified after every cycle. Mutable database state was reset before
each cycle, outside the measurement. Two warmup pairs preceded 20 measured pairs
in alternating AB/BA order. Warmups remain in the CSV but are excluded from the
summary. No other local validation build ran during measurement.

| Measurement | Baseline median (observed range) | Candidate median (observed range) | Median paired candidate minus baseline |
| --- | --- | --- | --- |
| Polling cycle wall time, seconds | 0.746001 (0.738826–0.763041) | 0.752204 (0.740908–0.855073) | +0.006495 |
| Process CPU time, seconds | 0.022048 (0.019588–0.045952) | 0.022403 (0.019180–0.049824) | −0.000320 |
| Process CPU usage, percent | 2.940351 (2.625428–6.182113) | 2.996671 (2.498811–5.826869) | +0.003860 percentage points |

The candidate had a higher observed median wall time in this run. CPU
measurements were similar, and the observed ranges overlap. These measurements
do not demonstrate a speedup or establish a general performance regression.
The difference between independent medians need not equal the median paired
difference. This was a shared development machine, not a dedicated performance
host. CPU measurements cover Spine and its children, excluding the database and
agent. The short loopback workload includes startup, connection and worker wait
time; it does not represent production network latency, SNMPv3, encrypted
database traffic or limited external scripts. Those workloads need separate
controlled comparisons. No percentage improvement is claimed.

`cycles.csv` preserves all 44 original cycle samples. `summary.json` retains
full precision, and `metadata.json` records configuration/fixture hashes,
binary identities, server version and the complete measurement status.
Independently check this record from the repository root:

```sh
python3 tests/tools/verify_benchmark_record.py \
  docs/benchmarks/results/2026-10-11-runtime-ownership
```
