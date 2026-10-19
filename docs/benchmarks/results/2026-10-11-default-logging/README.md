<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Default text logging comparison, 2026-10-11

This is a local run of the implemented paired-build harness, not a GitHub Actions
run. The baseline is `24e105fc1a4002c334b5cffd78d571fbb10388ce`; the candidate is
`a223c27a3323fd29fea72d05e29398cff8d5934d`. The candidate adds the nightly suite
manifest gate and opt-in JSON logging with cancellation-safe log writes. JSON
logging remained disabled for this comparison. Subsequent uncommitted database,
TLS and ownership changes were excluded from both source archives.

Both builds used GCC 13.3.0, `-O2 -g0`, empty `LDFLAGS` and
`--with-mysql-client=mariadb`, with the same installed packages. They ran in one
ARM64 Ubuntu 24.04 container under OrbStack, reporting 14 CPUs and an unlimited
cgroup CPU quota (`max 100000`). This was a shared development machine, not a
dedicated performance host. No other validation build ran during measurement.
Compiler, package, source-archive and binary hashes are recorded alongside the
raw samples.

The workload used one unchanged MariaDB 10.11.14 server, one unchanged Net-SNMP
agent, four Spine threads, 64 logical loopback devices and 16 SNMPv2c items per
device. Database TLS was disabled for both builds and the server. Every cycle
verified all 1,024 stored numeric results. There were two warmup pairs and 20
measured pairs in alternating AB/BA order; warmups are retained in the CSV and
excluded from the summary.

| Measurement | Baseline median (observed range) | Candidate median (observed range) | Median paired candidate minus baseline |
| --- | --- | --- | --- |
| Polling cycle wall time, seconds | 0.748508 (0.738710–0.802304) | 0.748362 (0.734315–0.795132) | −0.000265 |
| Process CPU time, seconds | 0.022530 (0.018157–0.040387) | 0.022347 (0.018816–0.050931) | +0.000629 |
| Process CPU usage, percent | 2.987910 (2.319196–5.401776) | 2.995814 (2.508910–6.405355) | +0.105005 percentage points |

The observed ranges overlap, and the paired differences are small relative to
cycle-to-cycle variation. This experiment does not establish a performance
improvement or regression. The difference between independent medians need not
equal the median of paired differences. CPU usage covers Spine and its children,
excluding the database and agent. The short loopback workload includes polling
startup, connection and worker wait time; it does not represent production
network latency, SNMPv3 or TLS workloads. No percentage speedup is claimed.

`cycles.csv` contains every original sample, and `summary.json` retains full
numeric precision. `metadata.json` records fixture/configuration hashes and
server identity. To independently check this record from the repository root:

```sh
python3 tests/tools/verify_benchmark_record.py \
  docs/benchmarks/results/2026-10-11-default-logging
```
