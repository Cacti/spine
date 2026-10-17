<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Recovered runtime comparison, 2026-10-11

This completed local measurement compares the active recovered implementation:
baseline PR #655 revision `a8bd78d712df17196b880130520f42a49105f99d` and candidate
PR #656 revision `3db06ab315041187680b896c3658db0fbe8c60e3`. The candidate adds
joined worker ownership, checked database leases, explicit TLS policy and opt-in
JSON logging to the baseline's script limits and destination-aware upserts.
It also contains the paired-build harness. The measurement was already retained
in the recovery evidence directory; this change independently verifies and
checks in its raw samples and provenance. It is not a GitHub Actions benchmark
run and does not measure the separate historical issue-resolution branch.

Both builds used the same GCC 12.2.0, installed packages, `-O2 -g0`, empty
`LDFLAGS` and `--with-mysql-client=mariadb`. Exact revision IDs, compiler/package
versions and binary hashes are recorded alongside the measurements. The run
used Linux ARM64 under OrbStack, reporting 14 CPUs, the same MariaDB 10.11.19
server and one Net-SNMP 5.9.3 agent. It kept four threads, 64 logical loopback
devices and 16 SNMPv2c items per device constant. TLS was disabled on both builds
and the disposable loopback server. JSON logging and optional script limits
were not enabled for this SNMP workload.

There were two warmup pairs and 20 measured pairs in alternating AB/BA order.
The harness reset mutable database state outside the timed cycle and verified
all 1,024 expected outputs after each cycle. The record verifier confirms all
44 samples, order, CPU accounting and recomputed summaries. Fixture, Spine
configuration and agent configuration hashes were independently checked against
the retained inputs before importing the record. Binary hashes agree between
the build records and measurement metadata.

| Measurement | Baseline median (observed range) | Candidate median (observed range) | Median paired candidate minus baseline |
| --- | --- | --- | --- |
| Polling cycle wall time, seconds | 0.752536 (0.740270–0.801703) | 0.749570 (0.715407–0.785846) | −0.002300 |
| Process CPU time, seconds | 0.023159 (0.020686–0.053646) | 0.023171 (0.020782–0.049239) | −0.000096 |
| Process CPU usage, percent | 3.081625 (2.649243–6.769641) | 3.090810 (2.786630–6.265735) | −0.000698 percentage points |

The candidate's observed median wall time was lower, while process CPU time was
similar. Ranges overlap, and this noisy loopback experiment does not establish a
general performance improvement. No percentage speedup is claimed. The
difference between independent medians need not equal the median paired
difference. CPU includes Spine and its children and excludes the server and
agent. This was a shared development machine; a dedicated idle-host guarantee
and cgroup CPU quota were not recorded with this retained evidence. Production
latency, SNMPv3, encrypted database traffic and limited scripts need separate
controlled comparisons. Results from this environment must not be pooled with
the other records, which used different compiler and dependency versions.

`cycles.csv` preserves all original samples, `summary.json` retains full numeric
precision and `metadata.json` records complete status and fixture identities.
From the repository root, verify the measurement:

```sh
python3 tests/tools/verify_benchmark_record.py \
  docs/benchmarks/results/2026-10-11-recovered-runtime
```
