<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Paired polling benchmarks

The `Paired build benchmark` workflow builds two exact Git revisions with the
same GCC, dependencies, configure options and `-O2 -g0` flags. Dispatch it with
baseline and candidate revisions. Both must already exist in the repository.
The workflow has read-only repository permissions and does not publish results
or change a live Cacti installation.

Both executables poll the same disposable MariaDB server and loopback Net-SNMP
agent on one runner. Defaults are four worker threads, 64 logical devices and
16 SNMPv2c items per device. Each item requests the agent's fixed `sysServices`
value of 72. Database TLS is disabled for both builds and checked on the server;
this workload does not measure TLS handshake or encrypted SNMPv3 performance.
There are two warmup pairs followed by 20 measured pairs, with alternating
baseline/candidate and candidate/baseline order.

Before each cycle, the harness recreates only the disposable `spine_benchmark`
schema, including host status and scheduling state. Reset and verification time
are excluded from measurements. A successful sample must exit successfully and
store every expected value with the expected distinct data-source IDs. Missing,
duplicate or unknown output fails the run. A failed run retains `incomplete`
metadata and cannot produce a completed summary.

`cycles.csv` records wall time, user CPU seconds, system CPU seconds, total CPU
seconds and CPU percentage for every cycle, including warmups. CPU percentage is
100 × CPU seconds / wall seconds and may exceed 100% for multithreaded work.
CPU measurements cover the Spine process and its children; database and agent
CPU are excluded. `summary.json` reports medians, observed ranges and median
paired candidate-minus-baseline deltas. Warmups are excluded from the summary.
Negative time deltas mean the candidate used less time in this experiment.

The uploaded artifact includes measurements, cycle logs, the exact fixture,
configuration hashes, binary hashes, resolved revision IDs, compiler and package
versions, and build logs. Results from GitHub's shared hosted runners can contain
CPU scheduling noise. Short cycles can be dominated by worker wait intervals;
the synthetic loopback workload does not establish production-network behavior.
Repeat on an idle, fixed server with representative device counts and latency
before making a general performance claim. A single median difference is not
proof of an improvement, and no percentage improvement should be inferred
without measurements.

## Recording results

Checked-in measurements are available for [default text logging](results/2026-10-11-default-logging/README.md)
and [the complete runtime changes](results/2026-10-11-runtime-ownership/README.md).
Each record preserves the raw cycles, exact build identities and interpretation.

After a completed workflow run, download its artifact and add a directory under
`docs/benchmarks/results/` containing `cycles.csv`, `summary.json`, `metadata.json`
and the build revision/toolchain records. Add a short Markdown interpretation
with the workflow run URL, workload, limitations and scope of the comparison.
Review and commit these files through the normal pull-request process. The job
does not automatically push commits. Keep generated executables and large logs
in the workflow artifact rather than Git.

For a dedicated Linux fixture with a loopback MariaDB server whose TLS is
disabled, the same harness can be run locally:

```sh
bash tests/tools/build_benchmark_pair.sh BASE_REF CANDIDATE_REF benchmark-builds
python3 tests/tools/benchmark_builds.py benchmark-builds/baseline/spine \
  benchmark-builds/candidate/spine --pairs 20
```

Use the repository's managed runtime through `mise` when selecting a Python
version locally. The harness intentionally accepts only the disposable loopback
database, and port 1161 must be available for its owned SNMP agent. It creates
disposable fixture users, never production credentials. Additional local
dimensions are available with `--threads`, `--devices`, `--items` and `--warmup`;
each setting applies identically to both builds.
