# Spine test harness

`make check` runs the cmocka unit tests. The Docker-backed integration fixture
uses a real Net-SNMP agent and MariaDB or MySQL to exercise the complete poll
and persistence path.

Run the standard end-to-end test with:

```sh
SPINE_TEST_DATABASE=mariadb tests/snmpv3/scripts/run-integration.sh
```

Run the concurrency contract with:

```sh
SPINE_TEST_HOSTS=24 \
SPINE_TEST_THREAD_COUNTS="1 4 12" \
SPINE_TEST_REPEATS=1 \
tests/integration/test_concurrency.sh
```

Exercise timeout and recovery behavior with real UDP packet loss:

```sh
tests/integration/test_network_faults.sh
```

The concurrency test creates an isolated Compose project, clones independent
SNMPv3 host records, sweeps worker counts, and verifies exact output and host
accounting after every run. It is intentionally transport-neutral so it can
also test a future libuv engine and reactor-count matrix without changing its
assertions. Fixture services communicate only on their project-local Compose
network, so independent test projects can run without competing for host ports.
The fault test uses `tc netem` inside the test-only SNMP agent container to
drop every response, verifies bounded completion without stale output, removes
the fault, and verifies the next poll recovers.

Useful controls:

- `SPINE_TEST_TIMEOUT_SECONDS`: per-Spine-run timeout (default `120`).
- `SPINE_TEST_ARTIFACT_DIR`: destination for logs and TAP results.
- `SPINE_TEST_KEEP_ENV_ON_FAILURE=1`: preserve containers after a failure.
- `SPINE_TEST_PROJECT`: explicit Compose project name for reproducibility.
- `SPINE_TEST_EXTRA_ARGS`: additional whitespace-separated Spine arguments.
  This provides the hook for future `--snmp-engine` and reactor-count sweeps;
  arguments are split but never evaluated as shell code.

Keep CI workloads bounded. Larger host counts and repeat counts belong in a
scheduled soak workflow rather than the pull-request critical path.
