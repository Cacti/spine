# Spine regression tests

`make check` runs the production script-process implementation against real
children. It covers deferred reaping, concurrent commands, cancellation, PID
ownership, interrupted/failed waits, tracking saturation, and bounded shutdown.
Only system-call failures are injected; the process-management code is linked
directly from `nft_popen.c`.

`make integration-check` runs real Spine executables against a disposable schema
on an **isolated MariaDB or MySQL test server**. The runner creates a random
database and user and removes them on completion. It temporarily enables the
server's general query log to verify the number of native eligibility counts.
Do not point it at a shared or production server.

Provide a mode-0600 MySQL client file through `SPINE_TEST_DB_CONFIG`. Its
`[client]` section must specify `host`, `port`, `user`, and, when required,
`password`. The test account needs permission to create/drop its disposable
database and user and to manage/read the general query log. Credentials stay
in that file and temporary mode-0600 Spine configs; they are not command-line
arguments.

The integration target requires Python 3, a `mariadb` or `mysql` CLI client,
and a GNU-compatible linker for the allocation-failure executable. Without a
linker that accepts `--wrap`, configure leaves that executable out and the
allocation-failure cases are reported as skipped. Production
Spine contains no allocation-failure hook. The tests cover one and ten device
threads, uneven/empty partitions, multiple devices, device zero, poller filters,
active profiles, multiple rows per source, mixed eligibility, completion order,
ties between SNMP ports across partitions, the default polling interval,
failed output writes, both worker allocations failing, one failed worker, and
successful retry. Every successful cycle checks output identities and values,
duplicate writes, schedule ordering, and the query budget.

Set `SPINE_TEST_CACTI_ROOT` to a complete upstream Cacti maintenance source
tree to also exercise the real Script Server bootstrap at pool sizes 1, 10,
and 15 and mixed shell/PHP polling. The runner copies that tree into its own
temporary directory, loads its complete schema, and writes fixture credentials
only into the copy. Without this option those two compatibility tests are
reported as skipped. The ordinary polling regressions still execute.

Set `SPINE_TEST_SNMPD` to a net-snmp `snmpd` executable to also poll a real
agent over SNMPv1, SNMPv2c, and SNMPv3 authNoPriv and authPriv, covering the
batched item gets and reindex assertion gets. The runner starts its own agent
on a free loopback port with a temporary configuration and fixed fixture
credentials, and stops it afterwards. Without this option that test is
reported as skipped.

Set `SPINE_TEST_REQUIRE` to a comma separated list of `cacti` (the Script
Server cases) and `fault` (the allocation-failure cases) to make those cases
fail instead of being skipped when their prerequisite is missing. CI sets it
so that a missing package or tree cannot pass unnoticed.

`schema.sql` contains the actual table definitions from Cacti maintenance
revision `8d5f404ea5beed56d50c4533bae01e5d5f0db026`, with its upstream notice.
The small fixtures test behavior; capacity measurements use the separate
250,000-source load matrix. Synthetic results do not establish customer-script
or fleet-wide capacity.
