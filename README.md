# spine

Multi-threaded SNMP and script poller for Cacti.

[![distro matrix](https://github.com/Cacti/spine/actions/workflows/distro-matrix.yml/badge.svg)](https://github.com/Cacti/spine/actions/workflows/distro-matrix.yml)
[![ci](https://github.com/Cacti/spine/actions/workflows/ci.yml/badge.svg)](https://github.com/Cacti/spine/actions/workflows/ci.yml)
[![license: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![C17](https://img.shields.io/badge/C-17-blue.svg)](CMakeLists.txt)

## At a glance

- Drop-in replacement for Cacti's `cmd.php` poller, written in C17.
- Pools SNMP v1/v2c/v3 and script targets across a configurable thread pool; one MySQL/MariaDB connection per worker.
- Runs as a short cron-driven batch or as a long-lived systemd `Type=notify` daemon with watchdog, SIGHUP reload, and SIGTERM drain.
- Per-host circuit breaker with exponential backoff; `--dry-run`, `--check`, and `--dump-config` for operator-safe iteration.
- Structured JSON logging on non-TTY stderr; USDT tracepoints around per-host polls and SNMP queries (Linux only).
- Used by enterprise, telecom, MSP, and hosting deployments running tens to hundreds of thousands of data sources.

## Quick start

```sh
git clone https://github.com/Cacti/spine.git
cd spine
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/spine --help
```

## Supported platforms

| Tier | Platforms |
|---|---|
| Tier 1 (primary, blocking CI) | RHEL / Rocky / Alma 9, Ubuntu 22.04 + 24.04, Debian 12, Fedora, FreeBSD 14, macOS |
| Tier 2 (supported, blocking CI) | Rocky 8, Debian trixie, openSUSE Leap 15, Alpine 3.20 |
| Tier 3 (advisory CI) | NetBSD 10, OpenBSD 7.5, DragonFly BSD, Windows MSVC / MSYS2, UBI 9 |
| Tier 4 (experimental, compile guards only) | AIX, Solaris / illumos |

Full matrix, tier policy, install commands, and local reproduction with `scripts/test-distros.sh` are in [docs/platforms.md](docs/platforms.md).

## Install

Package dependencies, then build from source. Representative per-distro commands are below; the full list lives in [docs/platforms.md](docs/platforms.md).

### RHEL / Rocky / Alma / Fedora

```sh
dnf install -y epel-release
dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel
```

### Debian / Ubuntu

```sh
apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev
```

### FreeBSD

```sh
pkg install -y cmake ninja pkgconf mysql80-client net-snmp openssl
```

### macOS

```sh
brew install cmake ninja pkg-config mysql-client net-snmp openssl@3
```

### Build and install

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSPINE_BUILD_MAIN=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

Disable the systemd integration with `-DWITH_SYSTEMD=OFF` on systems without libsystemd (Alpine / musl, BSDs, macOS, Windows).

### Reproducible builds

`SOURCE_DATE_EPOCH` is honoured by the build. Set it to the commit timestamp to produce bit-identical artifacts:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) cmake --build build -j
```

## Configuration

`spine.conf` holds database credentials and poller tuning. A full annotated template ships as [etc/spine.conf.dist](etc/spine.conf.dist). Minimum viable config:

```ini
DB_Host       localhost
DB_Database   cacti
DB_User       cactiuser
DB_Pass       cactipass
DB_Port       3306
DB_UseSSL     1

Threads       20
```

Mode `0600` owned by the spine user is recommended. Spine warns on world-readable configs and refuses to start if the file is group- or world-writable.

Validate the config without polling:

```sh
spine --check               # parse and validate spine.conf
spine --dump-config         # print the effective, redacted config
spine --dry-run             # run a full poll cycle with no SQL writes
```

## Running under systemd

The build installs `spine.service` and `spine.timer` into the distro's unit directory. The unit is `Type=notify`, uses `sd_notify(3)` for readiness and watchdog pings, and reloads `spine.conf` on `SIGHUP`.

```sh
systemctl enable --now spine.timer
systemctl status spine.service
journalctl -u spine.service -f
```

Unit source: [etc/systemd/spine.service](etc/systemd/spine.service). Hardening flags, watchdog tuning, and override examples are documented in [docs/systemd.md](docs/systemd.md).

## Debugging and observability

- `spine --log-format=json` emits one structured log line per event on stderr, suitable for `journalctl -o json` or a sidecar shipper.
- `spine --check` and `spine --dump-config` exit without polling; use for config regression checks.
- `spine --dry-run` runs a complete poll cycle and logs the SQL statements that would be executed.
- USDT tracepoints are compiled in on Linux when `<sys/sdt.h>` is present; elsewhere they expand to no-ops. List them with `bpftrace -l 'usdt:./build/spine:spine:*'`. Current probes: `poll_start(host_id)`, `poll_done(host_id, errors)`, `snmp_query(host_id)`.
- Attach gdbserver to a running spine, relax the hardened unit for ptrace, and capture cores per [docs/debugging.md](docs/debugging.md).

## Security

Spine trusts the Cacti database. Any principal with write access to `poller_item` can direct spine to execute arbitrary commands as the spine user. See [SECURITY.md](SECURITY.md) for the full trust model, recommended deployment (dedicated user, `CAP_NET_RAW`, `0600` config, TLS to the DB), and private vulnerability reporting instructions.

Runtime sandboxing, when available on the target OS:

- Linux: `NoNewPrivileges=yes` and `SystemCallFilter=@system-service` on the systemd unit; in-process `PR_SET_NO_NEW_PRIVS` under the opt-in `SPINE_SANDBOX` env gate. A full in-process seccomp-bpf allowlist is deferred.
- OpenBSD: `pledge(2)` + `unveil(2)` applied to the main process after DB, SNMP, and log init, under the opt-in `SPINE_SANDBOX` env gate.
- FreeBSD: stub in place; `capsicum(4)` integration is a tracked item.
- Windows: spawned child processes are confined in a Job Object.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All commits must carry a DCO `Signed-off-by` line (`git commit -s`). Run `bash scripts/test-distros.sh` before pushing platform-sensitive changes.

## Documentation

- [docs/platforms.md](docs/platforms.md) - tier policy, install commands, CI coverage
- [docs/systemd.md](docs/systemd.md) - unit installation, watchdog, hardening
- [docs/debugging.md](docs/debugging.md) - gdbserver, cores, strace, bpftrace
- [docs/platform-idioms.md](docs/platform-idioms.md) - portability rules for contributors
- [SECURITY.md](SECURITY.md) - trust model and disclosure

## License

GPL-2.0-or-later. See [LICENSE](LICENSE).

Copyright (c) 2004-2026 The Cacti Group, Inc.
