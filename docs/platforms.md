# Supported Platforms

Spine targets mainstream Linux distributions, macOS, and FreeBSD as
first-class build platforms. Windows builds are produced via MSYS2/MinGW and
remain advisory until the Windows code paths reach parity.

Each Linux row below is exercised automatically in the `distro-matrix`
workflow. You can reproduce any row locally with `scripts/test-distros.sh`,
which runs the same build inside the upstream container image:

```sh
scripts/test-distros.sh              # full matrix
scripts/test-distros.sh rockylinux:9 # single distro
```

Build output and logs land in `build-reports/<distro>.log`.

## Linux

| Distro | Package install command |
|---|---|
| Rocky Linux 9 / 8 | `dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| AlmaLinux 9 | `dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| Fedora (latest) | `dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| Debian 12 (bookworm) / trixie | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| Ubuntu 22.04 / 24.04 | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| openSUSE Leap 15 | `zypper install cmake gcc13 make net-snmp-devel libmariadb-devel libopenssl-devel pkg-config systemd-devel` (default `gcc` is 7.x and does not support C17; set `CC=gcc-13` or run `update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-13 100`) |
| Alpine 3.20 | `apk add bash cmake gcc make musl-dev net-snmp-dev mariadb-connector-c-dev openssl-dev pkgconfig linux-headers` |

### Red Hat Enterprise Linux 9

RHEL 9 is not in the CI matrix directly because the image requires a
subscription. The Rocky Linux 9 and AlmaLinux 9 lanes are bug-for-bug
compatible rebuilds of RHEL 9 sources and cover ~99% of RHEL 9 behaviour.

Options for testing on RHEL 9:

1. **Rocky 9 / Alma 9** — already covered; use these for day-to-day work.
2. **UBI 9** (Universal Base Image, free, no subscription) — advisory CI
   lane via `registry.access.redhat.com/ubi9/ubi`. Package set is
   restricted; `mariadb-connector-c-devel` may not be reachable without
   paid repos, so this lane is `continue-on-error: true`.
3. **Red Hat Developer Subscription** — free for individual developers at
   <https://developers.redhat.com/>, grants full RHEL 9 ISO and repo
   access. Use in a local VM when a RHEL-specific regression is reported.

Local reproduction via Docker (advisory):

```sh
bash scripts/test-distros.sh registry.access.redhat.com/ubi9/ubi
```

Build from a clean checkout:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/spine --help
```

`WITH_SYSTEMD=OFF` disables the Type=notify integration for distros without
libsystemd (Alpine, musl-based systems, containers). All other targets build
the notify hook automatically when `libsystemd.pc` is found.

## macOS

Requires Homebrew:

```sh
brew install cmake ninja pkg-config mysql-client net-snmp openssl@3
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$(brew --prefix mysql-client);$(brew --prefix net-snmp);$(brew --prefix openssl@3)"
cmake --build build -j
```

Tested on macOS 14 (Sonoma) and 15 (Sequoia) with Apple Clang.

## FreeBSD

```sh
pkg install -y cmake ninja pkgconf mysql80-client net-snmp openssl
cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
cmake --build build
```

Tested on FreeBSD 14.1.

## Windows (advisory)

Windows builds use MSYS2 MINGW64:

```sh
pacman -S --needed \
  mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-libmariadbclient mingw-w64-x86_64-openssl pkg-config
cmake --preset ci-smoke
cmake --build --preset ci-smoke
```

Net-SNMP is not currently packaged for MINGW64, so the full build presets
fall back to `ci-smoke` which exercises the platform abstraction without the
SNMP stack. Treat Windows results as a portability signal, not a release
target.

## CI coverage

The `distro-matrix` workflow (`.github/workflows/distro-matrix.yml`) runs on
every push to feat/fix branches, on PRs targeting `develop`, and weekly at
06:17 UTC Monday. It builds spine on:

- 10 Linux distros listed above
- macOS latest (Apple Silicon)
- Windows latest (MSYS2, advisory)
- FreeBSD 14.1 (via `cross-platform-actions/action`)
