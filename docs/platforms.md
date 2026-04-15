# Supported Platforms

Spine is a long-running network poller that runs on many Unix-like systems
plus Windows. Supported platforms are classified into four tiers based on
deployment footprint, CI coverage, and active maintenance.

## Tier definitions

| Tier | Meaning |
|---|---|
| **Tier 1** | Primary targets. Blocking CI. Regressions block merge. Actively tested and deployed in production. |
| **Tier 2** | Supported. Blocking CI. Regressions should be fixed before release but may not block urgent merges. |
| **Tier 3** | Advisory. Non-blocking CI (`continue-on-error: true`). Community-maintained. Failures are noted but do not block merges. |
| **Tier 4** | Experimental. No CI. Compile guards only. Community patches welcome; no runtime guarantees. |

CI status for every Tier 1, 2, and 3 lane is visible in the
[`distro-matrix`](../.github/workflows/distro-matrix.yml) workflow on every
PR and on a weekly schedule.

You can reproduce any Linux row locally with `scripts/test-distros.sh`,
which runs the same build inside the upstream container image:

```sh
scripts/test-distros.sh              # full matrix
scripts/test-distros.sh rockylinux:9 # single distro
```

Build output and logs land in `build-reports/<distro>.log`.

---

## Tier 1 — Primary

Mainstream targets with the largest Cacti deployment footprint, ordered
by market share. CI failures here block merge.

| Platform | Install command |
|---|---|
| **RHEL 9 / Rocky Linux 9 / AlmaLinux 9 / Oracle Linux 9** | `dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| **Ubuntu 24.04 LTS** | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| **Ubuntu 22.04 LTS** | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| **Debian 12 (bookworm)** | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| **Fedora (latest)** | `dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| **FreeBSD 14** | `pkg install -y cmake ninja pkgconf mysql80-client net-snmp openssl` |
| **macOS (arm64 + x86_64)** | `brew install cmake ninja pkg-config mysql-client net-snmp openssl@3` |

### Notes

- **Red Hat Enterprise Linux 9** is the primary deployment target for
  Cacti in enterprise, telecom, banking, and government environments.
  Rocky Linux 9 and AlmaLinux 9 are bug-for-bug RHEL 9 source rebuilds;
  Oracle Linux 9 shares the same upstream. All four behave identically
  for spine's purposes. The CI matrix runs Rocky 9 and Alma 9 because
  RHEL itself requires a paid subscription; a Red Hat Developer
  Subscription (free for individual developers, <https://developers.redhat.com/>)
  gives access to a real RHEL VM for local reproduction. UBI 9 is
  exercised as an advisory Tier 3 lane (toolchain smoke test only —
  `mariadb-connector-c-devel` is gated on subscription repos).
- **Ubuntu 22.04 / 24.04**: widely deployed for cloud and developer
  workloads; current LTS releases.
- **Debian 12**: Cacti's Debian baseline.
- **Fedora (latest)**: tracks the RHEL upstream toolchain and is the
  earliest signal for breakage on future RHEL releases.
- **FreeBSD 14**: primary BSD target. Significant Cacti deployment in
  ISPs, network operators, and hosting providers where the BSD licence
  and ZFS storage matter. CI runs FreeBSD 14.1 via
  `cross-platform-actions/action`.
- **macOS**: developer machines. Tested on macOS 14 (Sonoma) and 15
  (Sequoia) with Apple Clang on both Apple Silicon and Intel.

### FreeBSD build

```sh
pkg install -y cmake ninja pkgconf mysql80-client net-snmp openssl
cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
cmake --build build
```

### macOS build

```sh
brew install cmake ninja pkg-config mysql-client net-snmp openssl@3
cmake -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$(brew --prefix mysql-client);$(brew --prefix net-snmp);$(brew --prefix openssl@3)"
cmake --build build -j
```

---

## Tier 2 — Supported

Older or non-mainstream Linux distributions. CI failures here
block merge but may be deferred for urgent fixes.

| Platform | Install command |
|---|---|
| **Rocky Linux 8** | `dnf install -y epel-release && dnf install -y cmake gcc make net-snmp-devel mariadb-connector-c-devel openssl-devel pkgconfig systemd-devel` |
| **Debian trixie** | `apt-get install -y cmake gcc make libsnmp-dev libmariadb-dev-compat libssl-dev pkg-config libsystemd-dev` |
| **openSUSE Leap 15** | `zypper install cmake gcc13 make net-snmp-devel libmariadb-devel libopenssl-devel pkg-config systemd-devel` |
| **Alpine 3.20** | `apk add bash cmake gcc make musl-dev net-snmp-dev mariadb-connector-c-dev openssl-dev pkgconfig linux-headers` |

### Notes

- **Rocky 8**: older glibc and CMake baseline; covers backport scenarios.
- **Debian trixie**: next Debian stable; early warning for upcoming
  toolchain shifts.
- **openSUSE Leap 15**: default `gcc` is 7.x and does not support C17. Set
  `CC=gcc-13` or run `update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-13 100`
  before configuring. The CI lane does this automatically.
- **Alpine 3.20**: musl-based; primarily for container images.
  `WITH_SYSTEMD=OFF` disables the Type=notify integration on musl systems
  without libsystemd.

---

## Tier 3 — Advisory

Platforms that build and run but lack a dedicated CI runner, full
runtime verification, or stable upstream package availability. CI failures
do not block merges (`continue-on-error: true`). Community patches welcome.

| Platform | Install command |
|---|---|
| **NetBSD 10** | `pkgin install cmake ninja-build pkg-config mariadb-connector-c net-snmp openssl` |
| **OpenBSD 7.5** | `pkg_add cmake ninja mariadb-client net-snmp` |
| **DragonFly BSD 6.x** | `pkg install -y cmake ninja pkgconf mariadb-connector-c net-snmp openssl` |
| **Windows native (MSVC)** | Visual Studio 2022 with CMake; requires MariaDB Connector/C and Net-SNMP from upstream installers |
| **Windows MSYS2/MinGW** | `pacman -S --needed mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja mingw-w64-x86_64-libmariadbclient mingw-w64-x86_64-openssl pkg-config` |
| **UBI 9 / RHEL 9** | `dnf install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-9.noarch.rpm && dnf install -y cmake gcc make net-snmp-devel openssl-devel pkgconfig systemd-devel` |

For local reproduction on a developer workstation, the repo's
[`Vagrantfile`](../Vagrantfile) defines `freebsd`, `openbsd`, `netbsd`,
`dragonfly`, and `alpine` VMs. See
[CONTRIBUTING.md#bsd-and-niche-os-testing](../CONTRIBUTING.md#bsd-and-niche-os-testing)
and `scripts/test-vagrant.sh`.

### NetBSD 10

Tier 3. The CI lane uses `cross-platform-actions/action` to build inside a
NetBSD 10 VM. NetBSD provides `pipe2(2)`, `arc4random(3)`, and POSIX
sockets in libc; spine builds out of the box. No `CAP_NET_RAW` equivalent
is required (the BSDs use `setuid` or per-socket `pf` rules for raw
sockets). Bug reports tagged `platform:bsd` welcome.

### OpenBSD 7.x

Tier 3. CI lane targets OpenBSD 7.5. OpenBSD ships its own libc fork with
strict POSIX semantics; the same BSD code paths used for FreeBSD apply.
`pledge(2)` and `unveil(2)` integration is fully implemented in
`src/platform/platform_sandbox_openbsd.c`, providing robust syscall and
filesystem confinement when running as a non-root user.

### DragonFly BSD 6.x

Tier 3. No CI lane. DragonFly inherits the FreeBSD code paths
(`pipe2`, `arc4random`, `getifaddrs`) and is exercised by the same
`__FreeBSD__ || __OpenBSD__ || __NetBSD__ || __DragonFly__` macro guards
in `src/ping.c` and `src/platform/platform_process_posix.c`. Build with
the FreeBSD instructions; substitute `pkg` for DragonFly's package set.

### Windows native (MSVC)

Tier 3. A Windows port exists in `src/platform/platform_*_win.c`. The
build is exercised through the MSYS2/MinGW lane below. Native MSVC builds
are possible via the `ci-smoke` preset but full polling has not been
verified end-to-end against a Windows Cacti install.

### Windows MSYS2/MinGW

Tier 3. CI lane runs `cmake --preset ci-smoke` which exercises the
platform abstraction without the Net-SNMP stack (Net-SNMP is not currently
packaged for MINGW64). Treat Windows results as a portability signal, not
a release target.

```sh
pacman -S --needed \
  mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja \
  mingw-w64-x86_64-libmariadbclient mingw-w64-x86_64-openssl pkg-config
cmake --preset ci-smoke
cmake --build --preset ci-smoke
```

### UBI 9 / RHEL 9

Tier 3. RHEL 9 itself is not in CI because the image requires a paid
subscription. Three options exist for testing on RHEL 9:

1. **Rocky 9 / Alma 9** (Tier 1). Use these for day-to-day work.
2. **UBI 9** (Universal Base Image, free, no subscription). Advisory CI
   lane via `registry.access.redhat.com/ubi9/ubi`. Package set is
   restricted; `mariadb-connector-c-devel` may not be reachable without
   paid repos, so the lane is `continue-on-error: true`.
3. **Red Hat Developer Subscription**. Free for individual developers at
   <https://developers.redhat.com/>. Grants full RHEL 9 ISO and repo
   access. Use in a local VM when a RHEL-specific regression is reported.

Local Docker reproduction:

```sh
bash scripts/test-distros.sh registry.access.redhat.com/ubi9/ubi
```

---

## Tier 4 — Experimental

Compile-time scaffolding exists but no runtime verification has been
performed. No CI lane. These platforms have known-good build paths in
`CMakeLists.txt` and source-level guards in `src/`, but there is no
hardware in the lab and no community runner. See the GitHub tracker
issue for hardware donation, runner sponsorship, or test-result reports.

### AIX (IBM Power)

- **Status**: compiles cleanly with `xlclang` or `gcc` on AIX 7.2/7.3
  using the build flags set by `CMAKE_SYSTEM_NAME STREQUAL "AIX"` in
  `CMakeLists.txt` (`_ALL_SOURCE=1`, `_XOPEN_SOURCE=700`,
  `-Wl,-brtl`).
- **Known gaps**: runtime untested; raw ICMP (`ping`) path uses
  `/dev/urandom` fallback for ID generation since AIX lacks
  `arc4random(3)`.
- **Hardware**: pSeries / Power9+ LPAR welcome. Contact the issue
  tracker.

### Solaris / illumos (OpenIndiana, OmniOS, SmartOS)

- **Status**: compiles cleanly with `gcc` on illumos derivatives using
  the build flags set by `CMAKE_SYSTEM_NAME STREQUAL "SunOS"`
  (`_POSIX_PTHREAD_SEMANTICS=1`, `_XOPEN_SOURCE=700`, `__EXTENSIONS__=1`,
  links `socket` and `nsl`).
- **Known gaps**: runtime untested. `arc4random` is available on Solaris
  11.4+ and recent illumos; older Solaris builds fall back to
  `/dev/urandom`.
- **Hardware**: SPARC or x86 illumos zone welcome.

Tracker: see "Platform support: AIX and Solaris feasibility (Tier 4)" in
the spine issue tracker.

---

## Reporting platform issues

Tag platform issues with one of the labels below so they can be triaged
to the right tier:

- `platform:linux-<distro>` (e.g. `platform:linux-rhel`, `platform:linux-debian`)
- `platform:macos`
- `platform:bsd` (covers FreeBSD, NetBSD, OpenBSD, DragonFly)
- `platform:windows`
- `platform:aix`
- `platform:solaris`

Include the OS version, compiler version, CMake version, and the output
of `cmake --build build -j 2>&1 | tail -50` for build failures, or
`./build/spine --help` plus the failing command for runtime failures.

## CI coverage summary

The `distro-matrix` workflow (`.github/workflows/distro-matrix.yml`) runs
on every push to `feat/`, `fix/`, and `ci/` branches, on PRs targeting
`develop`, and weekly at 06:17 UTC Monday. It builds spine on:

- **Tier 1 (8 lanes)**: Rocky 9, Alma 9, Ubuntu 24.04, Ubuntu 22.04,
  Debian 12, Fedora latest, FreeBSD 14.1, macOS latest.
- **Tier 2 (4 lanes)**: Rocky 8, Debian trixie, openSUSE Leap 15,
  Alpine 3.20.
- **Tier 3 (4 lanes, advisory)**: NetBSD 10, OpenBSD 7.5, Windows MSYS2,
  UBI 9.

Tier 4 (AIX, Solaris) has no CI lane.
