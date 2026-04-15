# Contributing to spine

## Sign your commits

All contributions require a Developer Certificate of Origin sign-off. Use `-s` on every commit:

```sh
git commit -s -m "fix(poller): handle SNMP timeout on v3 auth failure"
```

If you forget, rebase with sign-off:

```sh
git rebase --signoff origin/develop
```

## Run the distro matrix locally

Platform-sensitive changes (CMake, `src/platform/`, sandboxing, logging, systemd) should be exercised against the full Linux matrix before pushing:

```sh
bash scripts/test-distros.sh              # full matrix
bash scripts/test-distros.sh rockylinux:9 # single target
```

Logs land in `build-reports/<distro>.log`. The same lanes run in CI as `distro-matrix.yml`.

For non-Linux targets, see [docs/platforms.md](docs/platforms.md) for FreeBSD, NetBSD, OpenBSD, macOS, and Windows reproduction instructions.

## Report issues

Open issues against [Cacti/spine](https://github.com/Cacti/spine/issues) and tag with a `platform:` label from [docs/platforms.md](docs/platforms.md#reporting-platform-issues):

- `platform:linux-<distro>`, `platform:macos`, `platform:bsd`, `platform:windows`, `platform:aix`, `platform:solaris`

Include `spine --version`, OS and MySQL/MariaDB version, and the tail of `cmake --build build -j 2>&1` for build failures. For pre-authentication or RCE findings, use GitHub Security Advisories per [SECURITY.md](SECURITY.md). Do not open public issues for those.
