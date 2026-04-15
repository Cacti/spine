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

## Testing CI locally

The workflow policy gate (`.github/scripts/check-workflow-policy.py`) and
most lint-style checks run happily without Docker:

    scripts/test-workflows.sh policy

For the distro build matrix, use the Docker runner that CI uses:

    scripts/test-distros.sh rockylinux:9

This is faster than `act` because it invokes Docker directly and skips
the GitHub Actions wrapping layer.

For workflows that aren't covered by `scripts/test-distros.sh`, install
[act](https://github.com/nektos/act) and run:

    brew install act          # macOS
    scripts/test-workflows.sh list
    scripts/test-workflows.sh <job>

Limitations of `act`:
- Matrix jobs with services containers (MariaDB, Redis) often break
  because `act` uses a simplified container network.
- `cross-platform-actions/action` lanes (FreeBSD, NetBSD, OpenBSD) do
  not run under `act`; they need a real GitHub runner.
- Windows (`windows-latest`) cannot be emulated; those lanes stay
  CI-only.

## Report issues

Open issues against [Cacti/spine](https://github.com/Cacti/spine/issues) and tag with a `platform:` label from [docs/platforms.md](docs/platforms.md#reporting-platform-issues):

- `platform:linux-<distro>`, `platform:macos`, `platform:bsd`, `platform:windows`, `platform:aix`, `platform:solaris`

Include `spine --version`, OS and MySQL/MariaDB version, and the tail of `cmake --build build -j 2>&1` for build failures. For pre-authentication or RCE findings, use GitHub Security Advisories per [SECURITY.md](SECURITY.md). Do not open public issues for those.
