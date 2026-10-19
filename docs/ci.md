# Native build and continuous integration

The CI builds Spine as GNU C17 with both MariaDB Connector/C and the legacy
MySQL client, and runs the production-linked and cmocka suites.
`tests/tools/test_configure_contracts.sh` verifies caller language overrides,
unsupported C17 compilers, hardening controls, preset fortify, invalid client
selection and simulated narrow-time detection. The simulated failure tests
validate configuration policy; they are not 32-bit ABI acceptance tests.

`tests/tools/run_coverage.sh` uses explicit measured object manifests for the
production-linked contracts and native unit programs. Source, generated-build,
binary and profile hashes accompany each run. Missing profiles or cmocka fail
validation. Declaration-only test globals have no executable profiles. The
branchless entry point is normalized from measured gcov output.

## Security scanning

`.github/workflows/security-scanning.yml` runs three jobs. Every action is
pinned to a commit, and every downloaded tool to a digest or checksum.

- `OpenSSF Scorecard` runs on pushes to `develop` and on the weekly
  schedule. It publishes results to the OpenSSF API and uploads SARIF to
  code scanning. The API rejects results unless the workflow has no
  top-level `env` or `defaults`, no workflow-level write permission, and
  `id-token: write` only on the Scorecard job, and unless that job uses only
  its allowed actions. Keep those rules when editing the file.
- `Secret scan (full history)` checks out every branch and tag and runs
  TruffleHog over all commits. The release tarball is checked against a
  pinned SHA-256. Only secrets that TruffleHog verifies as live fail the
  job.
- `Semgrep` runs the `p/c` and `p/secrets` rule sets in the official
  `semgrep/semgrep` image, pinned by digest, and uploads SARIF to code
  scanning. Any finding fails the job. The rule sets are fetched from the
  Semgrep registry at run time, so new rules can appear without a change
  here.

To update TruffleHog, take the new SHA-256 from the release's
`checksums.txt` after verifying that file's cosign signature. To update
Semgrep, pin the new image index digest
(`docker buildx imagetools inspect semgrep/semgrep:<version>`).

## Dependency maintenance

`.github/dependabot.yml` follows the repository's default branch, `develop`.
Version updates run weekly at staggered UTC times; minor/patch updates are
grouped by ecosystem and major upgrades remain separate. Security updates are
enabled in repository settings and are not delayed by the version cooldown.

| Ecosystem | Maintained inputs |
| --- | --- |
| GitHub Actions | Workflow and action references, including pinned commit IDs |
| Docker | Root, development/coverage and SNMP fixture base-image tags/digests |
| pip | `.github/requirements-*.in` and their complete hash-pinned `.txt` locks |
| pre-commit | Remote hook revisions in `.pre-commit-config.yaml` |

There is no npm application or manifest. Distro-managed C libraries, vendored
uthash bytes, local hook `additional_dependencies`, and tool/image versions
embedded in shell or environment variables still require explicit review.
Dependabot does not replace that work. Labels referenced by the configuration
exist in the repository. Updates use the same required tests and merge policy
as other changes; there is no privileged auto-merge workflow.

## Workflow conventions

Build jobs share the build/install composite actions. The installer validates
package names, passes an argument array, and omits recommended packages; it
does not cache mutable OS package state. Coverage and flawfinder use a selected
Python 3.12 runtime, hash-verified tool locks and download caches keyed by those
locks. This avoids mixing distro and pip coverage-tool versions or modifying
the system Python environment.
The standalone Rocky lane uses the same unprivileged distro runner and cmocka
suite as the matrix, with a pinned official Rocky image and failure artifacts;
it no longer installs an entire development-tool group or builds as root.

All checkouts disable persisted credentials, jobs have explicit timeouts, and
tokens default to read-only permissions. SARIF/OIDC permissions stay scoped to
the jobs that require them. Cacti/spine uses GitHub CodeQL default setup,
managed in repository security settings. It scans eligible branches and pull
requests. Avoid adding advanced CodeQL uploads while default setup is enabled.
Production regressions retain source and profile provenance.
Other long-running test workflows cancel superseded
runs; their stable required gate continues to reject failed, cancelled or
unexpectedly skipped jobs. Build/action changes trigger the affected fuzz,
integration and distro checks. No existing test, compiler lane, sanitizer,
coverage threshold or diagnostic gate is removed by this cleanup.
