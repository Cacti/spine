<!--
SPDX-FileCopyrightText: 2026 The Cacti Group
SPDX-License-Identifier: GPL-2.0-or-later
-->

# Contributing to Spine

Read [AGENTS.md](AGENTS.md) for the layout of the code and the rules for
working on the poller. Report security problems privately as described in
[SECURITY.md](SECURITY.md), not in an issue or pull request.

## Commits

Every commit needs a Developer Certificate of Origin sign-off that matches
its author. Use `git commit -s`. The `dco` job in CI rejects a pull request
that has an unsigned commit; `git rebase --signoff` fixes existing ones.

Write commit titles as [Conventional Commits](https://www.conventionalcommits.org/),
for example `fix(poller): ...`, `test(ping): ...`, `ci: ...` or `docs: ...`.
Keep one logical change per commit.

## Pre-commit hooks

`.pre-commit-config.yaml` runs the cheap CI checks before each commit:
whitespace and end-of-file fixes, YAML syntax, shellcheck, actionlint,
codespell with `.codespell-ignore-words.txt`, and clang-format on the lines
you changed. Install [pre-commit](https://pre-commit.com/) and enable the
hooks once per clone:

```sh
pre-commit install
pre-commit run --all-files
```

The clang-format hook checks staged lines against `HEAD` and prints the
change it wants; apply it with `git clang-format`. The actionlint hook
builds actionlint with Go, which pre-commit downloads if it is missing.
Hook versions are pinned to commit SHAs; `pre-commit autoupdate --freeze`
updates them.

## Building and testing

Spine uses Autotools. You need a C compiler, Autoconf, Automake, Libtool,
help2man, the Net-SNMP, MariaDB Connector/C and OpenSSL development
packages, and cmocka for the unit tests. On Debian or Ubuntu:

```sh
sudo apt-get install build-essential autoconf automake libtool help2man \
  libmariadb-dev libsnmp-dev libssl-dev libcmocka-dev
./bootstrap
./configure --enable-warnings
make -j"$(nproc)"
make check
```

`bootstrap` regenerates tracked files such as `Makefile.in`. Do not commit
that output; build in a separate copy if you want a clean tree.

`configure` uses MariaDB Connector/C (`mariadb_config`) when it finds it.
Building against MySQL's `libmysqlclient` still works, with
`--with-mysql-client=mysql` and `MYSQL_CONFIG` set to MySQL's
`mysql_config`, but it is deprecated and will be removed in the next
release; `configure` prints a warning when it is used. Connector/C connects
to both MariaDB and MySQL servers. See
[ADR 0003](docs/adr/0003-mariadb-connector.md).

### Regression tests in Docker

The `Production regressions` workflow also runs Spine against a MariaDB
server and a local SNMP agent. To run the same steps on your machine, start
a database and an Ubuntu 24.04 build container:

```sh
docker network create spine-test
docker run -d --name spine-db --network spine-test \
  -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 \
  -e MARIADB_DATABASE=spine_regressions mariadb:10.11
docker run --rm -it --network spine-test -v "$PWD:/src:ro" ubuntu:24.04 bash
```

Inside the container, build as an unprivileged user, as CI does:

```sh
apt-get update
apt-get install -y build-essential autoconf automake libtool help2man \
  libmariadb-dev mariadb-client libsnmp-dev snmpd libssl-dev libcmocka-dev
cp -a /src /build && chown -R ubuntu: /build
su ubuntu
cd /build
mkdir -p config m4 && autoreconf -fi && ./configure && make -j"$(nproc)" check
mariadb -h spine-db -u root spine_regressions < tests/fixtures/configuration.sql
mariadb -h spine-db -u root spine_regressions < tests/fixtures/poller.sql
snmpd -f -Lo -C -c tests/fixtures/snmpd.conf > snmpd.log 2>&1 &
export SPINE_TEST_DB_HOST=spine-db SPINE_TEST_SNMP_HOST=127.0.0.1
./test_spine_regressions --database
./test_spine_regressions --snmp-agent
./test_spine_faults --database
```

The SNMPv3, ICMP and setuid checks in that workflow need `sudo` and
`setcap`; see `.github/workflows/regressions.yml` for those steps. Remove
the database with `docker rm -f spine-db` and
`docker network rm spine-test`.

### Coverage

CI measures line coverage with gcovr and requires a minimum share of the
lines a pull request changes to be covered, using diff-cover. The
thresholds are in the `coverage` job of `.github/workflows/ci.yml`. To run
the same check on Linux before you push, with `gcovr` installed:

```sh
./configure CFLAGS="-g -O0 --coverage -fprofile-update=atomic" LDFLAGS=--coverage
make -j"$(nproc)" check
rm -f ./*conftest*.gcno ./*conftest*.gcda
gcovr -r . --exclude 'tests/.*' --xml coverage.xml --print-summary
python3 -m pip install --user --break-system-packages diff-cover==10.5.1
~/.local/bin/diff-cover coverage.xml --compare-branch=origin/develop --fail-under=70
```

New or changed behaviour needs a test. Unit tests use cmocka under
`tests/unit`; contract tests live in `tests/contracts/`; shell
regressions live in `tests/regression`. Add new tests to `Makefile.am` next
to the existing ones.

## C style

- C17. Declare variables at the top of a block. No variable-length arrays.
- Indent with tabs and match the file you are editing.
- Put opening braces on the same line as the statement or function
  declaration, as the existing code does.
- Use `/* */` comments, and use them to explain why, not what.
- Check every `malloc`, `calloc` and `realloc` result. Assign a `realloc`
  result to a temporary pointer first.
- Use `snprintf` and check its return value for truncation. Do not add
  `sprintf` or `strcpy`.
- Use the `db_*` wrappers in `src/database/sql.c` for database access.
- Never log SNMP communities, SNMPv3 passphrases, database passwords or
  script arguments.
- Keep changes focused. Do not reformat or rename code you are not changing.

`.clang-format` describes this style as closely as clang-format can. It is
not applied to the whole tree, because hand-aligned tables and assignment
blocks would churn. The `clang-format` job in the static analysis workflow
checks only the lines a pull request changes, with clang-format 18. To fix
those lines before you push:

```sh
git clang-format origin/develop
```

Use clang-format 18 for this. Other major versions format some constructs
differently.

## Pull requests

Open pull requests against `develop`. A pull request can merge only when:

- the `CI / required` check is green;
- every review conversation is resolved;
- the branch rebases onto `develop` without a merge commit, because
  `develop` requires linear history.

Describe what changed, why, and how you tested it.
