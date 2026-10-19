<!--
SPDX-FileCopyrightText: 2026 The Cacti Group
SPDX-License-Identifier: GPL-2.0-or-later
-->

# 0003: MariaDB Connector/C as the database client

## Status

Proposed for upstream review

## Date

2026-10-07

## Context

Spine talks to the Cacti database through the MySQL C API. Two libraries
provide that API: MariaDB Connector/C (`libmariadb`, configured with
`mariadb_config`) and MySQL's `libmysqlclient` (`mysql_config`). `configure`
accepted either and took whichever it found first. CI built both.

The build tests both providers. MariaDB Connector/C is available in the
Linux and BSD distribution lanes and on macOS. The providers use different
TLS options, so configure probes the installed API rather than assuming
that a tool named `mysql_config` belongs to Oracle's client.

Connector/C speaks the MySQL protocol, including the `caching_sha2_password`
authentication that MySQL 8.4 uses by default, so choosing it does not drop
MySQL servers. The SNMPv3 integration job in `.github/workflows/integration.yml`
already runs Spine built against `libmariadb-dev` with a MySQL 8.4 server.

## Decision

MariaDB Connector/C is Spine's database client library.

- `configure` looks for `mariadb_config` and `libmariadb` first.
  `--with-mysql-client=mariadb` requires Connector/C and fails without it.
  `--with-mysql-client=mysql` selects `libmysqlclient`.
- `configure` decides which library it found by linking a call to
  `mariadb_get_infov()`, which only Connector/C provides. It does not trust
  the tool's name, because Debian and Homebrew install a `mysql_config` that
  belongs to Connector/C.
- When `libmysqlclient` is linked, by choice or because it was the only
  client found, `configure` prints a warning that it is deprecated, once
  where the check runs and again at the end of its output.
- Both server families stay supported: MariaDB and MySQL servers, reached
  through Connector/C. CI keeps testing against both.

## Consequences

Packagers can select a client explicitly. Existing MySQL client builds
remain supported and both client providers stay in the compiler matrix.
No event-loop or build-system migration is included.

Spine still depends on Connector/C behaving like the MySQL client against
MySQL servers. A protocol or authentication change in a new MySQL release
reaches Spine only after Connector/C supports it. CI's MySQL server lanes
are what catch that.
