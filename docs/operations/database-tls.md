<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Explicit database TLS policy

Local and remote connections have independent `DB_SSL_*` and `RDB_SSL_*`
settings. Unset `Mode` preserves the legacy connector behavior. Explicit
unsupported policies fail instead of silently accepting weaker settings.

| Mode | Policy |
| --- | --- |
| `legacy` | Existing `DB_UseSSL` and key/certificate/CA options; connector defaults apply. |
| `disabled` | Require plaintext; supported by MySQL's native SSL mode API. |
| `preferred` | Attempt TLS with plaintext fallback permitted. |
| `required` | Require encryption without peer certificate authentication. |
| `verify-ca` | Require encryption and verification against the configured CA. |
| `verify-full` | Require encryption, configured CA trust and matching server identity. |

MySQL clients exposing `MYSQL_OPT_SSL_MODE` implement all modes. MariaDB
Connector/C clients exposing the complete TLS verification callback API support
`preferred`, `required`, `verify-ca` and `verify-full`; explicit `disabled` is
rejected because their enforcement API does not safely guarantee plaintext.
Older MariaDB clients lacking that callback support `preferred` and native
`verify-full`. They reject `required` and `verify-ca`: enforcement alone can
fall back to plaintext before authentication. A newer client advertising the
callback option without exporting the required verification function also
rejects the strict modes. Configure probes the actual headers and linked
library, rather than inferring capabilities from a server version.

The callback adapter forces trust and identity checks even for loopback
addresses where newer Connector/C defaults can omit hostname verification.
`required` uses the connector's mandatory-TLS flag with an encryption-only
callback. Every connection retry starts with a fresh handle and reapplies all
TLS settings; a failed handshake cannot consume settings and weaken a retry.
Strict modes also check the negotiated connection for a TLS cipher.

`DB_SSL_MinVersion` accepts `TLSv1.2` or `TLSv1.3`. `DB_SSL_Cipher` selects
pre-TLS-1.3 ciphers; `DB_SSL_Ciphersuites` selects TLS 1.3 suites when the client
exposes that separate option. Restriction directives require a strict mode
(`required`, `verify-ca` or `verify-full`); they cannot be combined with plaintext
fallback. Unknown modes, unsupported versions, excessive cipher strings,
unsupported client options and option-application failures reject the policy.

```text
DB_SSL_Mode verify-full
DB_SSL_CA /etc/cacti/database-ca.pem
DB_SSL_MinVersion TLSv1.2

RDB_SSL_Mode verify-full
RDB_SSL_CA /etc/cacti/remote-database-ca.pem
RDB_SSL_MinVersion TLSv1.3
```

Both verification modes require an explicit trusted CA. Server names/IP
addresses must match certificate identities for `verify-full`. Server-side
protocol/cipher configuration must be compatible with the selected client.
CA trust does not replace hostname verification.

`bash tests/tools/run_database_tls.sh` generates disposable certificates and
servers to test trust, wrong identities, minimum protocols, cipher restrictions,
retry behavior and plaintext rejection for both database destinations. The
regression workflow exercises MariaDB and MySQL client libraries separately.
Native Connector/C 3.4.11 was also tested against those certificate fixtures.

API references: [MariaDB mysql_optionsv](https://mariadb.com/docs/connectors/mariadb-connector-c/api-functions/mysql_optionsv),
[MySQL mysql_options](https://dev.mysql.com/doc/c-api/8.4/en/mysql-options.html).
