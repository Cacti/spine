# Security Policy

## Trust Model

spine is the polling backend for Cacti. It reads the set of devices,
scripts, and SNMP targets to execute from the Cacti MySQL/MariaDB
database and executes them verbatim. spine trusts the database. In
particular, any user with Cacti admin privileges to insert or modify
rows in `poller_item`, `data_input_data`, or related tables can cause
spine to run arbitrary shell commands as the spine user.

Cacti admin access is therefore equivalent to shell execution as the
spine user. Treat the Cacti admin credential and the database write
path with the same care as an SSH key for the spine account.

## Recommended Deployment

- Run spine as an unprivileged dedicated user, not root.
- Grant `CAP_NET_RAW` (and `CAP_NET_ADMIN` if required) only when the
  ICMP availability method is in use. Do not grant the binary setuid.
- Restrict `spine.conf` to mode `0600` owned by the spine user. Spine
  refuses to start if other bits are set or the owner does not match.
- Store DB credentials in `spine.conf` only, never on the command line.
- Enable MySQL/MariaDB TLS (`DB_UseSSL=1`) when the database is on a
  separate host. spine enforces server identity verification when TLS
  is enabled.
- Confine the log directory to the spine user. Log writes use
  `O_NOFOLLOW` but directory-level controls are still the correct
  perimeter.
- Run spine inside a systemd unit with `NoNewPrivileges=yes`,
  `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes`
  where available.

## Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security
Advisories on the [Cacti/spine](https://github.com/Cacti/spine)
repository, or by email to the Cacti maintainers per the policy in
the upstream [Cacti SECURITY.md](https://github.com/Cacti/cacti/blob/develop/SECURITY.md).

Do not open public issues or pull requests for pre-authentication or
remote-code-execution findings. Post-authentication issues with
limited impact may be filed as regular issues.

Please include:

- affected version (`spine --version` output)
- operating system and MySQL/MariaDB version
- a minimal reproducer
- any proposed fix or patch
