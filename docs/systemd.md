# systemd Integration

Spine ships three systemd unit templates:

- `spine.service.in`: long-running `Type=notify` profile (watchdog + reload support)
- `spine-batch.service.in`: `Type=oneshot` batch profile for timer/cron-like polling
- `spine-dynamic.service.in`: optional `DynamicUser=yes` hardening profile

`spine.timer` targets the batch unit (`spine-batch.service`).

## Installed unit paths

At install time, CMake renders the templates with distro paths:

- binary path from `CMAKE_INSTALL_FULL_SBINDIR` (typically `/usr/sbin/spine`)
- config path from `CMAKE_INSTALL_FULL_SYSCONFDIR` (typically `/etc/spine.conf`)

Units are installed into the systemd unit directory detected from `pkg-config`
(`systemdsystemunitdir`), with `/lib/systemd/system` fallback.

## Operational behavior

All shipped unit profiles use:

- `SyslogIdentifier=spine`
- `ConditionPathExists=<spine.conf>`
- `ExecStartPre=<spine> --check`
- hardened defaults (`NoNewPrivileges`, syscall filters, restricted address families)
- systemd-managed writable paths via `RuntimeDirectory=spine`, `StateDirectory=spine`, `LogsDirectory=cacti`

The notify units call:

- `READY=1` on startup
- `WATCHDOG=1` during poll loop
- `RELOADING=1` + `MONOTONIC_USEC` on SIGHUP reload
- `STOPPING=1` during shutdown

## Enabling

Timer-driven (recommended for periodic polling):

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now spine.timer
```

Long-running notify mode:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now spine.service
```

Dynamic user profile:

```sh
sudo systemctl daemon-reload
sudo systemctl disable --now spine.service
sudo systemctl enable --now spine-dynamic.service
```
