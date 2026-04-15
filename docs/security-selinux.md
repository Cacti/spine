# SELinux enablement

Spine ships an SELinux policy module skeleton under `etc/selinux/`. The
skeleton declares the `spine_t` domain, its entry point, and the log / pid
file contexts. It is intentionally minimal: enumerating every syscall and
file-access spine needs is a site-specific exercise once the Cacti scripts
tree, MariaDB location, and snmpd configuration are known.

## Policy status

The `spine.te` module is a skeleton. Loading it in enforcing mode without
the `audit2allow` pass described below will deny most real work and surface
AVCs in `/var/log/audit/audit.log`.

## Build and load

On Rocky, Alma, Fedora, or RHEL derivatives:

```
sudo dnf install selinux-policy-devel
make -C etc/selinux -f /usr/share/selinux/devel/Makefile
sudo semodule -i etc/selinux/spine.pp
sudo restorecon -Rv /usr/local/spine /var/log/cacti /var/run/spine
```

## Permissive mode for audit2allow

Switch the `spine_t` domain to permissive while the policy is being
extended:

```
sudo semanage permissive -a spine_t
sudo systemctl restart spine
# Run a full poll cycle.
sudo ausearch -m AVC -c spine | audit2allow -M spine_local
sudo semodule -i spine_local.pp
```

Review the generated `spine_local.te`, fold the production-worthy rules
into the committed `spine.te`, rebuild, and remove the permissive
exception:

```
sudo semanage permissive -d spine_t
```

## Known gaps

* The Cacti `scripts/` tree is accessed via `execve`. The skeleton leaves
  this to the operator because deployments pick different paths
  (`/usr/local/cacti/scripts`, `/usr/share/cacti/scripts`, custom NFS
  mounts).
* MySQL connection methods vary (local socket, TCP, Unix-domain through a
  proxy); the `optional_policy` block pulls in the distribution's
  `mysql_*` interfaces only when that policy module is installed.
* PHP script server child processes inherit the `spine_t` domain. If a
  site ships custom PHP scripts that fork helpers of their own, add a
  domain transition for those helpers rather than widening `spine_t`
  globally.

## Interaction with the systemd unit

`etc/systemd/spine.service` applies kernel-level sandboxing via
`ProtectSystem=strict`, `ProtectHome=yes`, and a `SystemCallFilter`.
SELinux layers on top: a call that systemd allows is still subject to
SELinux type-enforcement, so the policy module can be tighter than the
systemd unit without compatibility fallout.
