#!/bin/sh
# Test-fixture entrypoint: copy the bind-mounted spine.conf to a private path
# with mode 0600 so H1 (SECURITY.md §config-perms) accepts it at startup.
#
# The bind-mount source arrives from the git checkout with mode 0644; we cannot
# chmod it directly because it is read-only. Copy to a tmpfs path instead.
# This wrapper runs as root (user: "0:0" in docker-compose.yml), satisfying the
# owner == 0 requirement that H1 enforces alongside the mode check.
set -e
install -m 0600 /etc/spine/spine.conf.src /tmp/spine.conf
exec /usr/local/bin/spine --conf=/tmp/spine.conf "$@"
