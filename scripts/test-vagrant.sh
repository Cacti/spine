#!/usr/bin/env bash
# Local BSD/niche-OS testing via Vagrant + VirtualBox.
#
# Requires: vagrant, virtualbox (or vmware_desktop + plugin)
#
# Usage:
#   scripts/test-vagrant.sh              # run all BSDs (freebsd openbsd netbsd dragonfly)
#   scripts/test-vagrant.sh freebsd      # just FreeBSD
#   scripts/test-vagrant.sh all          # every VM including Alpine
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

command -v vagrant >/dev/null 2>&1 || {
    echo "ERROR: install vagrant (brew install --cask vagrant)"
    exit 1
}

case "${1:-bsd}" in
    all)
        VMS=(freebsd openbsd netbsd dragonfly alpine)
        ;;
    bsd)
        VMS=(freebsd openbsd netbsd dragonfly)
        ;;
    *)
        VMS=("$@")
        ;;
esac

for vm in "${VMS[@]}"; do
    echo "=== $vm ==="
    vagrant up --provision "$vm"
    vagrant halt "$vm"
done
