# -*- mode: ruby -*-
# vi: set ft=ruby :
#
# Vagrant configuration for testing spine on real BSD, Linux, and other
# Unix-like VMs that cannot be emulated in Docker (jails, zones, ZFS,
# pledge/unveil, capsicum, raw ICMP without root in a container).
#
# Usage:
#   vagrant up freebsd        # boot FreeBSD 14.1 VM
#   vagrant ssh freebsd
#   vagrant up --provision freebsd   # re-run provisioning
#   vagrant halt freebsd      # shut down
#   vagrant destroy freebsd   # delete VM
#
# Prerequisites: VirtualBox 7.x (or VMware Fusion / Parallels via the
# appropriate plugin) and Vagrant 2.3+.

Vagrant.configure("2") do |config|
  # Shared provisioning: sync source, build with CMake, smoke test.
  config.vm.synced_folder ".", "/spine", type: "rsync",
    rsync__exclude: [".git/", "build/", "build-*/", ".omc/", ".claude/",
                     ".worktrees/", ".idea/", "*.o", "*.a"]

  # FreeBSD 14 (Tier 1)
  config.vm.define "freebsd", autostart: false do |vm|
    vm.vm.box = "generic/freebsd14"
    vm.vm.hostname = "spine-freebsd14"
    vm.vm.provision "shell", inline: <<-SHELL
      pkg install -y cmake ninja pkgconf net-snmp mariadb106-client openssl
      cd /spine
      cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
      cmake --build build
      ./build/spine --help | head -5
    SHELL
  end

  # OpenBSD 7.5 (Tier 3) — required for pledge/unveil runtime coverage
  config.vm.define "openbsd", autostart: false do |vm|
    vm.vm.box = "generic/openbsd7"
    vm.vm.hostname = "spine-openbsd"
    vm.vm.provision "shell", inline: <<-SHELL
      pkg_add -I cmake ninja pkg-config mariadb-client net-snmp
      cd /spine
      cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
      cmake --build build
      ./build/spine --help | head -5 || true
    SHELL
  end

  # NetBSD 10 (Tier 3)
  config.vm.define "netbsd", autostart: false do |vm|
    vm.vm.box = "generic/netbsd10"
    vm.vm.hostname = "spine-netbsd"
    vm.vm.provision "shell", inline: <<-SHELL
      pkgin -y install cmake ninja pkg-config mariadb-client net-snmp openssl
      cd /spine
      cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON || cmake -B build -DSPINE_BUILD_MAIN=ON
      cmake --build build
      ./build/spine --help | head -5 || true
    SHELL
  end

  # DragonFly BSD 6 (Tier 3)
  config.vm.define "dragonfly", autostart: false do |vm|
    vm.vm.box = "generic/dragonfly6"
    vm.vm.hostname = "spine-dragonfly"
    vm.vm.provision "shell", inline: <<-SHELL
      pkg install -y cmake ninja pkgconf net-snmp mariadb106-client openssl
      cd /spine
      cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
      cmake --build build
      ./build/spine --help | head -5 || true
    SHELL
  end

  # Alpine 3.20 (Tier 2) — useful for musl debugging in a real VM
  config.vm.define "alpine", autostart: false do |vm|
    vm.vm.box = "generic/alpine320"
    vm.vm.hostname = "spine-alpine"
    vm.vm.provision "shell", inline: <<-SHELL
      apk add --no-cache bash cmake ninja gcc musl-dev pkgconf \
        net-snmp-dev mariadb-connector-c-dev openssl-dev linux-headers
      cd /spine
      cmake -G Ninja -B build -DSPINE_BUILD_MAIN=ON
      cmake --build build
      ./build/spine --help | head -5
    SHELL
  end

  # Provider sizing — default is conservative; bump for parallel build.
  config.vm.provider "virtualbox" do |vb|
    vb.memory = 4096
    vb.cpus = 4
  end

  config.vm.provider "vmware_desktop" do |v|
    v.vmx["memsize"] = "4096"
    v.vmx["numvcpus"] = "4"
  end
end
