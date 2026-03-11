# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2026 The Cacti Group                                 |
# |                                                                         |
# | This program is free software; you can redistribute it and/or           |
# | modify it under the terms of the GNU General Public License             |
# | as published by the Free Software Foundation; either version 2          |
# | of the License, or (at your option) any later version.                  |
# +-------------------------------------------------------------------------+

Name:           cacti-spine
Version:        1.3.0
Release:        1%{?dist}
Summary:        High-performance SNMP poller for Cacti

License:        GPL-2.0-or-later
URL:            https://www.cacti.net/
Source0:        https://github.com/Cacti/spine/archive/refs/tags/%{version}.tar.gz#/cacti-spine-%{version}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  dos2unix
BuildRequires:  help2man
BuildRequires:  mariadb-devel
BuildRequires:  net-snmp-devel
BuildRequires:  openssl-devel
BuildRequires:  libcap-devel
BuildRequires:  gcc
BuildRequires:  make

Requires:       mariadb-connector-c
Requires:       net-snmp-libs
Requires:       openssl-libs
Requires:       libcap

%description
Spine is a replacement for the cmd.php data collector in Cacti.
It uses POSIX threads to poll many devices in parallel via SNMP,
ICMP, and TCP, providing substantially higher throughput than the
PHP-based poller.

The spine binary uses CAP_NET_RAW (via file capabilities) to open raw
sockets for ICMP availability checking without running setuid-root.

%prep
%autosetup -n spine-%{version}

%build
./bootstrap
%configure \
    --enable-lcap \
    --bindir=%{_sbindir} \
    --sysconfdir=%{_sysconfdir} \
    --with-results-buffer=2048 \
    --with-max-scripts=20
%make_build

%install
%make_install
install -D -m 0640 spine.conf.dist %{buildroot}%{_sysconfdir}/spine.conf.dist

# Install man page (generated during build); upstream installs into man1
[ -f spine.1 ] && install -D -m 0644 spine.1 %{buildroot}%{_mandir}/man1/spine.1 || true

%post
# Grant CAP_NET_RAW so spine can open raw ICMP sockets without setuid-root.
setcap cap_net_raw+eip %{_sbindir}/spine || true

%preun
exit 0

%files
%license LICENSE
%doc README.md INSTALL CHANGELOG
%attr(0755, root, root) %{_sbindir}/spine
%ghost %config(noreplace) %{_sysconfdir}/spine.conf
%{_sysconfdir}/spine.conf.dist
%optional %{_mandir}/man1/spine.1*

%changelog
* Sun Mar 08 2026 The Cacti Group <developers@cacti.net> - 1.3.0-1
- Initial RPM packaging
