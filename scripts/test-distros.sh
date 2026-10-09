#!/bin/sh
# Build spine and run "make check" inside stock Linux distribution images.
#
#   scripts/test-distros.sh                  every Linux lane, one at a time
#   scripts/test-distros.sh debian:12 ...    only the named images
#
# The BSD lanes in .github/workflows/distro-matrix.yml run the same steps
# directly inside a VM: "--deps" as root, then "--build <dir>".
#
# The checkout is mounted read-only and copied inside the container, so no
# generated Autotools output reaches the working tree. Inside the container
# the script runs itself again: as root to install the distribution's
# packages, then as an unprivileged user to build and test. Several tests
# assert what spine does after dropping root, which cannot hold when the
# whole suite already runs as root.
#
# Logs land in $LOG_DIR (default: a new directory under ${TMPDIR:-/tmp}),
# with a directory per image holding the test logs of a failed make check.
# Plain POSIX sh: Alpine has no bash until the packages are installed.
set -eu

# Keep in step with .github/workflows/distro-matrix.yml and the lane list in
# .github/scripts/check-distro-eol.py.
default_images='rockylinux/rockylinux:8 rockylinux/rockylinux:9 rockylinux/rockylinux:10 almalinux:8 almalinux:9 almalinux:10 ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 debian:12 debian:13 fedora:44 opensuse/leap:16.0 alpine:3.24'
build_user=spinebuild

install_packages() {
	case "$(uname -s)" in
	FreeBSD)
		pkg install -y autoconf automake libtool gmake pkgconf bash \
			net-snmp mariadb-connector-c cmocka
		return
		;;
	NetBSD)
		# pkgsrc builds one binary set per major release on its .0
		# release, and pkg_install refuses those packages on 10.1
		# unless the OS ABI check is relaxed.
		if ! grep -q '^CHECK_OSABI=no' /etc/pkg_install.conf 2>/dev/null; then
			echo CHECK_OSABI=no >> /etc/pkg_install.conf
		fi
		if ! pkgin -y install autoconf automake libtool-base gmake \
			pkgconf bash net-snmp mariadb-client cmocka; then
			cat /var/db/pkgin/pkg_install-err.log >&2 || true
			exit 1
		fi
		return
		;;
	OpenBSD)
		pkg_add -I autoconf%2.72 automake%1.18 libtool gmake bash \
			net-snmp mariadb-client cmocka
		return
		;;
	esac

	# shellcheck disable=SC1091
	. /etc/os-release

	case "$ID" in
	rocky | almalinux)
		dnf -y install dnf-plugins-core epel-release
		case "$VERSION_ID" in
		8*) dnf config-manager --set-enabled powertools ;;
		*) dnf config-manager --set-enabled crb ;;
		esac
		dnf -y install gcc make autoconf automake libtool diffutils file \
			findutils procps-ng shadow-utils util-linux \
			net-snmp-devel mariadb-connector-c-devel openssl-devel \
			libcmocka-devel
		;;
	fedora)
		dnf -y install gcc make autoconf automake libtool diffutils file \
			findutils procps-ng shadow-utils util-linux \
			net-snmp-devel mariadb-connector-c-devel openssl-devel \
			libcmocka-devel
		;;
	debian | ubuntu)
		apt-get update
		DEBIAN_FRONTEND=noninteractive apt-get install -y \
			--no-install-recommends \
			gcc make autoconf automake libtool pkg-config file procps \
			libsnmp-dev libmariadb-dev libssl-dev libcmocka-dev
		;;
	opensuse-leap)
		zypper --non-interactive install gcc make autoconf automake \
			libtool diffutils file gawk procps shadow util-linux \
			net-snmp-devel libmariadb-devel libopenssl-devel \
			libcmocka-devel
		;;
	alpine)
		apk add --no-cache build-base autoconf automake libtool bash \
			linux-headers net-snmp-dev mariadb-connector-c-dev \
			openssl-dev cmocka-dev
		;;
	*)
		echo "unsupported distribution: $ID" >&2
		exit 1
		;;
	esac
}

build_and_check() {
	jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
	make_cmd='make'
	prefix=

	# Packages on the BSDs live outside the default search paths, and the
	# Automake test harness is only exercised with GNU make.
	case "$(uname -s)" in
	FreeBSD) make_cmd=gmake prefix=/usr/local ;;
	NetBSD) make_cmd=gmake prefix=/usr/pkg ;;
	OpenBSD)
		make_cmd=gmake prefix=/usr/local
		export AUTOCONF_VERSION=2.72 AUTOMAKE_VERSION=1.18
		;;
	esac

	cd "$1"
	autoreconf -fi
	if [ -n "$prefix" ]; then
		./configure --enable-warnings CPPFLAGS="-I$prefix/include" \
			LDFLAGS="-L$prefix/lib -Wl,-rpath,$prefix/lib"
	else
		./configure --enable-warnings
	fi
	"$make_cmd" -j"$jobs"
	./spine --version
	if ! "$make_cmd" -j"$jobs" check; then
		cat test-suite.log >&2 || true
		if [ -n "${ARTIFACT_DIR:-}" ]; then
			find . -name '*.log' -newer configure \
				-exec cp -p {} "$ARTIFACT_DIR/" \; || true
		fi
		exit 1
	fi
}

in_container() {
	install_packages

	if ! id "$build_user" >/dev/null 2>&1; then
		if command -v useradd >/dev/null 2>&1; then
			useradd -m "$build_user"
		else
			adduser -D "$build_user"
		fi
	fi

	work=$(mktemp -d)
	cp -R /src/. "$work/"
	chown -R "$build_user" "$work"
	if [ -d /artifacts ]; then
		chown "$build_user" /artifacts
	fi
	su "$build_user" -s /bin/sh -c \
		"ARTIFACT_DIR=/artifacts sh /src/scripts/test-distros.sh --build '$work'"
}

run_images() {
	root=$(cd -- "$(dirname -- "$0")/.." && pwd)
	log_dir=${LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/spine-distros.XXXXXX")}
	mkdir -p "$log_dir"
	summary=
	failed=0

	for image in "$@"; do
		case "$image" in
		*[!A-Za-z0-9._/:@-]* | '')
			echo "invalid image name: $image" >&2
			exit 2
			;;
		esac

		lane="$log_dir/$(printf '%s' "$image" | tr '/:@' '---')"
		log="$lane.log"
		status_file="$lane.status"
		mkdir -p "$lane"
		echo "=== $image"
		{
			rc=0
			docker run --rm --volume "$root:/src:ro" \
				--volume "$lane:/artifacts" "$image" \
				sh /src/scripts/test-distros.sh --in-container || rc=$?
			echo "$rc" > "$status_file"
		} 2>&1 | tee "$log"

		if [ "$(cat "$status_file")" = 0 ]; then
			result=PASS
		else
			result=FAIL
			failed=1
		fi
		summary="$summary$(printf '%-20s %s' "$image" "$result")
"
	done

	echo
	echo "=== summary (logs in $log_dir)"
	printf '%s' "$summary"
	return "$failed"
}

case "${1:-}" in
--deps)
	install_packages
	;;
--in-container)
	in_container
	;;
--build)
	build_and_check "$2"
	;;
'')
	# Word splitting of the fixed default list is intended.
	# shellcheck disable=SC2086
	run_images $default_images
	;;
*)
	run_images "$@"
	;;
esac
