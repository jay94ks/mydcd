#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# layout.sh PART PREFIX DEST BUILD [WEB_BUNDLE]: install one package's files
# under DEST as they land on a server with PREFIX (devel/design/install-packages.md 4).
#   PART        sfcli | sfcd | sfc-web-image
#   PREFIX      /usr (deb, rpm) or /usr/local (archive)
#   BUILD       build.sh's OUT (bin/, ENGINE_NOTICES); the source tree is the
#               working directory (LICENSE, NOTICE, THIRD_PARTY_NOTICES in BUILD)
#   WEB_BUNDLE  sfc-web-image_<tag>_linux_<arch>.tar.gz (sfc-web-image only)
# sfcd's real binaries sit in PREFIX/lib/sfc/bin, where sfcd and sfed accept
# each other (P-j); PREFIX/bin/sfcd is a relative link to it. The units go to
# /usr/lib/systemd/system for /usr, or to PREFIX/share/sfc/systemd for the
# archive, where the operator copies them from.
set -euo pipefail
part=${1:?usage: layout.sh PART PREFIX DEST BUILD [WEB_BUNDLE]}
prefix=${2:?}
dest=${3:?}
build=${4:?}
web=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
root=$dest$prefix
lib=$prefix/lib/sfc

doc() { # doc PKG FILE...: license files into PREFIX/share/doc/PKG
	local d=$root/share/doc/$1
	shift
	install -d -m 0755 "$d"
	install -m 0644 "$@" "$d/"
}

man() { # man PAGE SECTION: a gzipped manual page into PREFIX/share/man/SECTION
	install -d -m 0755 "$root/share/man/$2"
	gzip -9n <"$here/man/$1" >"$root/share/man/$2/$1.gz"
	chmod 0644 "$root/share/man/$2/$1.gz"
}

case $part in
sfcli)
	install -D -m 0755 "$build/bin/sfcli" "$root/bin/sfcli"
	install -D -m 0644 cmd/sfcli/SKILL.md "$root/share/sfc/SKILL.md"
	man sfcli.1 man1
	doc sfcli LICENSE NOTICE
	;;
sfcd)
	install -d -m 0755 "$root/lib/sfc/bin" "$root/bin"
	for b in sfcd sfed sfe-runc containerd containerd-shim-runc-v2 runc; do
		install -m 0755 "$build/bin/$b" "$root/lib/sfc/bin/$b"
	done
	ln -sfn ../lib/sfc/bin/sfcd "$root/bin/sfcd"
	man sfcd.8 man8
	if [ "$prefix" = /usr ]; then
		units=$dest/usr/lib/systemd/system
	else
		units=$root/share/sfc/systemd
	fi
	install -d -m 0755 "$units"
	for u in sfcd sfed; do
		sed "s|@LIBDIR@|$lib|g" "$here/systemd/$u.service.in" >"$units/$u.service"
		chmod 0644 "$units/$u.service"
	done
	install -d -m 0755 "$root/share/doc/sfcd/examples"
	install -m 0644 configs/node.managed.example.yaml configs/node.join.example.yaml "$root/share/doc/sfcd/examples/"
	cat "$build/THIRD_PARTY_NOTICES" "$build/ENGINE_NOTICES" >"$build/sfcd-notices"
	doc sfcd LICENSE NOTICE
	install -m 0644 "$build/sfcd-notices" "$root/share/doc/sfcd/THIRD_PARTY_NOTICES"
	rm -f "$build/sfcd-notices"
	;;
sfc-web-image)
	[ -f "$web" ] || { echo "layout.sh: sfc-web-image needs the signed bundle archive" >&2; exit 2; }
	install -d -m 0755 "$root/lib/sfc/images"
	tar -xzf "$web" -C "$root/lib/sfc/images" --no-same-owner
	[ -f "$root/lib/sfc/images/sfc-web/sfc-release.sig" ] || { echo "layout.sh: $web holds no signed sfc-web bundle" >&2; exit 3; }
	find "$root/lib/sfc/images" -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
	doc sfc-web-image LICENSE NOTICE "$build/THIRD_PARTY_NOTICES"
	;;
*)
	echo "layout.sh: unknown part $part" >&2
	exit 2
	;;
esac
