#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# deb/build.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]: the sfcli, sfcd and
# sfc-web-image .deb files from build.sh's BUILD, with dpkg-deb, then lintian.
# Runs inside the packaging/deb image with the source tree as the working
# directory. Without WEB_BUNDLE there is no sfc-web-image package.
set -euo pipefail
build=${1:?usage: deb/build.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]}
version=${2:?}
arch=${3:?}
outdir=${4:?}
web=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
"$here/../check-scripts.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$outdir"
maintainer='Jay <33371449+jay94ks@users.noreply.github.com>'
date=$(date -u -R -d "@${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}")

parts=(sfcli sfcd)
[ -n "$web" ] && parts+=(sfc-web-image)
for p in "${parts[@]}"; do
	root=$work/$p
	"$here/../layout.sh" "$p" /usr "$root" "$build" "$web"
	d=$root/usr/share/doc/$p
	cat >"$d/copyright" <<COPY
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Seafield Cluster
Source: https://github.com/jay94ks/seafield

Files: *
Copyright: 2026 Jay
License: Apache-2.0
 On Debian systems the full text of the Apache License 2.0 is in
 /usr/share/common-licenses/Apache-2.0. Bundled third-party components and
 their licenses are listed in NOTICE and THIRD_PARTY_NOTICES in this directory.
COPY
	rm -f "$d/LICENSE"
	printf '%s (%s) unstable; urgency=medium\n\n  * Release %s. See https://github.com/jay94ks/seafield/releases\n\n -- %s  %s\n' \
		"$p" "$version" "$version" "$maintainer" "$date" | gzip -9n >"$d/changelog.gz"
	[ -f "$here/$p.lintian-overrides" ] && install -d -m 0755 "$root/usr/share/lintian/overrides"
	[ -f "$here/$p.lintian-overrides" ] && install -m 0644 "$here/$p.lintian-overrides" "$root/usr/share/lintian/overrides/$p"
	install -d -m 0755 "$root/DEBIAN"
	case $p in
	sfcli) depends= ; desc="Seafield Cluster command line interface" ;;
	sfcd) depends="sfcli (= $version)" ; desc="Seafield Cluster node daemon and Seafield Engine" ;;
	sfc-web-image) depends="sfcd (= $version)" ; desc="Seafield Cluster web UI cluster app image" ;;
	esac
	size=$(du -sk --exclude=DEBIAN "$root" | cut -f1)
	{
		echo "Package: $p"
		echo "Version: $version"
		echo "Architecture: $arch"
		echo "Maintainer: $maintainer"
		echo "Installed-Size: $size"
		[ -n "$depends" ] && echo "Depends: $depends"
		echo "Section: admin"
		echo "Priority: optional"
		echo "Homepage: https://github.com/jay94ks/seafield"
		echo "Description: $desc"
		sed 's/^/ /; s/^ $/ ./' "$here/$p.description"
	} >"$root/DEBIAN/control"
	if [ -d "$here/$p" ]; then
		for s in "$here/$p"/*; do
			install -m 0755 "$s" "$root/DEBIAN/$(basename "$s")"
		done
	fi
	(cd "$root" && find . -path ./DEBIAN -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum | sed 's|  \./|  |') >"$root/DEBIAN/md5sums"
	chmod 0644 "$root/DEBIAN/control" "$root/DEBIAN/md5sums"
	deb=$outdir/${p}_${version}_${arch}.deb
	dpkg-deb --root-owner-group -Zxz --build "$root" "$deb" >/dev/null
	echo "deb/build.sh: $deb"
done

# lintian: no error and no warning.
for p in "${parts[@]}"; do
	lintian --fail-on error,warning "$outdir/${p}_${version}_${arch}.deb"
done
