#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# rpm/build.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]: the sfcli, sfcd and
# sfc-web-image .rpm files from build.sh's BUILD with rpmbuild -bb, then
# rpmlint. Runs inside the packaging/rpm image with the source tree as the
# working directory. ARCH is the Go name (amd64, arm64). Without WEB_BUNDLE
# there is no sfc-web-image package.
set -euo pipefail
build=$(cd "${1:?usage: rpm/build.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]}" && pwd)
version=${2:?}
goarch=${3:?}
outdir=${4:?}
web=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
"$here/../check-scripts.sh"
case $goarch in
amd64) arch=x86_64 ;;
arm64) arch=aarch64 ;;
*) echo "rpm/build.sh: unknown arch $goarch" >&2; exit 2 ;;
esac
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$outdir"
with=--without=web
if [ -n "$web" ]; then
	with=--with=web
	web=$(cd "$(dirname "$web")" && pwd)/$(basename "$web")
else
	web=none
fi
rpmbuild -bb --target "$arch" $with \
	--define "_topdir $work" \
	--define "sfc_version $version" \
	--define "sfc_arch $arch" \
	--define "sfc_src $(pwd)" \
	--define "sfc_build $build" \
	--define "sfc_web $web" \
	--define "sfc_date $(LC_ALL=C date -u -d "@${SOURCE_DATE_EPOCH:-$(date +%s)}" '+%a %b %d %Y')" \
	--define "_binary_payload w19.zstdio" \
	"$here/sfc.spec" >"$work/rpmbuild.log" 2>&1 || { cat "$work/rpmbuild.log" >&2; exit 1; }
rpms=$(find "$work/RPMS" -name '*.rpm' | LC_ALL=C sort)
for r in $rpms; do
	cp "$r" "$outdir/"
	echo "rpm/build.sh: $outdir/$(basename "$r")"
done
# rpmlint: no error and no warning.
rpmlint -r "$here/rpmlintrc" $rpms
