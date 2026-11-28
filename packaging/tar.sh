#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# tar.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]: sfc_<VERSION>_linux_<ARCH>.tar.gz,
# a /usr/local tree for servers without a package manager
# (devel/design/install-packages.md 2, 4). Install with
#   tar -C /usr/local --strip-components=1 -xzf sfc_<VERSION>_linux_<ARCH>.tar.gz
# then copy share/sfc/systemd/*.service to /etc/systemd/system.
set -euo pipefail
build=${1:?usage: tar.sh BUILD VERSION ARCH OUTDIR [WEB_BUNDLE]}
version=${2:?}
arch=${3:?}
outdir=${4:?}
web=${5:-}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
name=sfc_${version}_linux_${arch}
stage=$work/$name
parts=(sfcli sfcd)
[ -n "$web" ] && parts+=(sfc-web-image)
for p in "${parts[@]}"; do
	"$here/layout.sh" "$p" /usr/local "$work/root" "$build" "$web"
done
mv "$work/root/usr/local" "$stage"
mkdir -p "$outdir"
tar --sort=name --owner=0 --group=0 --numeric-owner \
	--mtime="@${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || date +%s)}" \
	-C "$work" -czf "$outdir/$name.tar.gz" "$name"
echo "tar.sh: $outdir/$name.tar.gz"
