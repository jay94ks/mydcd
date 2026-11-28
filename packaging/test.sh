#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# test.sh DIST OLD NEW ARCH: install, upgrade, remove and purge the packages in
# DIST inside clean containers (devel/design/install-packages.md 8, item 1).
# OLD and NEW are two package versions in DIST (NEW sorts after OLD); ARCH is
# the Go name. Everything is installed from the files alone, so no package
# manager reaches the network. Each run also checks that the host's base
# packages are exactly the same before and after (X23): ours never remove or
# install anything else.
#   deb: ubuntu:24.04, ubuntu:26.04, debian:trixie   rpm: fedora:43, rockylinux:10
#   tar.gz: ubuntu:24.04, extracted into /usr/local
set -euo pipefail
dist=$(cd "${1:?usage: test.sh DIST OLD NEW ARCH}" && pwd)
old=${2:?}
new=${3:?}
arch=${4:?}
case $arch in
amd64) rarch=x86_64 ;;
arm64) rarch=aarch64 ;;
*) echo "test.sh: unknown arch $arch" >&2; exit 2 ;;
esac
here=$(cd "$(dirname "$0")" && pwd)
run() { docker run --rm --platform "linux/$arch" -e OLD="$old" -e NEW="$new" -e ARCH="$arch" -e RARCH="$rarch" \
	-v "$dist:/dist:ro" -v "$here/test-in-container.sh:/t.sh:ro" "$@"; }

for img in ubuntu:24.04 ubuntu:26.04 debian:trixie-slim; do
	echo "== deb on $img"
	run "$img" bash /t.sh deb
done
for img in fedora:43 rockylinux/rockylinux:10; do
	echo "== rpm on $img"
	run "$img" bash /t.sh rpm
done
echo "== tar.gz on ubuntu:24.04"
run ubuntu:24.04 bash /t.sh tar
echo "test.sh: all passed"
