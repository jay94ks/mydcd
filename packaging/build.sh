#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build.sh OUT VERSION: build every binary the packages carry into OUT/bin and
# the engine's third-party notices into OUT/ENGINE_NOTICES. Runs inside the
# packaging/builder image with the source tree as the working directory
# (make packages does that), for the image's own architecture.
#   OUT/bin: sfcd sfcli sfed sfe-runc containerd containerd-shim-runc-v2 runc
set -euo pipefail
out=${1:?usage: build.sh OUT VERSION}
version=${2:?usage: build.sh OUT VERSION}
mkdir -p "$out/bin"
out=$(cd "$out" && pwd)
src=$(pwd)
here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=versions.env
. "$here/versions.env"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# sfcd and sfcli. A vX.Y.Z tag puts build number Z into them (tools/buildversion).
flags=$(go run ./tools/buildversion "$version")
for b in sfcd sfcli; do
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w $flags" -o "$out/bin/$b" "./cmd/$b"
done

# Seafield Engine: upstream tag + prune + patches, then sfed and sfe-runc.
"$src/seafield/prepare.sh" "$work/seafield"
"$src/seafield/build.sh" "$work/seafield" "$out/bin/sfed" "${version#v}"

# clone REPO TAG COMMIT DIR: a shallow clone of TAG that must be COMMIT.
clone() {
	git -c advice.detachedHead=false clone -q --depth 1 --branch "$2" "$1" "$4"
	local got
	got=$(git -C "$4" rev-parse HEAD)
	[ "$got" = "$3" ] || { echo "build.sh: $1 $2 is $got, versions.env pins $3" >&2; exit 3; }
}

# containerd and its runc shim, static (no cgo), as upstream Moby builds them.
clone https://github.com/containerd/containerd.git "$CONTAINERD_VERSION" "$CONTAINERD_COMMIT" "$work/containerd"
make -C "$work/containerd" STATIC=1 CGO_ENABLED=0 bin/containerd bin/containerd-shim-runc-v2 >/dev/null
cp "$work/containerd/bin/containerd" "$work/containerd/bin/containerd-shim-runc-v2" "$out/bin/"

# runc: cgo + static libseccomp.
clone https://github.com/opencontainers/runc.git "$RUNC_VERSION" "$RUNC_COMMIT" "$work/runc"
CGO_ENABLED=1 make -C "$work/runc" RUNC_BUILDTAGS="-libpathrs" static >/dev/null
cp "$work/runc/runc" "$out/bin/"

# The engine's licenses: each project's LICENSE and NOTICE, then every
# vendored module's, in path order.
notices() { # notices NAME DIR
	local name=$1 dir=$2 f
	printf '================================================================\n%s\n================================================================\n\n' "$name"
	for f in LICENSE NOTICE; do
		[ -f "$dir/$f" ] && { printf -- '--- %s/%s\n\n' "$name" "$f"; cat "$dir/$f"; printf '\n'; }
	done
	[ -d "$dir/vendor" ] || return 0
	(cd "$dir/vendor" && find . -type f \( -iname 'LICENSE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) | LC_ALL=C sort) | while read -r f; do
		printf -- '--- %s vendor/%s\n\n' "$name" "${f#./}"
		cat "$dir/vendor/$f"
		printf '\n'
	done
}
{
	notices "Seafield Engine (Moby $(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["tag"])' "$src/seafield/upstream.json"), patched)" "$work/seafield"
	notices "containerd $CONTAINERD_VERSION" "$work/containerd"
	notices "runc $RUNC_VERSION" "$work/runc"
} >"$out/ENGINE_NOTICES"

# The engine builds keep their symbol tables; packages ship stripped binaries.
strip "$out/bin/sfed" "$out/bin/sfe-runc" "$out/bin/runc"

for b in "$out"/bin/*; do
	if readelf -l "$b" | grep -q 'Requesting program interpreter'; then
		echo "build.sh: $b is dynamically linked" >&2
		exit 4
	fi
done
for b in sfcd sfcli sfed sfe-runc containerd containerd-shim-runc-v2 runc; do
	[ -x "$out/bin/$b" ] || { echo "build.sh: $b was not built" >&2; exit 5; }
done
echo "build.sh: $(ls "$out/bin" | tr '\n' ' ')in $out/bin"
