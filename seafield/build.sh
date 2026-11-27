#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# build.sh DIR OUT [VERSION]: prepare.sh로 만든 DIR에서 sfed(Seafield Engine) 바이너리를 OUT에,
# runc 감싸개 sfe-runc를 OUT과 같은 디렉터리에 빌드한다.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
dir=$(cd "${1:?usage: build.sh DIR OUT [VERSION]}" && pwd)
out=${2:?usage: build.sh DIR OUT [VERSION]}
version=${3:-dev}
gover=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["go"])' "$here/upstream.json")
tag=$(python3 -I -c 'import json,sys;print(json.load(open(sys.argv[1]))["tag"])' "$here/upstream.json")
head=$(git -C "$dir" rev-parse HEAD)
series=$(sha256sum "$here/series" | cut -c1-12)

pkg=github.com/moby/moby/v2/dockerversion
ldflags="-w -X $pkg.Version=$version -X $pkg.GitCommit=${head:0:12} -X $pkg.PlatformName=Seafield -X $pkg.ProductName=sfed"
ldflags+=" -X $pkg.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cd "$dir"
GOFLAGS=-mod=vendor CGO_ENABLED=0 GOTOOLCHAIN="go$gover" \
	go build -trimpath -ldflags "$ldflags" \
	-tags "grpcnotrace netgo osusergo static_build nri_no_wasm" \
	-o "$out" ./cmd/dockerd
GOFLAGS=-mod=vendor CGO_ENABLED=0 GOTOOLCHAIN="go$gover" \
	go build -trimpath -ldflags "-w" -o "$(dirname "$out")/sfe-runc" ./cmd/sfe-runc
echo "build.sh: $out, $(dirname "$out")/sfe-runc (upstream $tag, series $series)"
